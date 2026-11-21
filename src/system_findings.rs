//! Findings about the whole machine, from the System page's readings: memory pressure, swap that
//! keeps growing, thermal throttling, and a volume close to full. Each opens the System page.

use crate::findings::{Chart, Finding, Link, Severity};
use crate::procs::fmt_mem;
use crate::system::{Pressure, System, ThermalState, swap_growth};

/// How full a volume may get before it's worth a look, and before it's urgent, in percent.
pub const VOLUME_WARN: f64 = 90.0;
pub const VOLUME_CRITICAL: f64 = 97.0;

fn finding(
    rule: &'static str,
    subject: &str,
    severity: Severity,
    title: String,
    detail: String,
    fix: &str,
) -> Finding {
    Finding {
        rule,
        pid: 0,
        subject: subject.to_owned(),
        severity,
        title,
        detail,
        fix: fix.into(),
        chart: Chart::None,
        link: Link::System,
    }
}

fn mib(bytes: f64) -> String {
    fmt_mem(bytes / 1024.0)
}

/// Every machine-wide finding, from the latest good readings.
pub fn diagnose(s: &System) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(m) = &s.memory.last {
        let free = m.free_pct.map_or_else(String::new, |p| {
            format!(" {p:.0}% of memory is free for new work.")
        });
        let severity = match m.pressure {
            Pressure::Critical => Some(Severity::Critical),
            Pressure::Warning => Some(Severity::Warning),
            _ => None,
        };
        if let Some(severity) = severity {
            out.push(finding(
                "sys-memory-pressure",
                "Memory",
                severity,
                format!("Memory pressure is {}", m.pressure.label().to_lowercase()),
                format!("The system is compressing and swapping to make room.{free}"),
                "Quit what you aren't using; Top consumers on the System page lists who holds the most.",
            ));
        }
        if let Some(grown) = swap_growth(&s.mem_history) {
            out.push(finding(
                "sys-swap-growing",
                "Memory",
                Severity::Warning,
                format!("Swap grew {} in the last minute", mib(grown)),
                format!("{} of swap is in use and still rising, so memory is short.", mib(m.swap_used)),
                "Find the process that keeps growing (By memory on the System page) and restart or quit it.",
            ));
        }
    }
    if s.thermal_state() == Some(ThermalState::Throttled) {
        let limit = s.speed_limit().map_or_else(String::new, |l| {
            format!(" The CPU may run at {l:.0}% of its speed.")
        });
        let evidence = s
            .thermal
            .last
            .as_ref()
            .map(|t| t.evidence.clone())
            .unwrap_or_default();
        let detail = if evidence.is_empty() {
            format!("The system is slowing the CPU to cool down.{limit}")
        } else {
            format!("{}.{limit}", evidence.trim_end_matches('.'))
        };
        out.push(finding(
            "sys-thermal-throttled",
            "Thermal",
            Severity::Warning,
            "The CPU is thermally throttled".into(),
            detail,
            "Everything runs slower until it cools. Check what's busy, and give the machine air.",
        ));
    }
    let full: Vec<_> = s
        .volumes()
        .into_iter()
        .filter(|v| v.used_pct() >= VOLUME_WARN)
        .collect();
    if let Some(worst) = full
        .iter()
        .max_by(|a, b| a.used_pct().total_cmp(&b.used_pct()))
    {
        let severity = if worst.used_pct() >= VOLUME_CRITICAL {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let title = match full.len() {
            1 => format!("{} is {:.0}% full", worst.label(), worst.used_pct()),
            n => format!("{n} volumes are over {VOLUME_WARN:.0}% full"),
        };
        let detail = full
            .iter()
            .map(|v| {
                format!(
                    "{}: {} free of {}",
                    v.label(),
                    mib(v.avail),
                    mib(v.used + v.avail)
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        out.push(finding(
            "sys-volume-full",
            "Disks",
            severity,
            title,
            detail,
            "Free space before it runs out: apps and the system fail to save when a disk is full.",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{Fail, Memory, Reading, SWAP_WINDOW, Thermal, Volume};

    fn mem(pressure: Pressure, swap_used: f64) -> Memory {
        Memory {
            physical: 8e9,
            pressure,
            free_pct: Some(12.0),
            swap_used,
            ..Memory::default()
        }
    }

    fn vol(mount: &str, used: f64, avail: f64) -> Volume {
        Volume {
            mount: mount.into(),
            device: String::new(),
            fs_type: "apfs".into(),
            read_only: false,
            total: 2e12,
            used,
            avail,
        }
    }

    fn rules(s: &System) -> Vec<(&'static str, Severity)> {
        diagnose(s).iter().map(|f| (f.rule, f.severity)).collect()
    }

    #[test]
    fn memory_pressure_warns_then_turns_critical() {
        let mut s = System::new();
        s.land(Reading::Memory(Ok(mem(Pressure::Normal, 0.0))), 0.0, 0.0);
        assert!(
            rules(&s).is_empty(),
            "normal pressure is nothing to look at"
        );
        s.land(Reading::Memory(Ok(mem(Pressure::Warning, 0.0))), 5.0, 0.0);
        assert_eq!(rules(&s), [("sys-memory-pressure", Severity::Warning)]);
        s.land(Reading::Memory(Ok(mem(Pressure::Critical, 0.0))), 10.0, 0.0);
        let f = diagnose(&s);
        assert_eq!(
            (f[0].severity, f[0].title.as_str()),
            (Severity::Critical, "Memory pressure is critical")
        );
        assert_eq!(
            (f[0].link, f[0].pid),
            (Link::System, 0),
            "it opens the System page"
        );
        assert!(f[0].detail.contains("12% of memory is free"));
        // A failed reading keeps the last good one, and its finding.
        s.land(Reading::Memory(Err(Fail::Failed("boom".into()))), 15.0, 0.0);
        assert_eq!(rules(&s), [("sys-memory-pressure", Severity::Critical)]);
    }

    #[test]
    fn swap_counts_once_in_use_and_growing() {
        let mut s = System::new();
        let mb = 1024.0 * 1024.0;
        for i in 0..SWAP_WINDOW {
            s.land(
                Reading::Memory(Ok(mem(Pressure::Normal, 512.0 * mb))),
                i as f64 * 5.0,
                0.0,
            );
        }
        assert!(rules(&s).is_empty(), "swap in use but steady");
        for i in 0..SWAP_WINDOW {
            s.land(
                Reading::Memory(Ok(mem(Pressure::Normal, (512.0 + 10.0 * i as f64) * mb))),
                100.0 + i as f64 * 5.0,
                0.0,
            );
        }
        let f = diagnose(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "sys-swap-growing");
        assert_eq!(f[0].title, "Swap grew 120 MB in the last minute");
    }

    #[test]
    fn throttling_counts_and_warm_does_not() {
        let mut s = System::new();
        let t = |state, speed_limit| Thermal {
            state,
            evidence: "CPU speed limit 62%".into(),
            speed_limit,
        };
        s.land(Reading::Thermal(Ok(t(ThermalState::Warm, None))), 0.0, 0.0);
        assert!(
            rules(&s).is_empty(),
            "warm is shown on the page, not a finding"
        );
        s.land(
            Reading::Thermal(Ok(t(ThermalState::Throttled, Some(62.0)))),
            5.0,
            0.0,
        );
        let f = diagnose(&s);
        assert_eq!(f[0].rule, "sys-thermal-throttled");
        assert_eq!(
            f[0].detail,
            "CPU speed limit 62%. The CPU may run at 62% of its speed."
        );
    }

    #[test]
    fn a_volume_over_90_percent_full_counts_and_one_almost_full_is_critical() {
        let mut s = System::new();
        let tb = 1e12;
        s.land(
            Reading::Storage(Ok(vec![vol("/System/Volumes/Data", 0.89 * tb, 0.11 * tb)])),
            0.0,
            0.0,
        );
        assert!(rules(&s).is_empty(), "89% is fine");
        s.land(
            Reading::Storage(Ok(vec![vol("/System/Volumes/Data", 0.92 * tb, 0.08 * tb)])),
            30.0,
            0.0,
        );
        let f = diagnose(&s);
        assert_eq!(
            (f[0].rule, f[0].severity),
            ("sys-volume-full", Severity::Warning)
        );
        assert_eq!(f[0].title, "Startup disk is 92% full");
        s.land(
            Reading::Storage(Ok(vec![
                vol("/System/Volumes/Data", 0.92 * tb, 0.08 * tb),
                vol("/Volumes/Backup", 0.98 * tb, 0.02 * tb),
                // A simulator image is full by design and read-only: never counted.
                Volume {
                    read_only: true,
                    ..vol("/Library/Developer/CoreSimulator/Volumes/iOS", tb, 0.0)
                },
            ])),
            60.0,
            0.0,
        );
        let f = diagnose(&s);
        assert_eq!(
            f.len(),
            1,
            "one finding for every full volume, so ids stay unique"
        );
        assert_eq!(
            (f[0].severity, f[0].title.as_str()),
            (Severity::Critical, "2 volumes are over 90% full")
        );
        assert!(f[0].detail.contains("Startup disk") && f[0].detail.contains("Backup"));
    }
}
