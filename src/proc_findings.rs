//! Findings about any process, from the process feed and each process's recent readings:
//! sustained CPU, memory that only climbs, broken signatures, and how much runs unsigned.

use crate::findings::{Chart, Finding, Link, Severity};
use crate::procs::{ProcSample, Process, SignStatus, fmt_count, fmt_cpu, fmt_mem};

/// Readings a process must stay busy for (about 16 s at one every 2 s).
pub const CPU_WINDOW: usize = 8;
/// Percent of one core that counts as busy.
pub const BUSY_CPU: f64 = 80.0;
/// The fewest readings memory growth is judged on.
pub const GROWTH_READINGS: usize = 10;

/// The average CPU over the last `CPU_WINDOW` readings, when every one of them was busy.
pub fn sustained_cpu(history: &[ProcSample]) -> Option<f64> {
    if history.len() < CPU_WINDOW {
        return None;
    }
    let tail = &history[history.len() - CPU_WINDOW..];
    tail.iter()
        .all(|s| s.cpu >= BUSY_CPU)
        .then(|| tail.iter().map(|s| s.cpu).sum::<f64>() / CPU_WINDOW as f64)
}

/// `(percent, KiB)` grown across the whole history, when memory climbed steadily: at least 20%
/// and 50 MB in all, no reading lower than the one before by more than 2%, and at least
/// four in five steps not going down.
pub fn memory_growth(history: &[ProcSample]) -> Option<(f64, f64)> {
    if history.len() < GROWTH_READINGS {
        return None;
    }
    let first = history[0].rss_kib;
    let last = history[history.len() - 1].rss_kib;
    let grown = last - first;
    if first <= 0.0 || grown < 50.0 * 1024.0 || grown / first < 0.2 {
        return None;
    }
    let steps = history.len() - 1;
    let mut up = 0;
    for w in history.windows(2) {
        if w[1].rss_kib < w[0].rss_kib * 0.98 {
            return None;
        }
        if w[1].rss_kib >= w[0].rss_kib {
            up += 1;
        }
    }
    (up * 5 >= steps * 4).then_some((grown / first * 100.0, grown))
}

fn finding(p: &Process, rule: &'static str, severity: Severity, title: String, detail: String, fix: &str, chart: Chart) -> Finding {
    Finding {
        rule,
        pid: p.pid,
        subject: p.name(),
        severity,
        title,
        detail,
        fix: fix.into(),
        chart,
        link: Link::Process(p.pid),
    }
}

/// Every process finding, in feed order; `history` gives a pid's readings, oldest first.
pub fn diagnose<'a>(procs: &[Process], history: &dyn Fn(u32) -> &'a [ProcSample]) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in procs {
        let h = history(p.pid);
        if let Some(avg) = sustained_cpu(h) {
            out.push(finding(
                p,
                "proc-busy-cpu",
                Severity::Warning,
                format!("Busy: {} CPU for the last {CPU_WINDOW} readings", fmt_cpu(avg)),
                format!("It stayed above {BUSY_CPU:.0}% in every reading; 100% is one full core."),
                "If it shouldn't be working this hard, open it to see what it runs and who started it.",
                Chart::Cpu,
            ));
        }
        if let Some((pct, kib)) = memory_growth(h) {
            out.push(finding(
                p,
                "proc-memory-growth",
                Severity::Warning,
                format!("Memory grew {pct:.0}% to {}", fmt_mem(p.rss_kib)),
                format!("Up {} across the last {} readings, and it never came back down.", fmt_mem(kib), h.len()),
                "Memory that only climbs is how a leak looks. Restart it if it keeps growing.",
                Chart::Memory,
            ));
        }
        if p.sign_status() == SignStatus::Invalid {
            let path = if p.executable_path.is_empty() { p.name() } else { p.executable_path.clone() };
            out.push(finding(
                p,
                "proc-invalid-signature",
                Severity::Critical,
                "Its code signature is invalid".into(),
                format!("{path} changed after it was signed, or its signature is broken."),
                "Reinstall it from its maker. If you didn't install it, find out what started it.",
                Chart::None,
            ));
        }
    }
    if let Some(f) = unidentified(procs) {
        out.push(f);
    }
    out
}

/// One finding for every unsigned or ad hoc signed process, naming a few.
pub fn unidentified(procs: &[Process]) -> Option<Finding> {
    let found: Vec<&Process> = procs.iter().filter(|p| p.sign_status().is_unidentified()).collect();
    if found.is_empty() {
        return None;
    }
    let adhoc = found.iter().filter(|p| p.sign_status() == SignStatus::Adhoc).count();
    let unsigned = found.len() - adhoc;
    let mut names: Vec<String> = found.iter().map(|p| p.name()).collect();
    names.sort();
    names.dedup();
    let shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let rest = names.len().saturating_sub(3);
    let more = if rest > 0 { format!(" and {rest} more") } else { String::new() };
    let split = match (adhoc, unsigned) {
        (0, u) => format!("{} unsigned", fmt_count(u as u64)),
        (a, 0) => format!("{} ad hoc", fmt_count(a as u64)),
        (a, u) => format!("{} ad hoc, {} unsigned", fmt_count(a as u64), fmt_count(u as u64)),
    };
    let n = found.len();
    Some(Finding {
        rule: "proc-unidentified",
        pid: 0,
        subject: "Show them".into(),
        severity: Severity::Info,
        title: format!(
            "{} {} no identified developer behind {}",
            fmt_count(n as u64),
            if n == 1 { "process has" } else { "processes have" },
            if n == 1 { "it" } else { "them" }
        ),
        detail: format!("{split}: {shown}{more}. Tools you built yourself or installed from source often look like this."),
        fix: "Check you recognise each one. Anything you don't, find out what started it.".into(),
        chart: Chart::None,
        link: Link::Unidentified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::tests::proc;
    use crate::procs::Signing;

    fn cpu(values: &[f64]) -> Vec<ProcSample> {
        values.iter().map(|&cpu| ProcSample { cpu, rss_kib: 1.0 }).collect()
    }

    fn mem(values: &[f64]) -> Vec<ProcSample> {
        values.iter().map(|&mb| ProcSample { cpu: 0.0, rss_kib: mb * 1024.0 }).collect()
    }

    #[test]
    fn busy_in_every_recent_reading_is_sustained() {
        assert_eq!(sustained_cpu(&cpu(&[100.0; 8])), Some(100.0));
        assert_eq!(sustained_cpu(&cpu(&[0.0, 0.0, 90.0, 90.0, 90.0, 90.0, 90.0, 90.0, 90.0, 90.0])), Some(90.0));
        let mut dip = vec![100.0; 8];
        dip[4] = 20.0;
        assert_eq!(sustained_cpu(&cpu(&dip)), None, "one quiet reading breaks it");
        assert_eq!(sustained_cpu(&cpu(&[100.0; 7])), None, "too few readings");
    }

    #[test]
    fn memory_that_only_climbs_is_growth() {
        let climbing: Vec<f64> = (0..12).map(|i| 200.0 + 10.0 * i as f64).collect();
        let (pct, kib) = memory_growth(&mem(&climbing)).unwrap();
        assert_eq!(pct.round(), 55.0);
        assert_eq!(kib, 110.0 * 1024.0);
        // Flat stretches are fine.
        let mut steps = climbing.clone();
        steps[3] = steps[2];
        assert!(memory_growth(&mem(&steps)).is_some());
        // A real drop is a collection, not a leak.
        let mut sawtooth = climbing.clone();
        sawtooth[6] = 150.0;
        assert_eq!(memory_growth(&mem(&sawtooth)), None);
        // Too little to matter.
        let small: Vec<f64> = (0..12).map(|i| 10.0 + i as f64).collect();
        assert_eq!(memory_growth(&mem(&small)), None, "under 50 MB");
        assert_eq!(memory_growth(&mem(&climbing[..9])), None, "too few readings");
    }

    #[test]
    fn invalid_signatures_are_critical_and_unidentified_ones_are_one_finding() {
        let mut v = vec![proc(1, "good", 0.0, 1.0), proc(2, "bad", 0.0, 1.0), proc(3, "java", 0.0, 1.0), proc(4, "java", 0.0, 1.0), proc(5, "mine", 0.0, 1.0)];
        let sign = |s| Some(Signing { status: s, ..Signing::default() });
        v[0].signing = sign(SignStatus::Apple);
        v[1].signing = sign(SignStatus::Invalid);
        v[2].signing = sign(SignStatus::Adhoc);
        v[3].signing = sign(SignStatus::Adhoc);
        v[4].signing = sign(SignStatus::Unsigned);
        let empty: &[ProcSample] = &[];
        let f = diagnose(&v, &|_| empty);
        let rules: Vec<(&str, u32, Severity)> = f.iter().map(|f| (f.rule, f.pid, f.severity)).collect();
        assert_eq!(rules, [("proc-invalid-signature", 2, Severity::Critical), ("proc-unidentified", 0, Severity::Info)]);
        assert_eq!(f[0].link, Link::Process(2));
        assert_eq!(f[1].link, Link::Unidentified);
        assert_eq!(f[1].title, "3 processes have no identified developer behind them");
        assert!(f[1].detail.starts_with("2 ad hoc, 1 unsigned: java, mine."), "{}", f[1].detail);
        assert!(unidentified(&v[..2]).is_none());
    }

    #[test]
    fn busy_and_growing_processes_link_to_themselves() {
        let v = vec![proc(7, "busy", 150.0, 1.0)];
        let h: Vec<ProcSample> = (0..12).map(|i| ProcSample { cpu: 150.0, rss_kib: (300.0 + 20.0 * i as f64) * 1024.0 }).collect();
        let f = diagnose(&v, &|_| h.as_slice());
        let rules: Vec<&str> = f.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["proc-busy-cpu", "proc-memory-growth"]);
        assert!(f.iter().all(|f| f.link == Link::Process(7)));
        assert_eq!(f[0].title, "Busy: 150.0% CPU for the last 8 readings");
        assert_eq!(f[0].chart, Chart::Cpu);
    }
}
