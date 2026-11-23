//! What changed before it got slow: `spectra timeline` (processes that started and are still
//! running, error lines in the system log, installs) merged with `spectra updates --history`
//! (installs and updates, with who made them) over a chosen window, newest first. Error lines
//! from one process close together read as one burst. Read when the Timeline page opens, when
//! its window changes and on Refresh; never on a timer.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use serde::Deserialize;

use crate::app::App;
use crate::groups::Nav;
use crate::inspect::{Failure, Spectra};
use crate::procs::parse_rfc3339;

/// How long `spectra timeline` may take: a week of the system log can be slow to read.
pub const DEADLINE: Duration = Duration::from_secs(90);
/// How long `spectra updates --history` may take.
pub const UPDATES_DEADLINE: Duration = Duration::from_secs(45);
/// The most `spectra timeline` may print; a week here was 1.5 MB.
const MAX_OUTPUT: usize = 32 << 20;
/// The most `spectra updates --history` may print.
const UPDATES_OUTPUT: usize = 4 << 20;
/// Error lines one process wrote no further apart than this, in seconds, are one burst.
pub const BURST_GAP: i64 = 60;
/// Spectra keeps this many error lines of a window, the earliest first.
pub const LOG_CAP: usize = 5000;
/// How far before the load climbed, in seconds, a row counts as "around when things got slow".
pub const SLOW_BEFORE: i64 = 5 * 60;
/// And how far after, since the 1-minute load lags what it measures.
pub const SLOW_AFTER: i64 = 60;

/// How far back the page looks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Window {
    #[default]
    Hour,
    Hours6,
    Day,
    Week,
}

impl Window {
    pub const ALL: [Window; 4] = [Window::Hour, Window::Hours6, Window::Day, Window::Week];

    pub fn label(self) -> &'static str {
        match self {
            Window::Hour => "Last hour",
            Window::Hours6 => "6 h",
            Window::Day => "24 h",
            Window::Week => "7 days",
        }
    }

    /// Spectra's `--since`.
    pub fn arg(self) -> &'static str {
        match self {
            Window::Hour => "1h",
            Window::Hours6 => "6h",
            Window::Day => "24h",
            Window::Week => "168h",
        }
    }

    pub fn secs(self) -> i64 {
        match self {
            Window::Hour => 3600,
            Window::Hours6 => 6 * 3600,
            Window::Day => 24 * 3600,
            Window::Week => 7 * 24 * 3600,
        }
    }

    /// "in the last hour", for sentences.
    pub fn words(self) -> &'static str {
        match self {
            Window::Hour => "in the last hour",
            Window::Hours6 => "in the last 6 hours",
            Window::Day => "in the last 24 hours",
            Window::Week => "in the last 7 days",
        }
    }
}

/// What a row is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A process that started in the window and is still running.
    Start,
    /// Error lines one process wrote to the system log.
    Errors,
    /// Software installed or updated.
    Install,
}

/// Which rows show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Only(Kind),
}

impl Filter {
    pub const ALL: [Filter; 4] = [
        Filter::All,
        Filter::Only(Kind::Start),
        Filter::Only(Kind::Errors),
        Filter::Only(Kind::Install),
    ];

    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "Everything",
            Filter::Only(Kind::Start) => "Starts",
            Filter::Only(Kind::Errors) => "Errors",
            Filter::Only(Kind::Install) => "Installs",
        }
    }

    pub fn admits(self, kind: Kind) -> bool {
        match self {
            Filter::All => true,
            Filter::Only(k) => k == kind,
        }
    }
}

/// An install or update.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Install {
    pub name: String,
    pub version: String,
    /// `Apple` or `3rd Party`, as Spectra has it; empty when it didn't say.
    pub source: String,
}

impl Install {
    pub fn apple(&self) -> bool {
        self.source.eq_ignore_ascii_case("apple")
    }
}

/// One line of the timeline.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// Unix seconds: when it happened, or a burst's first line.
    pub at: i64,
    /// A burst's last line; `at` for anything else.
    pub until: i64,
    pub kind: Kind,
    /// The process that started or wrote the errors; empty for an install.
    pub process: String,
    /// A start's pid.
    pub pid: Option<u32>,
    /// Error lines in a burst.
    pub count: usize,
    /// A burst's first message.
    pub message: String,
    /// Whether any line in a burst was a fault or error rather than a warning.
    pub loud: bool,
    pub install: Option<Install>,
}

impl Row {
    /// One plain sentence.
    pub fn sentence(&self) -> String {
        match self.kind {
            Kind::Start => match self.pid {
                Some(pid) => format!("{} started (pid {pid}).", self.process),
                None => format!("{} started.", self.process),
            },
            Kind::Errors => {
                let who = if self.process.is_empty() {
                    "A process"
                } else {
                    &self.process
                };
                let (what, one) = if self.loud {
                    ("error", "an error")
                } else {
                    ("warning", "a warning")
                };
                let msg = short(&self.message, 160);
                if self.count <= 1 {
                    format!("{who} logged {one}: {msg}")
                } else {
                    format!(
                        "{who} logged {} {what}s in {}: {msg}",
                        self.count,
                        span(self.until - self.at)
                    )
                }
            }
            Kind::Install => {
                let Some(i) = &self.install else {
                    return "Something was installed.".into();
                };
                let mut s = format!("Installed {}", i.name);
                if !i.version.is_empty() {
                    s.push(' ');
                    s.push_str(&i.version);
                }
                if i.apple() {
                    s.push_str(" (Apple)");
                } else if !i.source.is_empty() {
                    s.push_str(" (third party)");
                }
                s.push('.');
                s
            }
        }
    }

    /// Tells this row from the others, for its key.
    pub fn id(&self) -> String {
        let kind = match self.kind {
            Kind::Start => "s",
            Kind::Errors => "e",
            Kind::Install => "i",
        };
        let who = match (&self.install, self.pid) {
            (Some(i), _) => i.name.clone(),
            (None, Some(pid)) => pid.to_string(),
            (None, None) => self.process.clone(),
        };
        format!("{kind}-{}-{}", self.at, who.replace(' ', "_"))
    }
}

/// `under a minute`, `3 min`, `2 h`.
fn span(secs: i64) -> String {
    match secs.max(0) {
        0..60 => "under a minute".into(),
        s @ 60..3600 => format!("{} min", s / 60),
        s => format!("{} h", s / 3600),
    }
}

/// `s` cut to about `n` characters, on a character boundary, with an ellipsis.
fn short(s: &str, n: usize) -> String {
    let s = s.trim();
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}…", s[..i].trim_end()),
        None => s.to_owned(),
    }
}

/// The merged timeline, newest first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timeline {
    pub rows: Vec<Row>,
    /// Seconds east of UTC the machine's clock reads, from Spectra's own times; None when no
    /// time carried an offset.
    pub offset: Option<i64>,
    /// Error lines Spectra listed: at [`LOG_CAP`], later ones in the window may be missing.
    pub log_lines: usize,
    /// Why the install history couldn't be read, when it couldn't; installs then come from the
    /// timeline alone.
    pub updates_error: Option<String>,
}

impl Timeline {
    pub fn shown(&self, filter: Filter) -> Vec<&Row> {
        self.rows.iter().filter(|r| filter.admits(r.kind)).collect()
    }

    /// Whether Spectra stopped at its cap on error lines.
    pub fn log_capped(&self) -> bool {
        self.log_lines >= LOG_CAP
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawTimeline {
    events: Option<Vec<RawEvent>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawEvent {
    time: String,
    source: String,
    severity: String,
    summary: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawUpdates {
    entries: Option<Vec<RawInstall>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawInstall {
    name: String,
    version: String,
    source: String,
    install_date: String,
}

/// One event as Spectra's timeline has it, its time read.
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: i64,
    /// Seconds east of UTC its time was written in, when not `Z`.
    pub offset: Option<i64>,
    pub source: String,
    pub severity: String,
    pub summary: String,
}

/// The offset an RFC 3339 time was written in, in seconds east; None for `Z` or a bad one.
fn offset_of(s: &str) -> Option<i64> {
    let tail = s.get(19..)?;
    let i = tail.find(['+', '-'])?;
    let sign = if tail.as_bytes()[i] == b'-' { -1 } else { 1 };
    let hh: i64 = tail.get(i + 1..i + 3)?.parse().ok()?;
    let mm: i64 = tail.get(i + 4..i + 6)?.parse().ok()?;
    Some(sign * (hh * 3600 + mm * 60))
}

/// `spectra timeline --json`. An event whose time can't be read is left out.
pub fn parse_timeline(json: &str) -> Result<Vec<Event>, String> {
    let raw: RawTimeline = serde_json::from_str(json)
        .map_err(|e| format!("Spectra's timeline couldn't be read: {e}"))?;
    Ok(raw
        .events
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| {
            Some(Event {
                at: parse_rfc3339(&e.time)?,
                offset: offset_of(&e.time),
                source: e.source,
                severity: e.severity,
                summary: e.summary,
            })
        })
        .collect())
}

/// `spectra updates --history --json`: each install and when. One without a time is left out.
pub fn parse_updates(json: &str) -> Result<Vec<(i64, Install)>, String> {
    let raw: RawUpdates = serde_json::from_str(json)
        .map_err(|e| format!("Spectra's install history couldn't be read: {e}"))?;
    Ok(raw
        .entries
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !e.name.trim().is_empty())
        .filter_map(|e| {
            Some((
                parse_rfc3339(&e.install_date)?,
                Install {
                    name: e.name.trim().to_owned(),
                    version: e.version.trim().to_owned(),
                    source: e.source.trim().to_owned(),
                },
            ))
        })
        .collect())
}

/// `name [pid] started` as its name and pid.
fn read_start(summary: &str) -> Option<(String, u32)> {
    let rest = summary.trim().strip_suffix(" started")?;
    let open = rest.rfind(" [")?;
    let pid = rest[open + 2..].strip_suffix(']')?.parse().ok()?;
    Some((rest[..open].to_owned(), pid))
}

/// `installed name version`, the timeline's own words for an install, as best it can be split:
/// the last word is the version when it starts with a digit.
fn read_install(summary: &str) -> Install {
    let rest = summary.trim();
    let rest = rest.strip_prefix("installed ").unwrap_or(rest);
    match rest.rsplit_once(' ') {
        Some((name, v)) if v.starts_with(|c: char| c.is_ascii_digit()) => Install {
            name: name.to_owned(),
            version: v.to_owned(),
            source: String::new(),
        },
        _ => Install {
            name: rest.to_owned(),
            ..Install::default()
        },
    }
}

/// Merges the timeline's events with the install history into rows, newest first. With the
/// history (`installs` is Some) its installs replace the timeline's own, which name neither
/// who made them nor always the version; without it the timeline's stand. Only what happened
/// at or after `since` is kept.
pub fn merge(events: &[Event], installs: Option<&[(i64, Install)]>, since: i64) -> Timeline {
    let mut rows = Vec::new();
    let offset = events
        .iter()
        .filter(|e| e.offset.is_some())
        .max_by_key(|e| e.at)
        .and_then(|e| e.offset);
    let mut logs: Vec<&Event> = Vec::new();
    for e in events.iter().filter(|e| e.at >= since) {
        match e.source.as_str() {
            "process" => match read_start(&e.summary) {
                Some((name, pid)) => rows.push(Row {
                    at: e.at,
                    until: e.at,
                    kind: Kind::Start,
                    process: name,
                    pid: Some(pid),
                    count: 1,
                    message: String::new(),
                    loud: false,
                    install: None,
                }),
                None => rows.push(Row {
                    at: e.at,
                    until: e.at,
                    kind: Kind::Start,
                    process: e.summary.trim().trim_end_matches(" started").to_owned(),
                    pid: None,
                    count: 1,
                    message: String::new(),
                    loud: false,
                    install: None,
                }),
            },
            "log" => logs.push(e),
            "update" if installs.is_none() => {
                rows.push(install_row(e.at, read_install(&e.summary)))
            }
            _ => {}
        }
    }
    for (at, i) in installs.unwrap_or_default() {
        if *at >= since {
            rows.push(install_row(*at, i.clone()));
        }
    }
    let log_lines = events.iter().filter(|e| e.source == "log").count();
    rows.extend(bursts(&mut logs));
    // Newest first; ties keep a stable order by kind and who.
    rows.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.id().cmp(&b.id())));
    Timeline {
        rows,
        offset,
        log_lines,
        updates_error: None,
    }
}

fn install_row(at: i64, install: Install) -> Row {
    Row {
        at,
        until: at,
        kind: Kind::Install,
        process: String::new(),
        pid: None,
        count: 1,
        message: String::new(),
        loud: false,
        install: Some(install),
    }
}

/// Error lines as bursts: one process's lines no more than [`BURST_GAP`] apart are one row.
fn bursts(logs: &mut [&Event]) -> Vec<Row> {
    logs.sort_by_key(|e| e.at);
    let mut open: HashMap<String, Row> = HashMap::new();
    let mut out = Vec::new();
    for e in logs.iter() {
        let (who, msg) = match e.summary.split_once(": ") {
            Some((who, msg)) if !who.contains(' ') || who.len() <= 40 => {
                (who.trim().to_owned(), msg.to_owned())
            }
            _ => (String::new(), e.summary.clone()),
        };
        let loud = !e.severity.eq_ignore_ascii_case("warn");
        match open.get_mut(&who) {
            Some(r) if e.at - r.until <= BURST_GAP => {
                r.until = e.at;
                r.count += 1;
                r.loud |= loud;
            }
            _ => {
                let row = Row {
                    at: e.at,
                    until: e.at,
                    kind: Kind::Errors,
                    process: who.clone(),
                    pid: None,
                    count: 1,
                    message: msg,
                    loud,
                    install: None,
                };
                if let Some(done) = open.insert(who, row) {
                    out.push(done);
                }
            }
        }
    }
    out.extend(open.into_values());
    out
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A civil date from days since 1970-01-01 (Howard Hinnant's civil_from_days).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// The clock time of `at` on a clock `offset` seconds east: `21:07`, or `Nov 19, 21:07` when it
/// isn't the same day as `now`.
pub fn clock(at: i64, now: i64, offset: i64) -> String {
    let local = at + offset;
    let (day, secs) = (local.div_euclid(86_400), local.rem_euclid(86_400));
    let hm = format!("{:02}:{:02}", secs / 3600, secs % 3600 / 60);
    if day == (now + offset).div_euclid(86_400) {
        hm
    } else {
        let (_, m, d) = civil(day);
        format!("{} {d}, {hm}", MONTHS[(m - 1) as usize])
    }
}

/// How long ago: `just now`, `40 s ago`, `12 min ago`, `3 h ago`, `2 days ago`.
pub fn ago(secs: i64) -> String {
    match secs.max(0) {
        0..5 => "just now".into(),
        s @ 5..60 => format!("{s} s ago"),
        s @ 60..3600 => format!("{} min ago", s / 60),
        s @ 3600..86_400 => format!("{} h ago", s / 3600),
        s if s < 2 * 86_400 => "1 day ago".into(),
        s => format!("{} days ago", s / 86_400),
    }
}

/// Where a row leads.
#[derive(Clone, Debug, PartialEq)]
pub enum Go {
    Process(u32),
    App(String),
}

/// When the load last climbed past one per core and has stayed there, in Unix seconds, from the
/// Machine page's load history (a reading every 5 s, six minutes kept). None when it isn't high
/// now, or it was already high when the history begins, so when it climbed isn't known.
pub fn slow_since(
    loads: &[f64],
    cpus: u32,
    updated_ago: f64,
    every: f64,
    wall: i64,
) -> Option<i64> {
    if cpus == 0 {
        return None;
    }
    let high = |l: &f64| *l >= f64::from(cpus);
    let run = loads.iter().rev().take_while(|l| high(l)).count();
    if run == 0 || run == loads.len() {
        return None;
    }
    // The first high reading landed `run - 1` readings before the last one.
    let back = updated_ago + every * (run - 1) as f64;
    Some(wall - back.round() as i64)
}

/// Whether a row happened around when the load climbed at `onset`.
pub fn around(row: &Row, onset: i64) -> bool {
    row.until >= onset - SLOW_BEFORE && row.at <= onset + SLOW_AFTER
}

/// Both commands, as the page runs them.
pub fn timeline_args(w: Window) -> Vec<String> {
    ["timeline", "--since", w.arg(), "--json"]
        .map(String::from)
        .to_vec()
}

pub fn updates_args(w: Window) -> Vec<String> {
    ["updates", "--history", "--since", w.arg(), "--json"]
        .map(String::from)
        .to_vec()
}

/// Reads the timeline and the install history for `w`, as of `wall`.
pub fn read(
    spectra: &dyn Spectra,
    w: Window,
    wall: i64,
    cancel: &AtomicBool,
) -> Result<Timeline, Failure> {
    let out = spectra.run_capped(&timeline_args(w), DEADLINE, MAX_OUTPUT, cancel)?;
    let events = parse_timeline(&out).map_err(Failure::Failed)?;
    let installs = spectra
        .run_capped(&updates_args(w), UPDATES_DEADLINE, UPDATES_OUTPUT, cancel)
        .and_then(|o| parse_updates(&o).map_err(Failure::Failed));
    let since = wall - w.secs();
    Ok(match installs {
        Ok(i) => merge(&events, Some(&i), since),
        Err(Failure::Cancelled) => return Err(Failure::Cancelled),
        Err(Failure::Failed(why)) => Timeline {
            updates_error: Some(why),
            ..merge(&events, None, since)
        },
    })
}

/// One reading's answer.
pub struct Landed {
    pub job: u64,
    pub result: Result<Timeline, Failure>,
}

struct Flight {
    job: u64,
    cancel: Arc<AtomicBool>,
    window: Window,
}

/// The Timeline page's state.
pub struct TimelinePage {
    pub window: Window,
    pub filter: Filter,
    /// The last good reading, its window, and the wall clock when it was asked for.
    pub data: Option<(Timeline, Window, i64)>,
    pub error: Option<String>,
    pub spectra: Arc<dyn Spectra>,
    /// False in tests: a reading runs on the calling thread.
    pub threaded: bool,
    flight: Option<Flight>,
    job: u64,
    tx: Sender<Landed>,
    rx: Receiver<Landed>,
}

impl Default for TimelinePage {
    fn default() -> TimelinePage {
        TimelinePage::new()
    }
}

impl TimelinePage {
    pub fn new() -> TimelinePage {
        let (tx, rx) = channel();
        TimelinePage {
            window: Window::default(),
            filter: Filter::default(),
            data: None,
            error: None,
            spectra: Arc::new(crate::inspect::System),
            threaded: true,
            flight: None,
            job: 0,
            tx,
            rx,
        }
    }

    /// The window being read, if a reading is on its way.
    pub fn reading(&self) -> Option<Window> {
        self.flight.as_ref().map(|f| f.window)
    }

    /// A reading that never lands and runs nothing, so a sample scene shows the page reading.
    pub fn sample_flight(&mut self) {
        self.job += 1;
        self.flight = Some(Flight {
            job: self.job,
            cancel: Arc::new(AtomicBool::new(false)),
            window: self.window,
        });
    }

    /// Stops the reading on its way, if any; its answer, when it comes, is dropped.
    pub fn cancel(&mut self) {
        if let Some(f) = self.flight.take() {
            f.cancel.store(true, Ordering::SeqCst);
        }
    }
}

impl App {
    /// Reads the timeline for the page's window, stopping any reading already on its way.
    pub fn read_timeline(&mut self) {
        let wall = (self.wall)();
        let wake = self.wake.clone();
        let t = &mut self.timeline;
        t.cancel();
        t.job += 1;
        let (job, window, cancel) = (t.job, t.window, Arc::new(AtomicBool::new(false)));
        t.flight = Some(Flight {
            job,
            cancel: Arc::clone(&cancel),
            window,
        });
        let (spectra, tx) = (Arc::clone(&t.spectra), t.tx.clone());
        if !t.threaded {
            let result = read(spectra.as_ref(), window, wall, &cancel);
            let _ = tx.send(Landed { job, result });
            return;
        }
        // Quit waits for this from now until it's done, even before Spectra starts.
        let hold = crate::run::pending();
        let thread_tx = tx.clone();
        let started = std::thread::Builder::new()
            .name("spectra-timeline".into())
            .spawn(move || {
                let result = read(spectra.as_ref(), window, wall, &cancel);
                let _ = thread_tx.send(Landed { job, result });
                drop(hold);
                if let Some(wake) = wake {
                    wake();
                }
            });
        if let Err(e) = started {
            let _ = tx.send(Landed {
                job,
                result: Err(Failure::Failed(format!(
                    "Couldn't start a thread to read the timeline: {e}."
                ))),
            });
        }
    }

    /// A different window reads again at once.
    pub fn set_timeline_window(&mut self, w: Window) {
        if self.timeline.window != w {
            self.timeline.window = w;
            self.read_timeline();
        }
    }

    pub fn set_timeline_filter(&mut self, f: Filter) {
        self.timeline.filter = f;
    }

    /// Lands finished readings. True when one changed the page.
    pub fn land_timeline(&mut self) -> bool {
        let mut changed = false;
        while let Ok(l) = self.timeline.rx.try_recv() {
            let t = &mut self.timeline;
            let Some(f) = t.flight.as_ref().filter(|f| f.job == l.job) else {
                continue;
            };
            let window = f.window;
            t.flight = None;
            match l.result {
                Ok(tl) => {
                    t.data = Some((tl, window, (self.wall)()));
                    t.error = None;
                }
                Err(Failure::Cancelled) => {}
                Err(Failure::Failed(why)) => t.error = Some(why),
            }
            changed = true;
        }
        changed
    }

    /// Leaving the page stops a reading on its way; opening it reads.
    pub fn timeline_nav(&mut self, from: Nav, to: Nav) {
        if from == Nav::Timeline && to != Nav::Timeline {
            self.timeline.cancel();
        }
        if to == Nav::Timeline {
            self.read_timeline();
        }
    }

    /// Where a row leads, if anywhere: a start to its process while that pid still runs under
    /// the same name; errors to the one running process with that name, or its app; an install
    /// to the running app of the same name.
    pub fn timeline_go(&self, r: &Row) -> Option<Go> {
        match r.kind {
            Kind::Start => {
                let pid = r.pid?;
                self.same_process(pid, &r.process)
                    .then_some(Go::Process(pid))
            }
            Kind::Errors => {
                if r.process.is_empty() {
                    return None;
                }
                let mut named = self.procs.iter().filter(|p| p.name() == r.process.as_str());
                let first = named.next()?;
                if named.next().is_none() {
                    return Some(Go::Process(first.pid));
                }
                first.bundle_path().map(|path| Go::App(path.to_owned()))
            }
            Kind::Install => {
                let name = r.install.as_ref()?.name.to_lowercase();
                self.procs.iter().find_map(|p| {
                    let app = p.app.as_ref()?;
                    (app.name.to_lowercase() == name).then(|| Go::App(app.bundle_path.clone()))
                })
            }
        }
    }

    /// When the load climbed, if it's high now and the Machine page's history saw it climb.
    pub fn slow_since(&self) -> Option<i64> {
        let load = &self.system.load;
        let (last, updated) = (load.last.as_ref()?, load.updated?);
        let loads: Vec<f64> = self.system.cpu_history.iter().map(|p| p.load1).collect();
        slow_since(
            &loads,
            last.cpus,
            self.now - updated,
            load.every.as_secs_f64(),
            (self.wall)(),
        )
    }

    pub fn follow_timeline(&mut self, go: Go) {
        match go {
            Go::Process(pid) => self.open(pid),
            Go::App(path) => self.open_app(&path),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    pub const TIMELINE: &str = include_str!("../tests/fixtures/timeline/timeline.json");
    pub const UPDATES: &str = include_str!("../tests/fixtures/timeline/updates.json");
    /// Invented, in the shape Spectra prints: local and UTC times, fractions, every source.
    pub const MIXED: &str = include_str!("../tests/fixtures/timeline/timeline-mixed.json");
    pub const UPDATES_MIXED: &str = include_str!("../tests/fixtures/timeline/updates-mixed.json");
    pub const EMPTY: &str = include_str!("../tests/fixtures/timeline/timeline-empty.json");
    pub const UPDATES_EMPTY: &str = include_str!("../tests/fixtures/timeline/updates-empty.json");

    /// 2026-11-20T12:00:00Z, the sample's clock.
    pub const NOW: i64 = 1_795_176_000;

    /// Spectra standing in with set answers by subcommand, recording what it was asked.
    pub struct Fake {
        pub replies: HashMap<&'static str, Result<String, String>>,
        pub calls: Mutex<Vec<Vec<String>>>,
    }

    impl Fake {
        pub fn new(timeline: Result<&str, &str>, updates: Result<&str, &str>) -> Fake {
            let own = |r: Result<&str, &str>| r.map(str::to_owned).map_err(str::to_owned);
            Fake {
                replies: HashMap::from([("timeline", own(timeline)), ("updates", own(updates))]),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Spectra for Fake {
        fn run(
            &self,
            args: &[String],
            _: Duration,
            cancel: &AtomicBool,
        ) -> Result<String, Failure> {
            self.calls.lock().unwrap().push(args.to_vec());
            if cancel.load(Ordering::Relaxed) {
                return Err(Failure::Cancelled);
            }
            match self.replies.get(args[0].as_str()) {
                Some(Ok(out)) => Ok(out.clone()),
                Some(Err(why)) => Err(Failure::Failed(why.clone())),
                None => Err(Failure::Failed(format!("no fake for {}", args[0]))),
            }
        }
    }

    fn sample() -> Timeline {
        let events = parse_timeline(TIMELINE).unwrap();
        let installs = parse_updates(UPDATES).unwrap();
        merge(&events, Some(&installs), NOW - Window::Day.secs())
    }

    #[test]
    fn a_mixed_reading_parses_every_kind() {
        let events = parse_timeline(MIXED).unwrap();
        assert_eq!(events.len(), 6);
        let kinds = |s: &str| events.iter().filter(|e| e.source == s).count();
        assert_eq!((kinds("process"), kinds("log"), kinds("update")), (3, 2, 1));
        // 05:42:05 at -06:00 and 11:45:00.25Z are both read as UTC seconds.
        assert_eq!(events[2].at - events[0].at, 2 * 60 + 55);
        assert_eq!(
            (events[0].offset, events[2].offset),
            (Some(-6 * 3600), None)
        );
        assert_eq!(
            read_start("Example Helper (Renderer) [4420] started"),
            Some(("Example Helper (Renderer)".into(), 4420))
        );
        let t = merge(&events, None, 0);
        assert_eq!(t.offset, Some(-6 * 3600));
        let odd = t
            .rows
            .iter()
            .find(|r| r.pid.is_none() && r.kind == Kind::Start);
        assert_eq!(odd.unwrap().sentence(), "a name without a pid started.");
        assert_eq!(t.rows.iter().filter(|r| r.kind == Kind::Errors).count(), 2);
        // A blank name or an unreadable time is left out.
        let installs = parse_updates(UPDATES_MIXED).unwrap();
        assert_eq!(installs.len(), 2);
        assert_eq!(installs[1].1.name, "Example Audio Driver 0.7.1");
        assert_eq!(installs[1].1.version, "");
        assert!(!installs[1].1.apple() && installs[0].1.apple());
    }

    #[test]
    fn missing_fields_and_null_lists_dont_fail() {
        assert!(parse_timeline(EMPTY).unwrap().is_empty());
        assert!(parse_timeline("{}").unwrap().is_empty());
        assert!(parse_updates(UPDATES_EMPTY).unwrap().is_empty());
        // An event without a time, or an install without a name, is left out; the rest stay.
        let evs = parse_timeline(
            r#"{"events": [{"summary": "x"}, {"time": "2026-11-20T06:00:00Z", "source": "process", "summary": "a [1] started", "extra": 1}]}"#,
        )
        .unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].offset, None);
        let ups =
            parse_updates(r#"{"entries": [{"install_date": "2026-11-20T06:00:00Z"}]}"#).unwrap();
        assert!(ups.is_empty());
        assert!(parse_timeline("not json").is_err());
    }

    #[test]
    fn rows_are_newest_first_with_bursts_folded() {
        let t = sample();
        assert!(t.rows.windows(2).all(|w| w[0].at >= w[1].at));
        assert_eq!(t.offset, Some(-5 * 3600));
        // Nine examplesyncd lines, each within a minute of the last, are one burst.
        let sharing: Vec<&Row> = t
            .rows
            .iter()
            .filter(|r| r.process == "examplesyncd")
            .collect();
        assert_eq!(sharing.len(), 1);
        assert_eq!(sharing[0].count, 9);
        assert_eq!(
            sharing[0].sentence(),
            "examplesyncd logged 9 errors in 1 min: could not reach the sync service, will retry"
        );
        // A lone warning reads as one.
        let mds = t.rows.iter().find(|r| r.process == "mds_stores").unwrap();
        assert_eq!(
            mds.sentence(),
            "mds_stores logged a warning: Failed to open index store at <private>"
        );
        let start = t.rows.iter().find(|r| r.pid == Some(901)).unwrap();
        assert_eq!(
            start.sentence(),
            "Slack Helper (Renderer) started (pid 901)."
        );
    }

    #[test]
    fn the_history_replaces_the_timelines_own_installs() {
        let t = sample();
        let installs: Vec<String> = t
            .rows
            .iter()
            .filter(|r| r.kind == Kind::Install)
            .map(Row::sentence)
            .collect();
        // One Slack, from the history, saying who made it; the two from before the window are out.
        assert_eq!(
            installs,
            [
                "Installed Slack 4.41.105 (third party).",
                "Installed Example Audio Driver 0.7.1 (third party).",
            ]
        );
        // Without the history, the timeline's own install stands.
        let events = parse_timeline(TIMELINE).unwrap();
        let alone = merge(&events, None, NOW - Window::Day.secs());
        let own: Vec<String> = alone
            .rows
            .iter()
            .filter(|r| r.kind == Kind::Install)
            .map(Row::sentence)
            .collect();
        assert_eq!(own, ["Installed Slack 4.41.105."]);
    }

    #[test]
    fn a_window_keeps_only_what_happened_in_it() {
        let events = parse_timeline(TIMELINE).unwrap();
        let installs = parse_updates(UPDATES).unwrap();
        let hour = merge(&events, Some(&installs), NOW - Window::Hour.secs());
        assert!(hour.rows.iter().all(|r| r.at >= NOW - 3600));
        assert!(hour.rows.len() < sample().rows.len());
        assert_eq!(hour.shown(Filter::Only(Kind::Install)).len(), 1);
    }

    #[test]
    fn filters_count_and_narrow() {
        let t = sample();
        let total = t.shown(Filter::All).len();
        let parts: usize = Filter::ALL[1..].iter().map(|f| t.shown(*f).len()).sum();
        assert_eq!(total, parts);
        assert!(
            t.shown(Filter::Only(Kind::Errors))
                .iter()
                .all(|r| r.kind == Kind::Errors)
        );
    }

    #[test]
    fn clocks_and_ages_read_plainly() {
        let off = -5 * 3600;
        assert_eq!(clock(NOW - 600, NOW, off), "06:50");
        assert_eq!(clock(NOW - 12 * 3600, NOW, off), "Nov 19, 19:00");
        assert_eq!(clock(NOW, NOW, 0), "12:00");
        assert_eq!(ago(2), "just now");
        assert_eq!(ago(42), "42 s ago");
        assert_eq!(ago(600), "10 min ago");
        assert_eq!(ago(3 * 3600 + 5), "3 h ago");
        assert_eq!(ago(30 * 3600), "1 day ago");
        assert_eq!(ago(3 * 86_400), "3 days ago");
        assert_eq!(
            offset_of("2026-11-20T06:50:03.5-05:30"),
            Some(-(5 * 3600 + 1800))
        );
        assert_eq!(offset_of("2026-11-20T06:50:03Z"), None);
    }

    #[test]
    fn the_load_onset_is_where_it_last_climbed() {
        // Calm, then high for the last three readings; the last landed 2 s ago.
        let loads = [2.0, 3.0, 9.0, 12.0, 11.0];
        assert_eq!(slow_since(&loads, 8, 2.0, 5.0, NOW), Some(NOW - 12));
        // Not high now, high all along, or no cores: not known.
        assert_eq!(slow_since(&[9.0, 2.0], 8, 0.0, 5.0, NOW), None);
        assert_eq!(slow_since(&[9.0, 9.0], 8, 0.0, 5.0, NOW), None);
        assert_eq!(slow_since(&loads, 0, 0.0, 5.0, NOW), None);
        let onset = NOW - 4 * 60;
        let t = sample();
        let marked: Vec<String> = t
            .rows
            .iter()
            .filter(|r| around(r, onset))
            .map(|r| r.process.clone() + r.install.as_ref().map_or("", |i| i.name.as_str()))
            .collect();
        assert_eq!(
            marked,
            [
                "mds_stores",
                "WindowServer",
                "Slack Helper (Renderer)",
                "Slack",
                "Slack"
            ]
        );
    }

    #[test]
    fn reading_asks_for_both_and_survives_a_failed_history() {
        let fake = Fake::new(Ok(TIMELINE), Err("updates: system_profiler failed"));
        let t = read(&fake, Window::Day, NOW, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            fake.calls(),
            [timeline_args(Window::Day), updates_args(Window::Day)]
        );
        assert_eq!(fake.calls()[0], ["timeline", "--since", "24h", "--json"]);
        assert_eq!(
            t.updates_error.as_deref(),
            Some("updates: system_profiler failed")
        );
        assert_eq!(t.shown(Filter::Only(Kind::Install)).len(), 1);
        let failed = Fake::new(Err("spectra timeline took longer than 90 s"), Ok(UPDATES));
        assert!(matches!(
            read(&failed, Window::Day, NOW, &AtomicBool::new(false)),
            Err(Failure::Failed(why)) if why.contains("90 s")
        ));
        assert_eq!(failed.calls().len(), 1, "no history without a timeline");
    }

    #[test]
    fn long_messages_are_cut_on_a_character() {
        let s = "é".repeat(200);
        let cut = short(&s, 160);
        assert_eq!(cut.chars().count(), 161);
        assert!(cut.ends_with('…'));
        assert_eq!(short("  short  ", 10), "short");
    }
}
