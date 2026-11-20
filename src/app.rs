//! App state: both feeds' latest readings (every process, and the JVMs in detail), each one's
//! recent history, the pinned JVM baseline, and what's on screen.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::{Receiver, Sender, channel};

use rune::TextEdit;
use rune_kit::shell::PaneState;
use rune_kit::{SortDir, TableState};

use crate::data::{Jvm, Sample};
use crate::findings::{Finding, Link, Severity, diagnose};
use crate::groups::{self, Group, Nav, Row, Sort, SortKey};
use crate::proc_findings;
use crate::procs::{ProcError, ProcFeed, ProcSample, Process};

pub const HISTORY: usize = 120;
/// Readings kept per process: three minutes at one every 2 s.
pub const PROC_HISTORY: usize = 90;

pub type Feed = Result<Vec<Jvm>, String>;

/// A reading pinned by "Pin baseline", and which reading it was, so the timeline can mark it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Baseline {
    pub sample: Sample,
    /// How many readings of this JVM had landed when it was pinned (the pinned one included).
    pub reading: u64,
}

/// One process's recent readings, oldest first. `started` tells a reused pid from the old one.
#[derive(Clone, Debug, Default)]
pub struct Track {
    pub started: String,
    pub samples: Vec<ProcSample>,
}

pub struct App {
    pub sidebar: PaneState,
    pub jvms: Vec<Jvm>,
    pub history: HashMap<u32, VecDeque<Sample>>,
    /// Readings landed per JVM since it appeared, including those rolled out of `history`.
    pub readings: HashMap<u32, u64>,
    /// The readings the evidence compares against.
    pub baseline: HashMap<u32, Baseline>,
    /// The process (or JVM) whose page is open, over whatever `nav` shows.
    pub selected: Option<u32>,
    pub expanded: Option<String>,
    pub args_open: bool,
    /// Whether a process page shows its whole command line.
    pub cmd_all: bool,
    pub loaded: bool,
    pub error: Option<String>,
    pub feed: Option<Receiver<Feed>>,
    pub feed_tx: Option<Sender<Feed>>,

    pub procs: Vec<Process>,
    proc_index: HashMap<u32, usize>,
    pub tracks: HashMap<u32, Track>,
    pub proc_findings: Vec<Finding>,
    pub proc_loaded: bool,
    pub proc_error: Option<ProcError>,
    pub proc_feed: Option<Receiver<ProcFeed>>,
    pub proc_tx: Option<Sender<ProcFeed>>,
    /// Logical cores, to put total CPU in proportion.
    pub cores: usize,

    pub nav: Nav,
    pub sort: Sort,
    pub table: TableState,
    pub query: TextEdit,
    /// Ids of the groups shown open.
    pub open_groups: HashSet<String>,
    /// The list as it stands: `nav` and the search applied, grouped and sorted.
    pub groups: Vec<Group>,
    pub rows: Vec<Row>,
}

pub fn init() -> App {
    let (tx, rx) = channel();
    let (ptx, prx) = channel();
    let mut table = TableState::new().key("procs");
    table.set_sort("cpu", SortDir::Descending);
    App {
        sidebar: PaneState::new(240.0).range(160.0, 420.0),
        jvms: Vec::new(),
        history: HashMap::new(),
        readings: HashMap::new(),
        baseline: HashMap::new(),
        selected: None,
        expanded: None,
        args_open: false,
        cmd_all: false,
        loaded: false,
        error: None,
        feed: Some(rx),
        feed_tx: Some(tx),
        procs: Vec::new(),
        proc_index: HashMap::new(),
        tracks: HashMap::new(),
        proc_findings: Vec::new(),
        proc_loaded: false,
        proc_error: None,
        proc_feed: Some(prx),
        proc_tx: Some(ptx),
        cores: std::thread::available_parallelism().map_or(1, |n| n.get()),
        nav: Nav::Overview,
        sort: Sort::default(),
        table,
        query: TextEdit::new(""),
        open_groups: HashSet::new(),
        groups: Vec::new(),
        rows: Vec::new(),
    }
}

impl App {
    pub fn land(&mut self, feed: Feed) {
        self.loaded = true;
        match feed {
            Ok(jvms) => {
                self.error = None;
                let live = |pid: &u32| jvms.iter().any(|j| j.pid == *pid);
                self.history.retain(|pid, _| live(pid));
                self.readings.retain(|pid, _| live(pid));
                self.baseline.retain(|pid, _| live(pid));
                for j in &jvms {
                    let h = self.history.entry(j.pid).or_default();
                    h.push_back(j.sample());
                    if h.len() > HISTORY {
                        h.pop_front();
                    }
                    *self.readings.entry(j.pid).or_default() += 1;
                }
                self.jvms = jvms;
                self.drop_gone_selection();
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Takes a reading of every process: extends each one's history, forgets the ones that
    /// ended, and rebuilds the list and the process findings.
    pub fn land_procs(&mut self, feed: ProcFeed) {
        self.proc_loaded = true;
        let procs = match feed {
            Ok(procs) => procs,
            Err(e) => {
                self.proc_error = Some(e);
                return;
            }
        };
        self.proc_error = None;
        let mut tracks = HashMap::with_capacity(procs.len());
        for p in &procs {
            let mut t = self.tracks.remove(&p.pid).filter(|t| t.started == p.started_at).unwrap_or_else(|| Track {
                started: p.started_at.clone(),
                samples: Vec::new(),
            });
            t.samples.push(p.sample());
            if t.samples.len() > PROC_HISTORY {
                t.samples.remove(0);
            }
            tracks.insert(p.pid, t);
        }
        self.tracks = tracks;
        self.proc_index = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
        self.procs = procs;
        let tracks = &self.tracks;
        let empty: &[ProcSample] = &[];
        self.proc_findings = proc_findings::diagnose(&self.procs, &|pid| tracks.get(&pid).map_or(empty, |t| t.samples.as_slice()));
        self.drop_gone_selection();
        self.rebuild();
    }

    /// Closes the open page once its process is in neither feed.
    fn drop_gone_selection(&mut self) {
        if let Some(pid) = self.selected
            && self.process(pid).is_none()
            && self.jvm(pid).is_none()
        {
            self.selected = None;
        }
    }

    /// Whether the process feed works; without it the app shows only JVMs.
    pub fn has_processes(&self) -> bool {
        self.proc_error.is_none() && !self.procs.is_empty()
    }

    pub fn process(&self, pid: u32) -> Option<&Process> {
        self.proc_index.get(&pid).and_then(|&i| self.procs.get(i))
    }

    pub fn children(&self, pid: u32) -> Vec<&Process> {
        self.procs.iter().filter(|p| p.ppid == pid && p.pid != pid).collect()
    }

    pub fn proc_history(&self, pid: u32) -> &[ProcSample] {
        self.tracks.get(&pid).map_or(&[], |t| t.samples.as_slice())
    }

    /// Re-cuts the list after a reading, a sidebar choice, a search, a sort or a group opening.
    pub fn rebuild(&mut self) {
        let q = self.query.text.trim().to_lowercase();
        let nav = if self.nav == Nav::Overview { Nav::All } else { self.nav };
        let kept: Vec<&Process> = self
            .procs
            .iter()
            .filter(|p| nav.holds(p) && groups::matches_query(p, &q))
            .collect();
        self.groups = groups::group(&kept, self.sort);
        self.rows = groups::flatten(&self.groups, &self.open_groups);
    }

    /// Shows `nav` in the main pane, closing any open page.
    pub fn show(&mut self, nav: Nav) {
        self.nav = nav;
        self.selected = None;
        self.table.clear_selection();
        self.rebuild();
    }

    pub fn toggle_group(&mut self, id: &str) {
        if !self.open_groups.remove(id) {
            self.open_groups.insert(id.to_owned());
        }
        self.rebuild();
    }

    /// A header click: CPU and memory start busiest first, names A to Z.
    pub fn sort_by(&mut self, column: &str, dir: SortDir) {
        let key = match column {
            "mem" => SortKey::Memory,
            "name" => SortKey::Name,
            _ => SortKey::Cpu,
        };
        let descending = if key != self.sort.key && key != SortKey::Name {
            true
        } else {
            dir == SortDir::Descending
        };
        self.sort = Sort { key, descending };
        self.table.set_sort(column, if descending { SortDir::Descending } else { SortDir::Ascending });
        self.rebuild();
    }

    /// A list row was pressed: a group opens or closes, a process opens its page.
    pub fn press_row(&mut self, id: &str) {
        if let Some(group) = id.strip_prefix("g:") {
            self.toggle_group(group);
        } else if let Some(pid) = id.strip_prefix("p:").and_then(|p| p.parse().ok()) {
            self.select(Some(pid));
        }
    }

    pub fn follow(&mut self, link: Link) {
        match link {
            Link::Process(pid) => self.select(Some(pid)),
            Link::Unidentified => self.show(Nav::Unidentified),
        }
    }

    pub fn history(&self, pid: u32) -> Vec<Sample> {
        self.history
            .get(&pid)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn jvm(&self, pid: u32) -> Option<&Jvm> {
        self.jvms.iter().find(|j| j.pid == pid)
    }

    /// Every finding, worst first.
    pub fn findings(&self) -> Vec<Finding> {
        let mut all: Vec<Finding> = self
            .jvms
            .iter()
            .flat_map(|j| diagnose(j, &self.history(j.pid)))
            .chain(self.proc_findings.iter().cloned())
            .collect();
        all.sort_by_key(|f| (f.severity, f.pid));
        all
    }

    /// One process's findings, its JVM's included, worst first.
    pub fn findings_for(&self, pid: u32) -> Vec<Finding> {
        let mut all: Vec<Finding> = self
            .jvm(pid)
            .map(|j| diagnose(j, &self.history(pid)))
            .unwrap_or_default();
        all.extend(self.proc_findings.iter().filter(|f| f.link == Link::Process(pid)).cloned());
        all.sort_by_key(|f| f.severity);
        all
    }

    pub fn worst(&self, pid: u32) -> Severity {
        self.findings_for(pid)
            .first()
            .map_or(Severity::Healthy, |f| f.severity)
    }

    /// Where the baseline sits in `history(pid)`, if it hasn't rolled out of it.
    pub fn baseline_index(&self, pid: u32) -> Option<usize> {
        let base = self.baseline.get(&pid)?;
        let len = self.history.get(&pid).map_or(0, VecDeque::len);
        baseline_index(
            self.readings.get(&pid).copied().unwrap_or(0),
            len,
            base.reading,
        )
    }

    /// Pins every JVM's latest reading, or clears the baseline when one is pinned.
    pub fn toggle_baseline(&mut self) {
        if !self.baseline.is_empty() {
            self.baseline.clear();
            return;
        }
        self.baseline = self
            .jvms
            .iter()
            .map(|j| {
                (
                    j.pid,
                    Baseline {
                        sample: j.sample(),
                        reading: self.readings.get(&j.pid).copied().unwrap_or(0),
                    },
                )
            })
            .collect();
    }

    pub fn select(&mut self, pid: Option<u32>) {
        if self.selected != pid {
            self.cmd_all = false;
        }
        self.selected = pid;
    }
}

/// The index in a history of `len` readings of the reading that was number `pinned` (1-based)
/// when `landed` readings have landed in all. `None` once it has rolled out, or before any landed.
pub fn baseline_index(landed: u64, len: usize, pinned: u64) -> Option<usize> {
    let first = landed.checked_sub(len as u64)?; // readings that rolled out before the window
    let idx = pinned.checked_sub(1)?.checked_sub(first)?;
    (idx < len as u64).then_some(idx as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data;
    use crate::groups::tests::proc;

    fn started(mut p: Process, at: &str) -> Process {
        p.started_at = at.into();
        p
    }

    #[test]
    fn process_history_is_bounded_and_forgets_ended_processes() {
        let mut s = init();
        for i in 0..(PROC_HISTORY + 5) {
            s.land_procs(Ok(vec![proc(1, "a", i as f64, 1.0), proc(2, "b", 0.0, 1.0)]));
        }
        assert_eq!(s.proc_history(1).len(), PROC_HISTORY);
        assert_eq!(s.proc_history(1)[0].cpu, 5.0, "the oldest rolled out");
        s.land_procs(Ok(vec![proc(1, "a", 0.0, 1.0)]));
        assert!(s.proc_history(2).is_empty(), "pid 2 ended");
        assert!(!s.tracks.contains_key(&2));
    }

    #[test]
    fn a_reused_pid_starts_a_new_history() {
        let mut s = init();
        s.land_procs(Ok(vec![started(proc(1, "a", 1.0, 1.0), "09:00")]));
        s.land_procs(Ok(vec![started(proc(1, "a", 2.0, 1.0), "09:00")]));
        assert_eq!(s.proc_history(1).len(), 2);
        s.land_procs(Ok(vec![started(proc(1, "b", 3.0, 1.0), "10:00")]));
        assert_eq!(s.proc_history(1).len(), 1);
    }

    #[test]
    fn a_failed_reading_keeps_the_last_list_and_an_ended_page_closes() {
        let mut s = init();
        s.land_procs(Ok(vec![proc(1, "a", 1.0, 1.0), proc(2, "b", 1.0, 1.0)]));
        s.select(Some(2));
        s.land_procs(Err(ProcError::Failed("boom".into())));
        assert_eq!(s.procs.len(), 2);
        assert_eq!(s.selected, Some(2));
        s.land_procs(Ok(vec![proc(1, "a", 1.0, 1.0)]));
        assert_eq!(s.selected, None);
        assert!(s.has_processes());
    }

    #[test]
    fn sorting_by_a_new_column_starts_busiest_first() {
        let mut s = init();
        s.land_procs(Ok(vec![proc(1, "a", 1.0, 5.0), proc(2, "b", 9.0, 1.0)]));
        s.show(Nav::All);
        assert_eq!(s.rows[0].id, "p:2", "CPU, busiest first");
        s.sort_by("mem", SortDir::Ascending);
        assert_eq!(s.sort, Sort { key: SortKey::Memory, descending: true });
        assert_eq!(s.rows[0].id, "p:1");
        s.sort_by("mem", SortDir::Ascending);
        assert_eq!(s.rows[0].id, "p:2", "a second click flips it");
        s.sort_by("name", SortDir::Ascending);
        assert_eq!(s.rows[0].id, "p:1", "names start A to Z");
    }

    #[test]
    fn baseline_index_follows_history_as_it_rolls() {
        // Pinned at reading 3 of 8, nothing rolled out: index 2.
        assert_eq!(baseline_index(8, 8, 3), Some(2));
        // 130 readings, history holds the last 120 (11..=130): reading 15 is at index 4.
        assert_eq!(baseline_index(130, HISTORY, 15), Some(4));
        // Reading 10 has rolled out.
        assert_eq!(baseline_index(130, HISTORY, 10), None);
        assert_eq!(baseline_index(0, 0, 0), None);
    }

    #[test]
    fn baseline_marker_survives_history_rolling_past_its_limit() {
        let mut s = init();
        let jvm = |ou: f64| Jvm {
            pid: 9,
            main_class: "a.B".into(),
            gc: Some(data::Gc {
                ou,
                ..data::Gc::default()
            }),
            ..Jvm::default()
        };
        for i in 0..5 {
            s.land(Ok(vec![jvm(i as f64)]));
        }
        s.toggle_baseline();
        assert_eq!(s.baseline_index(9), Some(4));
        for i in 5..(HISTORY + 2) {
            s.land(Ok(vec![jvm(i as f64)]));
        }
        // 122 readings landed, history holds 3..=122; the pinned reading 5 is at index 2.
        assert_eq!(s.baseline_index(9), Some(2));
        assert_eq!(
            s.history(9)[2].old_used_kib,
            s.baseline[&9].sample.old_used_kib
        );
        for i in 0..3 {
            s.land(Ok(vec![jvm(i as f64)]));
        }
        assert_eq!(s.baseline_index(9), None);
    }
}
