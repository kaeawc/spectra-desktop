//! How the process list is cut and ordered: which processes a sidebar choice and the search
//! keep, how they gather into rows a person recognises (an app with its helpers, twelve zsh),
//! and a sort that keeps rows still when values tie.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use crate::procs::{Process, Role, Runtime, SignStatus};

/// The sidebar's categories, by what a process is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Apps,
    Agents,
    Terminals,
    DevTools,
    System,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Apps,
        Category::Agents,
        Category::Terminals,
        Category::DevTools,
        Category::System,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Apps => "Apps",
            Category::Agents => "AI agents",
            Category::Terminals => "Terminals and shells",
            Category::DevTools => "Developer tools",
            Category::System => "System",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Category::Apps => "apps",
            Category::Agents => "agents",
            Category::Terminals => "terminals",
            Category::DevTools => "devtools",
            Category::System => "system",
        }
    }

    pub fn holds(self, role: Role) -> bool {
        match self {
            Category::Apps => matches!(role, Role::App | Role::AppHelper),
            Category::Agents => role == Role::AiAgent,
            Category::Terminals => matches!(role, Role::Terminal | Role::Shell),
            Category::DevTools => role == Role::Cli,
            Category::System => role == Role::System,
        }
    }
}

/// What the main pane shows when no process is open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Nav {
    #[default]
    Overview,
    All,
    Category(Category),
    Runtime(Runtime),
    /// Unsigned and ad hoc signed processes, reached from their finding.
    Unidentified,
}

impl Nav {
    pub fn title(self) -> &'static str {
        match self {
            Nav::Overview => "Overview",
            Nav::All => "All processes",
            Nav::Category(c) => c.label(),
            Nav::Runtime(r) => r.label(),
            Nav::Unidentified => "Unsigned or ad hoc",
        }
    }

    /// Whether `p` belongs in this list. The overview lists nothing.
    pub fn holds(self, p: &Process) -> bool {
        match self {
            Nav::Overview => false,
            Nav::All => true,
            Nav::Category(c) => c.holds(p.role),
            Nav::Runtime(r) => p.runtime == r,
            Nav::Unidentified => p.sign_status().is_unidentified(),
        }
    }
}

/// Whether `p` matches a search, lowercased and trimmed: by name, pid, app, bundle id or path.
pub fn matches_query(p: &Process, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    let has = |s: &str| s.to_lowercase().contains(q);
    p.pid.to_string() == q
        || has(&p.name())
        || has(&p.executable_path)
        || p.app.as_ref().is_some_and(|a| has(&a.name) || has(&a.bundle_id) || has(&a.bundle_path))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Cpu,
    Memory,
    Name,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort {
    pub key: SortKey,
    pub descending: bool,
}

impl Default for Sort {
    fn default() -> Sort {
        Sort {
            key: SortKey::Cpu,
            descending: true,
        }
    }
}

impl Sort {
    /// Orders by the sort key, then always by name and an id ascending, so equal values keep
    /// their places from one reading to the next.
    fn order(self, a: (f64, f64, &str, &str), b: (f64, f64, &str, &str)) -> Ordering {
        let by_name = || caseless(a.2, b.2);
        let by_key = match self.key {
            SortKey::Cpu => a.0.total_cmp(&b.0),
            SortKey::Memory => a.1.total_cmp(&b.1),
            SortKey::Name => by_name(),
        };
        let by_key = if self.descending { by_key.reverse() } else { by_key };
        by_key.then_with(by_name).then_with(|| a.3.cmp(b.3))
    }

    pub fn processes(self, a: &Process, b: &Process) -> Ordering {
        let (na, nb) = (a.name(), b.name());
        self.order((a.cpu_pct, a.rss_kib, &na, ""), (b.cpu_pct, b.rss_kib, &nb, ""))
            .then(a.pid.cmp(&b.pid))
    }

    pub fn groups(self, a: &Group, b: &Group) -> Ordering {
        self.order((a.cpu, a.rss_kib, &a.name, &a.id), (b.cpu, b.rss_kib, &b.name, &b.id))
    }
}

/// Compares names ignoring case (ASCII ones without allocating); exact case breaks a tie.
fn caseless(a: &str, b: &str) -> Ordering {
    let fold = |s: &str| s.chars().flat_map(char::to_lowercase).collect::<Vec<_>>();
    if a.is_ascii() && b.is_ascii() {
        a.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
            .then_with(|| a.cmp(b))
    } else {
        fold(a).cmp(&fold(b)).then_with(|| a.cmp(b))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// An app bundle and its helpers.
    App,
    /// Several processes running the same executable.
    Exe,
    /// One process on its own.
    Single,
}

/// One row of the list before it's opened: an app, a set of same-named processes, or one process.
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    /// Stable across readings; never holds `/`, which element-key paths use.
    pub id: String,
    pub name: String,
    pub kind: GroupKind,
    /// Members, in the list's sort order.
    pub pids: Vec<u32>,
    /// The process that speaks for the group: the app itself rather than a helper.
    pub lead: u32,
    pub cpu: f64,
    pub rss_kib: f64,
    pub threads: u64,
    pub role: Role,
    pub runtime: Runtime,
    /// The worst signature among the members.
    pub signing: SignStatus,
}

fn key_safe(s: &str) -> String {
    s.replace('/', ":")
}

/// Gathers `procs` into groups, sorted by `sort`, members too.
pub fn group(procs: &[&Process], sort: Sort) -> Vec<Group> {
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for p in procs.iter().filter(|p| p.bundle_path().is_none()) {
        *by_name.entry(p.name()).or_default() += 1;
    }
    let mut order: Vec<String> = Vec::new();
    let mut members: HashMap<String, (GroupKind, String, Vec<&Process>)> = HashMap::new();
    for p in procs {
        let (id, kind, name) = match (&p.app, p.bundle_path()) {
            (Some(app), Some(path)) => {
                let name = if app.name.is_empty() { p.name() } else { app.name.clone() };
                (format!("app:{}", key_safe(path)), GroupKind::App, name)
            }
            _ if by_name.get(&p.name()).copied().unwrap_or(0) > 1 => {
                (format!("exe:{}", key_safe(&p.name())), GroupKind::Exe, p.name())
            }
            _ => (format!("pid:{}", p.pid), GroupKind::Single, p.name()),
        };
        members
            .entry(id.clone())
            .or_insert_with(|| {
                order.push(id.clone());
                (kind, name, Vec::new())
            })
            .2
            .push(p);
    }
    let mut groups: Vec<Group> = order
        .into_iter()
        .map(|id| {
            let (kind, name, mut ps) = members.remove(&id).unwrap_or((GroupKind::Single, String::new(), Vec::new()));
            ps.sort_by(|a, b| sort.processes(a, b));
            let lead = ps
                .iter()
                .filter(|p| p.role != Role::AppHelper)
                .min_by_key(|p| p.pid)
                .or_else(|| ps.iter().min_by_key(|p| p.pid))
                .copied();
            let lead_p = lead.cloned().unwrap_or_default();
            Group {
                id,
                name,
                kind,
                pids: ps.iter().map(|p| p.pid).collect(),
                lead: lead_p.pid,
                cpu: ps.iter().map(|p| p.cpu_pct).sum(),
                rss_kib: ps.iter().map(|p| p.rss_kib).sum(),
                threads: ps.iter().map(|p| p.thread_count).sum(),
                role: lead_p.role,
                runtime: lead_p.runtime,
                signing: ps.iter().map(|p| p.sign_status()).min().unwrap_or_default(),
            }
        })
        .collect();
    groups.sort_by(|a, b| sort.groups(a, b));
    groups
}

/// What a list row stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowRef {
    /// An index into the groups.
    Group(usize),
    Process(u32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// The table's row id: `g:` and the group's id, or `p:` and the pid.
    pub id: String,
    pub depth: u8,
    pub item: RowRef,
}

/// The rows on screen: each group, followed by its members when it's open. A group of one is
/// its process.
pub fn flatten(groups: &[Group], open: &HashSet<String>) -> Vec<Row> {
    let mut rows = Vec::with_capacity(groups.len());
    for (i, g) in groups.iter().enumerate() {
        if g.kind == GroupKind::Single || g.pids.len() == 1 {
            rows.push(Row { id: format!("p:{}", g.pids[0]), depth: 0, item: RowRef::Process(g.pids[0]) });
            continue;
        }
        rows.push(Row { id: format!("g:{}", g.id), depth: 0, item: RowRef::Group(i) });
        if open.contains(&g.id) {
            rows.extend(g.pids.iter().map(|&pid| Row { id: format!("p:{pid}"), depth: 1, item: RowRef::Process(pid) }));
        }
    }
    rows
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::procs::{AppInfo, Signing};

    pub fn proc(pid: u32, name: &str, cpu: f64, rss_kib: f64) -> Process {
        Process {
            pid,
            ppid: 1,
            command: name.into(),
            cpu_pct: cpu,
            rss_kib,
            thread_count: 2,
            role: Role::Cli,
            ..Process::default()
        }
    }

    pub fn app(mut p: Process, name: &str, path: &str, role: Role) -> Process {
        p.app = Some(AppInfo { name: name.into(), bundle_path: path.into(), bundle_id: format!("com.example.{name}") });
        p.role = role;
        p
    }

    fn sample() -> Vec<Process> {
        let mut v = vec![
            app(proc(10, "Slack", 2.0, 200_000.0), "Slack", "/Applications/Slack.app", Role::App),
            app(proc(11, "Slack Helper", 5.0, 300_000.0), "Slack", "/Applications/Slack.app", Role::AppHelper),
            app(proc(12, "Slack Helper (GPU)", 1.0, 100_000.0), "Slack", "/Applications/Slack.app", Role::AppHelper),
            proc(20, "zsh", 0.0, 3_000.0),
            proc(21, "zsh", 0.0, 3_000.0),
            proc(22, "zsh", 0.5, 3_000.0),
            proc(30, "gh", 0.0, 40_000.0),
        ];
        v[1].signing = Some(Signing { status: SignStatus::Adhoc, ..Signing::default() });
        v[0].signing = Some(Signing { status: SignStatus::DeveloperId, ..Signing::default() });
        v
    }

    fn refs(v: &[Process]) -> Vec<&Process> {
        v.iter().collect()
    }

    #[test]
    fn an_app_and_its_helpers_are_one_group() {
        let v = sample();
        let g = group(&refs(&v), Sort::default());
        let slack = g.iter().find(|g| g.kind == GroupKind::App).unwrap();
        assert_eq!(slack.name, "Slack");
        assert_eq!(slack.pids, [11, 10, 12], "members by CPU, busiest first");
        assert_eq!(slack.lead, 10, "the app itself, not a helper");
        assert_eq!(slack.cpu, 8.0);
        assert_eq!(slack.rss_kib, 600_000.0);
        assert_eq!(slack.signing, SignStatus::Adhoc, "the worst member's signature");
        assert!(!slack.id.contains('/'));
    }

    #[test]
    fn same_named_processes_group_and_a_lone_one_stays_single() {
        let v = sample();
        let g = group(&refs(&v), Sort::default());
        let zsh = g.iter().find(|g| g.name == "zsh").unwrap();
        assert_eq!((zsh.kind, zsh.pids.len()), (GroupKind::Exe, 3));
        let gh = g.iter().find(|g| g.name == "gh").unwrap();
        assert_eq!(gh.kind, GroupKind::Single);
    }

    #[test]
    fn sorts_by_cpu_memory_and_name() {
        let v = sample();
        let names = |s: Sort| group(&refs(&v), s).into_iter().map(|g| g.name).collect::<Vec<_>>();
        assert_eq!(names(Sort::default()), ["Slack", "zsh", "gh"]);
        assert_eq!(names(Sort { key: SortKey::Memory, descending: true }), ["Slack", "gh", "zsh"]);
        assert_eq!(names(Sort { key: SortKey::Name, descending: false }), ["gh", "Slack", "zsh"]);
        assert_eq!(names(Sort { key: SortKey::Name, descending: true }), ["zsh", "Slack", "gh"]);
    }

    #[test]
    fn ties_keep_their_order_from_reading_to_reading() {
        // Five idle processes with equal CPU, landing in a different order each time.
        let mut v: Vec<Process> = (0..5).map(|i| proc(100 + i, &format!("idle{i}"), 0.0, 1_000.0)).collect();
        let first: Vec<String> = group(&refs(&v), Sort::default()).into_iter().map(|g| g.id).collect();
        v.reverse();
        let second: Vec<String> = group(&refs(&v), Sort::default()).into_iter().map(|g| g.id).collect();
        assert_eq!(first, second);
        assert_eq!(first[0], "pid:100", "ties fall back to name");
        // Same name and value: the pid decides.
        let mut twins = vec![proc(9, "zsh", 0.0, 1.0), proc(3, "zsh", 0.0, 1.0)];
        let a = group(&refs(&twins), Sort::default())[0].pids.clone();
        twins.reverse();
        assert_eq!(group(&refs(&twins), Sort::default())[0].pids, a);
        assert_eq!(a, [3, 9]);
    }

    #[test]
    fn opening_a_group_lists_its_members_under_it() {
        let v = sample();
        let g = group(&refs(&v), Sort::default());
        let closed = flatten(&g, &HashSet::new());
        assert_eq!(closed.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["g:app::Applications:Slack.app", "g:exe:zsh", "p:30"]);
        let open: HashSet<String> = ["app::Applications:Slack.app".to_owned()].into();
        let rows = flatten(&g, &open);
        assert_eq!(rows.len(), 6);
        assert_eq!((rows[1].id.as_str(), rows[1].depth), ("p:11", 1));
        assert_eq!(rows[4].item, RowRef::Group(1));
    }

    #[test]
    fn filters_by_category_runtime_and_search() {
        let mut v = sample();
        v[3].role = Role::Shell;
        v[6].runtime = Runtime::Go;
        assert!(Nav::Category(Category::Apps).holds(&v[1]));
        assert!(!Nav::Category(Category::Apps).holds(&v[3]));
        assert!(Nav::Category(Category::Terminals).holds(&v[3]));
        assert!(Nav::Runtime(Runtime::Go).holds(&v[6]));
        assert!(!Nav::Overview.holds(&v[6]));
        assert!(Nav::Unidentified.holds(&v[1]));
        assert!(!Nav::Unidentified.holds(&v[0]));
        v[6].executable_path = "/opt/homebrew/bin/gh".into();
        assert!(matches_query(&v[6], "homebrew"));
        assert!(matches_query(&v[6], "30"), "by pid");
        assert!(!matches_query(&v[6], "3"), "a pid matches whole");
        assert!(matches_query(&v[1], "com.example.slack"), "by bundle id");
        assert!(matches_query(&v[1], "slack helper"));
        assert!(matches_query(&v[1], ""));
        assert!(!matches_query(&v[3], "slack"));
    }
}
