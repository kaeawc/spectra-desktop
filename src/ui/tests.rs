//! Headless runs of the real view: press what a person would press, then look for keyed elements.

use rune::{Env, Runtime, TextEdit};

use crate::app::{App, init};
use crate::data::{Gc, Jvm};
use crate::groups::{Category, Nav};
use crate::procs::Role;
use crate::sample::{detail_scene, old_scene, sample_scene};

const SLACK: &str = "g:app::Applications:Slack.app";

fn runtime(state: App) -> Runtime<App> {
    let env = Env {
        system_dark: true,
        scale: 2.0,
    };
    let mut rt = Runtime::new(state, super::view, (980.0, 640.0), env);
    rt.frame(0.0);
    rt
}

fn scene(f: fn(&mut App)) -> Runtime<App> {
    let mut s = init();
    f(&mut s);
    runtime(s)
}

fn sample() -> Runtime<App> {
    scene(sample_scene)
}

fn settle(rt: &mut Runtime<App>) {
    for _ in 0..30 {
        rt.frame(1.0 / 60.0);
    }
}

/// Scrolls `key` into view, then presses it.
fn press(rt: &mut Runtime<App>, key: &str) {
    let k = key.to_owned();
    rt.update(move |_, tx| tx.scroll_into_view(k));
    settle(rt);
    let (x, y) = rt
        .find(key)
        .unwrap_or_else(|| panic!("nothing keyed {key} on screen"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(rt);
}

fn text_of(rt: &Runtime<App>, key: &str) -> Option<String> {
    rt.elements()
        .into_iter()
        .find(|e| e.key.as_deref() == Some(key))
        .and_then(|e| e.text)
}

#[test]
fn the_overview_leads_with_a_summary_and_findings() {
    let rt = sample();
    for key in ["summary-procs", "summary-cpu", "summary-memory", "findings-title"] {
        assert!(rt.find(key).is_some(), "the overview shows {key}");
    }
    assert_eq!(text_of(&rt, "summary-procs-value").as_deref(), Some("49"));
    assert!(rt.find("subject-941-proc-invalid-signature").is_some());
    assert!(rt.find("too-old").is_none());
}

#[test]
fn a_sidebar_category_filters_the_list() {
    let mut rt = sample();
    press(&mut rt, "cat-apps");
    assert_eq!(rt.state.nav, Nav::Category(Category::Apps));
    assert!(rt.find("procs").is_some(), "the list shows");
    assert!(rt.find(SLACK).is_some(), "Slack is an app");
    assert!(rt.find("p:1340").is_none(), "python3 is not");
    let s = &rt.state;
    let pids: Vec<u32> = s.groups.iter().flat_map(|g| g.pids.iter().copied()).collect();
    assert!(!pids.is_empty());
    assert!(
        pids.iter()
            .all(|pid| matches!(s.process(*pid).unwrap().role, Role::App | Role::AppHelper))
    );

    press(&mut rt, "rt-jvm");
    assert_eq!(rt.state.nav, Nav::Runtime(crate::procs::Runtime::Jvm));
    assert_eq!(rt.state.groups.len(), 1, "the three JVMs, as one java group");
    assert_eq!(rt.state.groups[0].pids.len(), 3);
}

#[test]
fn a_group_opens_onto_its_processes() {
    let mut rt = sample();
    press(&mut rt, "all");
    assert!(rt.find("p:901").is_none(), "closed");
    press(&mut rt, SLACK);
    assert!(rt.state.open_groups.contains("app::Applications:Slack.app"));
    assert!(rt.find("p:901").is_some(), "its helper is listed under it");
    assert_eq!(rt.state.selected, None, "opening a group opens no page");
    press(&mut rt, SLACK);
    assert!(rt.find("p:901").is_none());
}

#[test]
fn clicking_a_row_opens_its_page_and_back_returns() {
    let mut rt = sample();
    press(&mut rt, "all");
    press(&mut rt, "p:1300");
    assert_eq!(rt.state.selected, Some(1300));
    for key in [
        "pd-header",
        "pd-facts",
        "pd-lane-cpu",
        "pd-lane-mem",
        "pd-cmd",
        "pd-evidence",
    ] {
        assert!(rt.find(key).is_some(), "the page shows {key}");
    }
    assert_eq!(text_of(&rt, "pd-name").as_deref(), Some("rust-analyzer"));
    assert_eq!(
        text_of(&rt, "pd-verdict").as_deref(),
        Some("Busy: 138.8% CPU for the last 8 readings")
    );
    press(&mut rt, "back");
    assert_eq!(rt.state.selected, None);
    assert_eq!(rt.state.nav, Nav::All, "back where it was");
}

#[test]
fn the_parent_link_opens_the_parent() {
    let mut rt = sample();
    press(&mut rt, "all");
    press(&mut rt, "p:1300");
    assert_eq!(
        text_of(&rt, "pd-parent").as_deref(),
        Some("Code Helper (Plugin) · 921")
    );
    press(&mut rt, "pd-parent");
    assert_eq!(rt.state.selected, Some(921));
    assert_eq!(text_of(&rt, "pd-name").as_deref(), Some("Code Helper (Plugin)"));
    assert!(
        rt.find("pd-child-1300").is_some(),
        "and lists what it started"
    );
    press(&mut rt, "pd-child-1310");
    assert_eq!(rt.state.selected, Some(1310));
}

#[test]
fn a_spectra_too_old_to_classify_says_so_and_jvms_still_work() {
    let mut rt = scene(old_scene);
    assert!(rt.find("too-old").is_some());
    assert_eq!(
        text_of(&rt, "too-old-title").as_deref(),
        Some("Spectra is too old to list every process")
    );
    assert!(rt.find("all").is_none(), "no process list to offer");
    assert!(rt.find("subject-4102-jvm-heap-pressure").is_some());
    press(&mut rt, "jvm-4101");
    assert_eq!(rt.state.selected, Some(4101));
    for key in [
        "jd-header",
        "jd-tile-heap",
        "jd-tile-gc-time",
        "jd-lane-heap",
        "jd-lane-old",
        "jd-lane-gc",
        "jd-lane-threads",
        "jd-args",
    ] {
        assert!(rt.find(key).is_some(), "the JVM page shows {key}");
    }
    assert_eq!(
        text_of(&rt, "jd-verdict").as_deref(),
        Some("Heap 83% full"),
        "the verdict is its worst finding"
    );
    assert!(
        rt.find("jd-tile-heap-since").is_some(),
        "a pinned baseline shows deltas"
    );
    assert!(rt.find("subject-4101-jvm-heap-pressure").is_some());
    assert!(rt.find("subject-4102-jvm-heap-pressure").is_none());
    press(&mut rt, "overview");
    assert_eq!(rt.state.selected, None);
    assert!(rt.find("jd-detail").is_none());
}

#[test]
fn a_jvms_process_page_holds_its_jvm_numbers() {
    let rt = scene(detail_scene);
    assert_eq!(text_of(&rt, "pd-name").as_deref(), Some("Server"), "named for what it runs");
    assert_eq!(text_of(&rt, "pd-verdict").as_deref(), Some("Heap 83% full"));
    for key in ["jd-detail", "jd-tile-heap", "jd-lane-heap", "jd-args", "pd-lane-cpu"] {
        assert!(rt.find(key).is_some(), "the page shows {key}");
    }
    assert!(rt.find("subject-4101-jvm-heap-pressure").is_some());
    assert!(rt.find("subject-4102-jvm-heap-pressure").is_none());
}

#[test]
fn a_cards_subject_opens_its_process_without_toggling_the_card() {
    let mut rt = sample();
    let expanded = rt.state.expanded.clone();
    assert!(expanded.is_some());
    press(&mut rt, "subject-4102-jvm-heap-pressure");
    assert_eq!(rt.state.selected, Some(4102));
    assert_eq!(rt.state.expanded, expanded, "the card stays as it was");
    assert!(rt.find("jd-detail").is_some());
}

#[test]
fn the_unsigned_finding_lists_those_processes() {
    let mut rt = sample();
    press(&mut rt, "subject-0-proc-unidentified");
    assert_eq!(rt.state.nav, Nav::Unidentified);
    let s = &rt.state;
    assert!(
        s.groups
            .iter()
            .flat_map(|g| &g.pids)
            .all(|pid| s.process(*pid).unwrap().sign_status().is_unidentified())
    );
    assert!(rt.find("p:1340").is_some(), "python3 is unsigned");
}

#[test]
fn a_search_narrows_the_list() {
    let mut rt = sample();
    press(&mut rt, "all");
    rt.update(|s, _| {
        s.query = TextEdit::new("slack");
        s.rebuild();
    });
    settle(&mut rt);
    assert_eq!(rt.state.groups.len(), 1);
    assert!(rt.find(SLACK).is_some());
    assert!(rt.find("p:1300").is_none());
    rt.update(|s, _| {
        s.query = TextEdit::new("4101");
        s.rebuild();
    });
    settle(&mut rt);
    assert!(rt.find("p:4101").is_some(), "a lone match shows as its process");
}

#[test]
fn the_arguments_open_one_flag_per_line() {
    let mut rt = scene(detail_scene);
    assert!(rt.find("jd-arg-0").is_none(), "collapsed by default");
    press(&mut rt, "jd-args/trigger");
    assert!(rt.state.args_open);
    let flags: Vec<Option<String>> = (0..4)
        .map(|i| text_of(&rt, &format!("jd-arg-{i}")))
        .collect();
    let want = [
        "-Xmx2g",
        "-Xms512m",
        "-XX:+UseG1GC",
        "-Dspring.profiles.active=prod",
    ];
    assert_eq!(flags, want.map(|s| Some(s.to_owned())));
    press(&mut rt, "jd-args/trigger");
    assert!(!rt.state.args_open);
    assert!(rt.find("jd-arg-0").is_none());
}

#[test]
fn one_reading_says_its_still_collecting() {
    let mut s = init();
    let jvm = Jvm {
        pid: 7,
        main_class: "a.App".into(),
        vm_args: "-Xmx1g".into(),
        gc: Some(Gc {
            ou: 1024.0,
            ..Gc::default()
        }),
        ..Jvm::default()
    };
    s.land(Ok(vec![jvm]));
    s.selected = Some(7);
    let rt = runtime(s);
    assert!(rt.find("jd-timeline-collecting").is_some());
    assert!(rt.find("jd-lane-heap").is_none());
}
