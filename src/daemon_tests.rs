//! The daemon transport against a fake daemon on a socket in a temporary folder.

use super::*;
use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicUsize;

type Handler = Arc<dyn Fn(&str, &Value) -> Option<Result<Value, (i64, String)>> + Send + Sync>;

/// A fake daemon: answers `daemon.status` with `methods`, everything else with `handler`
/// (`None` never answers), records each request, and can push notifications.
struct Fake {
    path: PathBuf,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    conns: Arc<Mutex<Vec<UnixStream>>>,
}

/// A handler, typed so its closure takes any borrow.
fn h(
    f: impl Fn(&str, &Value) -> Option<Result<Value, (i64, String)>> + Send + Sync + 'static,
) -> Handler {
    Arc::new(f)
}

static DIRS: AtomicUsize = AtomicUsize::new(0);

fn socket() -> PathBuf {
    let n = DIRS.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sdd-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("d.sock")
}

impl Fake {
    fn serve(methods: &[&str], handler: Handler) -> Fake {
        Fake::serve_at(socket(), methods, handler)
    }

    fn serve_at(path: PathBuf, methods: &[&str], handler: Handler) -> Fake {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let methods: Vec<String> = methods.iter().map(|m| (*m).to_owned()).collect();
        let (calls, conns) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let (c, k) = (Arc::clone(&calls), Arc::clone(&conns));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                lock(&k).push(stream.try_clone().unwrap());
                let (c, handler, methods) = (Arc::clone(&c), Arc::clone(&handler), methods.clone());
                std::thread::spawn(move || {
                    let mut out = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let v: Value = serde_json::from_str(&line).unwrap();
                        let (id, method) = (
                            v["id"].clone(),
                            v["method"].as_str().unwrap_or_default().to_owned(),
                        );
                        lock(&c).push((method.clone(), v["params"].clone()));
                        let reply = if method == "daemon.status" {
                            Some(Ok(json!({"methods": methods})))
                        } else {
                            handler(&method, &v["params"])
                        };
                        let msg = match reply {
                            None => continue,
                            Some(Ok(r)) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
                            Some(Err((code, m))) => {
                                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}})
                            }
                        };
                        if writeln!(out, "{msg}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Fake { path, calls, conns }
    }

    fn calls(&self, method: &str) -> Vec<Value> {
        lock(&self.calls)
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, p)| p.clone())
            .collect()
    }

    /// Pushes a notification on every open connection.
    fn push(&self, method: &str, params: Value) {
        for c in lock(&self.conns).iter_mut() {
            let _ = writeln!(
                c,
                "{}",
                json!({"jsonrpc": "2.0", "method": method, "params": params})
            );
        }
    }

    /// The daemon going away: its connections close and its socket goes.
    fn stop(&self) {
        for c in lock(&self.conns).drain(..) {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }

    fn daemon(&self) -> Daemon {
        Daemon::new(self.path.clone(), Box::new(|| {}))
    }
}

fn never() -> AtomicBool {
    AtomicBool::new(false)
}

const SEC: Duration = Duration::from_secs(2);

fn current(load1: f64) -> Value {
    json!({"sample": {"load1": load1, "ncpu": 16, "memory_pressure": "normal"}, "active_alerts": []})
}

fn set(methods: &[&str]) -> HashSet<String> {
    methods.iter().map(|m| (*m).to_owned()).collect()
}

fn routed(args: &[&str], methods: &[&str]) -> &'static str {
    match route(args, &set(methods)) {
        Route::Table(e) => e.method,
        Route::Exec => EXEC,
        Route::Cli => "cli",
    }
}

#[test]
fn the_table_routes_a_call_to_the_daemon_only_while_it_lists_the_method() {
    let all = ["watch.current", "process.list", "jvm.list"];
    assert_eq!(
        routed(&["load", "--json", "--top", "1"], &all),
        "watch.current"
    );
    assert_eq!(
        routed(&["process", "-json", "--classify"], &all),
        "process.list"
    );
    assert_eq!(routed(&["jvm", "-json"], &all), "jvm.list");
    // An older daemon without the method: the CLI runs.
    assert_eq!(
        routed(&["process", "-json", "--classify"], &["watch.current"]),
        "cli"
    );
    assert_eq!(routed(&["load", "--json"], &[]), "cli");
    // A call the table doesn't name.
    assert_eq!(routed(&["memory", "--json"], &all), "cli");
    // An unclassified process list isn't what the feed asks for.
    assert_eq!(routed(&["process", "-json"], &all), "cli");
}

#[test]
fn a_generic_exec_takes_every_call_the_table_does_not_name() {
    let m = ["exec", "watch.current"];
    assert_eq!(routed(&["memory", "--json"], &m), EXEC);
    assert_eq!(routed(&["sample", "-json", "7"], &m), EXEC);
    assert_eq!(
        routed(&["load", "--json"], &m),
        "watch.current",
        "the table still wins"
    );
    // The daemon's own management never goes through the daemon.
    assert_eq!(routed(&["daemon", "start"], &m), "cli");
    assert_eq!(routed(&["capabilities", "--json"], &m), "cli");
}

#[test]
fn names_the_capability_interface_a_call_invokes() {
    let caps = parse_interfaces(
        r#"{"interfaces":[{"name":"owner","argv":["owner","--json","[--timeout <duration>]","<target>"]},
        {"name":"owner.under","argv":["owner","--under","--json","<dir>..."]},
        {"name":"load","argv":["load","--json","[--top <n>]"]},
        {"name":"jvm.gc","argv":["jvm","gc-stats","--json","<pid>"]},
        {"name":"inspect","argv":["--json","<app_path>..."]}]}"#,
    );
    assert_eq!(
        interface_name(&["owner", "--json", "7"], &caps),
        Some("owner")
    );
    assert_eq!(
        interface_name(&["owner", "--under", "--json", "/a"], &caps),
        Some("owner.under")
    );
    assert_eq!(
        interface_name(&["load", "--json", "--top", "1"], &caps),
        Some("load")
    );
    assert_eq!(
        interface_name(&["jvm", "gc-stats", "--json", "7"], &caps),
        Some("jvm.gc")
    );
    assert_eq!(interface_name(&["vmmap", "7"], &caps), None);
}

#[test]
fn load_comes_from_the_host_sample_in_the_shape_the_cli_prints() {
    let f = Fake::serve(
        &["watch.current"],
        h(|m, _| (m == "watch.current").then(|| Ok(current(3.5)))),
    );
    let d = f.daemon();
    let out = d
        .answer(&["load", "--json", "--top", "1"], SEC, &never())
        .unwrap()
        .unwrap();
    let load = crate::system::parse_load(&out).unwrap();
    assert_eq!((load.load1, load.cpus), (3.5, 16));
}

#[test]
fn a_method_the_daemon_lacks_or_refuses_runs_the_cli() {
    let f = Fake::serve(&["daemon.status"], h(|_, _| Some(Ok(Value::Null))));
    assert!(
        f.daemon()
            .answer(&["load", "--json"], SEC, &never())
            .is_none()
    );
    let f = Fake::serve(
        &["watch.current"],
        h(|_, _| Some(Err((-32601, "method not found".into())))),
    );
    assert!(
        f.daemon()
            .answer(&["load", "--json"], SEC, &never())
            .is_none()
    );
}

#[test]
fn no_daemon_runs_the_cli_and_starts_the_daemon_once() {
    let started = Arc::new(AtomicUsize::new(0));
    let s = Arc::clone(&started);
    let d = Daemon::new(
        socket(),
        Box::new(move || {
            s.fetch_add(1, Ordering::SeqCst);
        }),
    );
    // START_WAIT passes with no socket; the next call doesn't try again for a while.
    assert!(d.answer(&["load", "--json"], SEC, &never()).is_none());
    let at = Instant::now();
    assert!(d.answer(&["load", "--json"], SEC, &never()).is_none());
    assert!(
        at.elapsed() < Duration::from_millis(500),
        "a down daemon isn't dialled on every call"
    );
    assert_eq!(started.load(Ordering::SeqCst), 1);
}

#[test]
fn reconnects_after_the_daemon_restarts() {
    let handler = h(|m, _| (m == "watch.current").then(|| Ok(current(1.0))));
    let f = Fake::serve(&["watch.current"], Arc::clone(&handler));
    let d = f.daemon();
    assert!(
        d.answer(&["load", "--json"], SEC, &never())
            .unwrap()
            .is_ok()
    );
    f.stop();
    std::thread::sleep(Duration::from_millis(100));
    let g = Fake::serve_at(f.path.clone(), &["watch.current"], handler);
    let out = d
        .answer(&["load", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    assert!(out.contains("\"load1\":1.0"), "{out}");
    assert_eq!(
        g.calls("daemon.status").len(),
        1,
        "it said hello to the new daemon"
    );
}

#[test]
fn a_daemon_that_does_not_answer_runs_out_of_time() {
    let f = Fake::serve(&["watch.current"], h(|_, _| None));
    let d = f.daemon();
    let at = Instant::now();
    let r = d.answer(&["load", "--json"], Duration::from_millis(300), &never());
    assert_eq!(r, Some(Err(Error::Timeout)));
    assert!(at.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_cancelled_call_stops_waiting() {
    let f = Fake::serve(&["watch.current"], h(|_, _| None));
    let d = f.daemon();
    let cancel = AtomicBool::new(true);
    assert_eq!(
        d.answer(&["load", "--json"], Duration::from_secs(10), &cancel),
        Some(Err(Error::Cancelled))
    );
}

#[test]
fn a_pushed_host_sample_answers_without_asking() {
    let f = Fake::serve(
        &["watch.current", "alerts.subscribe"],
        h(|m, _| match m {
            "alerts.subscribe" => Some(Ok(json!({"subscribed": true}))),
            _ => Some(Ok(current(9.0))),
        }),
    );
    let d = f.daemon();
    d.methods();
    assert_eq!(f.calls("alerts.subscribe"), vec![json!({"samples": true})]);
    f.push("watch.sample", json!({"load1": 7.25, "ncpu": 8}));
    let since = Instant::now();
    while d.pushed_sample().is_none() && since.elapsed() < SEC {
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = d
        .answer(&["load", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    assert!(out.contains("7.25"), "{out}");
    assert!(f.calls("watch.current").is_empty(), "the push answered it");
}

fn rows(at: &str, pid: u32) -> Value {
    json!({"sampled_at": at, "processes": [{"pid": pid, "command": "x", "role": "app", "runtime": "native"}]})
}

#[test]
fn the_process_feed_comes_from_the_shared_snapshot() {
    let f = Fake::serve(
        &["process.list"],
        h(|_, _| Some(Ok(rows("2026-11-22T00:00:00Z", 42)))),
    );
    let out = f
        .daemon()
        .answer(&["process", "-json", "--classify"], SEC, &never())
        .unwrap()
        .unwrap();
    let procs = crate::procs::parse(&out).unwrap();
    assert_eq!(procs[0].pid, 42);
}

#[test]
fn the_process_feed_asks_for_classified_rows() {
    let f = Fake::serve(
        &["process.list", "process.subscribe"],
        h(|m, _| match m {
            "process.subscribe" => Some(Ok(json!({"subscribed": true}))),
            _ => Some(Ok(rows("t", 1))),
        }),
    );
    f.daemon()
        .answer(&["process", "-json", "--classify"], SEC, &never())
        .unwrap()
        .unwrap();
    assert_eq!(
        f.calls("process.subscribe"),
        vec![json!({"classify": true})]
    );
    assert_eq!(f.calls("process.list"), vec![json!({"classify": true})]);
}

#[test]
fn a_daemon_that_does_not_classify_leaves_the_feed_to_the_cli() {
    // It ignores the flag: rows without roles.
    let f = Fake::serve(
        &["process.list"],
        h(|_, _| {
            Some(Ok(
                json!({"sampled_at": "t", "processes": [{"pid": 1, "command": "x"}]}),
            ))
        }),
    );
    let d = f.daemon();
    let args = ["process", "-json", "--classify"];
    assert!(d.answer(&args, SEC, &never()).is_none());
    assert!(d.answer(&args, SEC, &never()).is_none());
    assert_eq!(
        f.calls("process.list").len(),
        1,
        "not asked again on every reading"
    );
    // It refuses the flag as invalid params, and so its subscription doesn't count either.
    let f = Fake::serve(
        &["process.list", "process.subscribe"],
        h(|_, p| (p.get("classify").is_some()).then(|| Err((-32602, "invalid params".into())))),
    );
    let d = f.daemon();
    assert!(d.answer(&args, SEC, &never()).is_none());
    assert!(!d.has("process.subscribe"));
    assert!(!d.has("process.list"));
}

#[test]
fn a_classification_that_failed_is_a_failed_reading_not_a_reason_to_stop() {
    let f = Fake::serve(
        &["process.list"],
        h(|_, _| {
            Some(Ok(
                json!({"sampled_at": "t", "warning": "classify: timed out",
                "processes": [{"pid": 1, "command": "x"}]}),
            ))
        }),
    );
    let d = f.daemon();
    let args = ["process", "-json", "--classify"];
    assert_eq!(
        d.answer(&args, SEC, &never()),
        Some(Err(Error::Warned("classify: timed out".into())))
    );
    assert!(d.has("process.list"), "it's asked again next time");
}

#[test]
fn unclassified_pushes_are_not_landed() {
    let f = Fake::serve(
        &["process.list", "process.subscribe"],
        h(|m, _| match m {
            "process.subscribe" => Some(Ok(json!({"subscribed": true}))),
            _ => Some(Ok(rows("2026-11-22T00:00:00Z", 1))),
        }),
    );
    let d = f.daemon();
    let args = ["process", "-json", "--classify"];
    d.answer(&args, SEC, &never()).unwrap().unwrap();
    f.push(
        "process.update",
        json!({"sampled_at": "2026-11-22T00:00:15Z", "processes": [{"pid": 3, "command": "x"}]}),
    );
    // Nothing classified came, so after waiting it asks again.
    let out = d
        .answer(&args, Duration::from_millis(400), &never())
        .unwrap()
        .unwrap();
    assert!(!out.contains("\"pid\":3"), "{out}");
    assert_eq!(f.calls("process.list").len(), 2);
}

#[test]
fn subscribed_process_lists_are_pushed_and_never_landed_twice() {
    let f = Fake::serve(
        &["process.list", "process.subscribe"],
        h(|m, _| match m {
            "process.subscribe" => Some(Ok(json!({"subscribed": true}))),
            _ => Some(Ok(rows("2026-11-22T00:00:00Z", 1))),
        }),
    );
    let d = f.daemon();
    let args = ["process", "-json", "--classify"];
    // The first comes at once, asked for.
    let first = d.answer(&args, SEC, &never()).unwrap().unwrap();
    assert!(first.contains("\"pid\":1"));
    assert_eq!(f.calls("process.list").len(), 1);
    // The next waits for a newer push rather than handing the same list out again.
    let pusher = {
        let conns = Arc::clone(&f.conns);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            for c in lock(&conns).iter_mut() {
                let msg = json!({"jsonrpc": "2.0", "method": "process.update", "params": rows("2026-11-22T00:00:15Z", 2)});
                let _ = writeln!(c, "{msg}");
            }
        })
    };
    let at = Instant::now();
    let second = d.answer(&args, SEC, &never()).unwrap().unwrap();
    pusher.join().unwrap();
    assert!(second.contains("\"pid\":2"), "{second}");
    assert!(
        at.elapsed() >= Duration::from_millis(150),
        "it waited for the push"
    );
    assert_eq!(f.calls("process.list").len(), 1, "the push answered it");
}

#[test]
fn the_jvm_list_is_read_in_either_shape() {
    let f = Fake::serve(
        &["jvm.list"],
        h(|_, _| Some(Ok(json!([{"pid": 5, "main_class": "a.B"}])))),
    );
    let out = f
        .daemon()
        .answer(&["jvm", "-json"], SEC, &never())
        .unwrap()
        .unwrap();
    assert_eq!(crate::data::parse(&out).unwrap()[0].pid, 5);
    let f = Fake::serve(
        &["jvm.list"],
        h(|_, _| Some(Ok(json!({"jvms": [{"pid": 6}]})))),
    );
    let out = f
        .daemon()
        .answer(&["jvm", "-json"], SEC, &never())
        .unwrap()
        .unwrap();
    assert_eq!(crate::data::parse(&out).unwrap()[0].pid, 6);
    let f = Fake::serve(&["jvm.list"], h(|_, _| Some(Ok(Value::Null))));
    assert_eq!(
        f.daemon().answer(&["jvm", "-json"], SEC, &never()),
        Some(Ok("[]".into()))
    );
}

fn exec_daemon(f: &Fake) -> Daemon {
    let d = f.daemon();
    let _ = d.interfaces.set(vec![(
        "owner".into(),
        vec!["owner".into(), "--json".into(), "<target>".into()],
    )]);
    d
}

#[test]
fn exec_runs_a_cli_interface_in_the_daemon() {
    let f = Fake::serve(
        &["exec"],
        h(|_, _| Some(Ok(json!({"stdout": "{\"pid\":7}"})))),
    );
    let d = exec_daemon(&f);
    let out = d
        .answer(&["owner", "--json", "7"], SEC, &never())
        .unwrap()
        .unwrap();
    assert_eq!(out, "{\"pid\":7}");
    let sent = &f.calls("exec")[0];
    assert_eq!(sent["interface"], "owner");
    assert_eq!(sent["args"], json!(["owner", "--json", "7"]));
    assert_eq!(sent["timeout_ms"], 2000);
    // An interface the capabilities don't name runs the CLI.
    assert!(d.answer(&["vmmap", "7"], SEC, &never()).is_none());
}

#[test]
fn a_cancelled_exec_is_cancelled_in_the_daemon_too() {
    let f = Fake::serve(
        &["exec", "exec.cancel"],
        h(|m, _| (m == "exec.cancel").then_some(Ok(Value::Null))),
    );
    let d = exec_daemon(&f);
    let cancel = Arc::new(AtomicBool::new(false));
    let c = Arc::clone(&cancel);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        c.store(true, Ordering::SeqCst);
    });
    assert_eq!(
        d.answer(&["owner", "--json", "7"], Duration::from_secs(10), &cancel),
        Some(Err(Error::Cancelled))
    );
    let since = Instant::now();
    while f.calls("exec.cancel").is_empty() && since.elapsed() < SEC {
        std::thread::sleep(Duration::from_millis(10));
    }
    let exec_id = lock(&f.calls)
        .iter()
        .position(|(m, _)| m == "exec")
        .map(|i| i as u64 + 1);
    assert_eq!(f.calls("exec.cancel").len(), 1);
    // Ids count from 1 on this connection, in the order the fake recorded them.
    assert_eq!(f.calls("exec.cancel")[0]["id"].as_u64(), exec_id);
}

#[test]
fn only_plain_spectra_calls_are_routed() {
    let f = Fake::serve(&["watch.current"], h(|_, _| Some(Ok(current(2.0)))));
    let d = f.daemon();
    let mut cmd = Command::new(bin());
    cmd.args(["load", "--json"]);
    assert!(answer_with(&d, &cmd, SEC, &never()).is_some());
    let mut other = Command::new("/bin/echo");
    other.args(["load", "--json"]);
    assert!(answer_with(&d, &other, SEC, &never()).is_none());
    let mut with_env = Command::new(bin());
    with_env.args(["load", "--json"]).env("HOME", "/var/empty");
    assert!(answer_with(&d, &with_env, SEC, &never()).is_none());
}

/// A fake daemon that lists `method` and answers it with `reading`.
fn reading_daemon(method: &'static str, reading: Value) -> Fake {
    Fake::serve(
        &[method],
        h(move |m, _| (m == method).then(|| Ok(reading.clone()))),
    )
}

#[test]
fn the_machine_readings_route_to_the_daemon_only_while_it_lists_them() {
    let all = [
        "memory.current",
        "thermal.current",
        "power.current",
        "network.current",
    ];
    for (args, method) in [
        (["memory", "--json"], "memory.current"),
        (["thermal", "--json"], "thermal.current"),
        (["power", "--json"], "power.current"),
        (["network", "--json"], "network.current"),
    ] {
        assert_eq!(routed(&args, &all), method);
        assert_eq!(routed(&args, &[method]), method);
        assert_eq!(routed(&args, &[]), "cli", "{method} unlisted runs the CLI");
        assert_eq!(routed(&args, &["exec"]), EXEC);
    }
    // The Network page's windows are another call.
    assert_eq!(
        routed(&["network", "top", "--json", "--duration", "3s"], &all),
        "cli"
    );
}

#[test]
fn memory_comes_from_the_daemon_in_the_shape_the_cli_prints() {
    let f = reading_daemon(
        "memory.current",
        json!({"physical_bytes": 17179869184u64, "pressure_level": "warn", "swap": {"used_bytes": 1024}}),
    );
    let out = f
        .daemon()
        .answer(&["memory", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    let m = crate::system::parse_memory(&out).unwrap();
    assert_eq!((m.physical, m.swap_used), (17179869184.0, 1024.0));
    assert_eq!(f.calls("memory.current"), vec![json!({})]);
}

#[test]
fn thermal_comes_from_the_daemon_in_the_shape_the_cli_prints() {
    let f = reading_daemon(
        "thermal.current",
        json!({"verdict": "throttled", "evidence": "speed limit 70%", "limits": {"cpu_speed_limit": 70}}),
    );
    let out = f
        .daemon()
        .answer(&["thermal", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    let t = crate::system::parse_thermal(&out).unwrap();
    assert_eq!(t.state, crate::system::ThermalState::Throttled);
    assert_eq!(t.speed_limit, Some(70.0));
}

#[test]
fn power_comes_from_the_daemon_in_the_shape_the_cli_prints() {
    let f = reading_daemon(
        "power.current",
        json!({"battery": {"pct": 42, "on_battery": true}, "thermal": {"pressure": "nominal"}}),
    );
    let out = f
        .daemon()
        .answer(&["power", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    let p = crate::system::parse_power(&out).unwrap();
    assert_eq!(
        p.battery.map(|b| (b.pct, b.on_battery)),
        Some((Some(42.0), true))
    );
    assert_eq!(p.thermal_pressure.as_deref(), Some("nominal"));
}

#[test]
fn network_comes_from_the_daemon_in_the_shape_the_cli_prints() {
    let f = reading_daemon(
        "network.current",
        json!({"listening_ports": [{"port": 8080, "proto": "tcp", "pid": 9, "local_addr": "127.0.0.1"}]}),
    );
    let out = f
        .daemon()
        .answer(&["network", "--json"], SEC, &never())
        .unwrap()
        .unwrap();
    let n = crate::system::parse_network(&out).unwrap();
    assert_eq!(
        n.ports.iter().map(|p| p.port).collect::<Vec<_>>(),
        vec![8080]
    );
}

#[test]
fn a_machine_reading_the_daemon_does_not_list_or_garbles_runs_the_cli() {
    // Listed but not this one: the CLI, and the daemon is never asked for it.
    let f = reading_daemon("memory.current", json!({"physical_bytes": 1}));
    let d = f.daemon();
    for args in [
        ["thermal", "--json"],
        ["power", "--json"],
        ["network", "--json"],
    ] {
        assert!(d.answer(&args, SEC, &never()).is_none(), "{args:?}");
    }
    assert!(f.calls("thermal.current").is_empty());
    // Listed, but its answer isn't a reading: the CLI, and the method isn't asked again.
    let f = reading_daemon("power.current", Value::Null);
    let d = f.daemon();
    assert!(d.answer(&["power", "--json"], SEC, &never()).is_none());
    assert!(d.answer(&["power", "--json"], SEC, &never()).is_none());
    assert_eq!(f.calls("power.current").len(), 1);
}
