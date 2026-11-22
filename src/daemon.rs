//! Spectra's daemon: one long-lived connection to its socket, newline-delimited JSON-RPC 2.0,
//! so a reading the daemon already holds costs a message instead of a new `spectra` process.
//!
//! Every Spectra call still goes through [`crate::run::run_until`]; it asks [`answer`] first,
//! and [`route`] decides, in one table, whether the daemon answers that call or the CLI runs. A
//! call the table doesn't name goes to the daemon's generic [`EXEC`] method once the daemon lists
//! it, and to the CLI until then, with no change to the pages that make the call. Each entry
//! applies only while `daemon.status` lists its method, so a newer daemon's methods switch on
//! by themselves.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The generic method that runs any CLI interface inside the daemon, `{interface, args,
/// timeout_ms}`, the interface named as `spectra capabilities --json` names it. Every call
/// [`TABLE`] doesn't answer goes through it once the daemon lists it.
pub const EXEC: &str = "exec";
/// Asks the daemon to stop an [`EXEC`] call, by the call's request id.
pub const EXEC_CANCEL: &str = "exec.cancel";
const STATUS: &str = "daemon.status";
/// Pushes `watch.sample` (and `alerts.event`) notifications on the connection that asked.
const SUBSCRIBE: &str = "alerts.subscribe";
/// The process list from the daemon's shared snapshot: `{sampled_at, processes}`, the rows
/// `spectra process --json` prints; asked with `classify: true` for the `--classify` fields,
/// which a daemon without that leaves out (or refuses as invalid params).
const PROCESS_LIST: &str = "process.list";
/// Pushes `process.update` notifications shaped like [`PROCESS_LIST`]'s answer.
const PROCESS_SUBSCRIBE: &str = "process.subscribe";
/// How long a connection may take to say which methods it has.
const HELLO: Duration = Duration::from_secs(3);
/// After the daemon couldn't be reached, how long calls go to the CLI before it's tried again.
const RETRY: Duration = Duration::from_secs(30);
/// How long to wait for the socket to appear after `spectra daemon start`.
const START_WAIT: Duration = Duration::from_secs(5);
/// A pushed host sample younger than this answers a load reading without asking.
const FRESH: Duration = Duration::from_secs(20);
/// How long the first classified process list may take: a cold one is about 32 s in the
/// daemon (collecting 15 s, classifying 15 s, 2 s grace).
const FIRST_LIST: Duration = Duration::from_secs(40);
/// How often a waiting call looks at its cancel flag.
const CHECK: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// No daemon to talk to: the socket is missing or refused, or it was tried too recently.
    Unavailable(String),
    /// The daemon answered with a JSON-RPC error.
    Rpc {
        code: i64,
        message: String,
    },
    /// The connection dropped before the answer came.
    Disconnected,
    Timeout,
    Cancelled,
    /// The answer wasn't the shape the call expects.
    Shape(String),
    /// The daemon answered but couldn't do all of it, and said why (it couldn't classify the
    /// processes this time): a failed reading, not a reason to stop asking it.
    Warned(String),
}

impl Error {
    /// What went wrong, in words.
    pub fn why(&self) -> String {
        match self {
            Error::Unavailable(why) | Error::Shape(why) | Error::Warned(why) => why.clone(),
            Error::Rpc { code, message } => format!("{message} ({code})"),
            Error::Disconnected => "the connection dropped".into(),
            Error::Timeout => "it didn't answer in time".into(),
            Error::Cancelled => "stopped".into(),
        }
    }
}

type Reply = Result<Value, Error>;
type Pending = Arc<Mutex<HashMap<u64, Sender<Reply>>>>;

/// One open connection and the reader thread that answers its calls.
struct Conn {
    writer: UnixStream,
    pending: Pending,
    alive: Arc<AtomicBool>,
}

/// What the daemon pushed on the connection, kept for the calls it answers.
#[derive(Default)]
struct Pushed {
    /// The last host sample, and when it came.
    sample: Mutex<Option<(Instant, Value)>>,
    /// The last process list: when the daemon sampled it, and its rows as JSON.
    procs: Mutex<Option<(String, String)>>,
    procs_came: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A CLI call the daemon can answer, and how.
pub struct Entry {
    /// The CLI call's leading words.
    pub cli: &'static [&'static str],
    /// The daemon method that has to be listed for this entry to apply.
    pub method: &'static str,
    /// Answers the call with what the CLI would have printed.
    answer: fn(&Daemon, &[&str], Duration, &AtomicBool) -> Result<String, Error>,
}

/// The one table of which CLI calls the daemon answers instead of a new process.
pub static TABLE: &[Entry] = &[
    // The main process feed, from the daemon's shared snapshot, pushed once subscribed.
    Entry {
        cli: &["process", "-json", "--classify"],
        method: PROCESS_LIST,
        answer: processes,
    },
    // Every JVM, from the daemon's cached list (a reading runs a JDK tool per JVM).
    Entry {
        cli: &["jvm", "-json"],
        method: "jvm.list",
        answer: jvms,
    },
    // `spectra load` lists every process for a load average the host sample already holds.
    Entry {
        cli: &["load"],
        method: "watch.current",
        answer: load,
    },
];

/// Where a CLI call goes.
pub enum Route {
    Table(&'static Entry),
    /// Through the daemon's generic [`EXEC`].
    Exec,
    Cli,
}

/// Where `args` goes, given the methods the daemon lists. The daemon's own management calls
/// always run the CLI.
pub fn route(args: &[&str], methods: &HashSet<String>) -> Route {
    if matches!(args.first(), None | Some(&"daemon") | Some(&"capabilities")) {
        return Route::Cli;
    }
    if let Some(e) = TABLE
        .iter()
        .find(|e| args.starts_with(e.cli) && methods.contains(e.method))
    {
        return Route::Table(e);
    }
    if methods.contains(EXEC) {
        Route::Exec
    } else {
        Route::Cli
    }
}

/// The capability interface `args` invokes: the one whose literal words (not `[optional]`,
/// `<placeholder>` or `--json`) all appear in `args`, its first word first, the most specific
/// winning. `owner --under --json d` is `owner.under`; `owner --json 7` is `owner`.
pub fn interface_name<'a>(
    args: &[&str],
    interfaces: &'a [(String, Vec<String>)],
) -> Option<&'a str> {
    interfaces
        .iter()
        .filter_map(|(name, argv)| {
            let words: Vec<&str> = argv
                .iter()
                .map(String::as_str)
                .filter(|w| {
                    !w.starts_with('[') && !w.starts_with('<') && *w != "--json" && *w != "-json"
                })
                .collect();
            let first = words.first()?;
            (args.first() == Some(first) && words.iter().all(|w| args.contains(w)))
                .then_some((name.as_str(), words.len()))
        })
        .max_by_key(|(_, n)| *n)
        .map(|(name, _)| name)
}

/// `spectra capabilities --json`'s interfaces as (name, argv).
pub fn parse_interfaces(json: &str) -> Vec<(String, Vec<String>)> {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    v.get("interfaces")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    let name = i.get("name")?.as_str()?.to_owned();
                    let argv = i
                        .get("argv")?
                        .as_array()?
                        .iter()
                        .filter_map(|w| w.as_str().map(str::to_owned))
                        .collect();
                    Some((name, argv))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub struct Daemon {
    socket: PathBuf,
    /// Starts the daemon when its socket is missing; tried once per run.
    start: Box<dyn Fn() + Send + Sync>,
    started: AtomicBool,
    conn: Mutex<Option<Conn>>,
    methods: Mutex<HashSet<String>>,
    /// When the daemon last couldn't be reached.
    failed_at: Mutex<Option<Instant>>,
    next: AtomicU64,
    pushed: Arc<Pushed>,
    /// When the process list last handed out was sampled, so the same one isn't landed twice.
    served_procs: Mutex<String>,
    /// The capability interfaces, read once the daemon has [`EXEC`].
    interfaces: OnceLock<Vec<(String, Vec<String>)>>,
}

impl Daemon {
    pub fn new(socket: PathBuf, start: Box<dyn Fn() + Send + Sync>) -> Daemon {
        Daemon {
            socket,
            start,
            started: AtomicBool::new(false),
            conn: Mutex::new(None),
            methods: Mutex::new(HashSet::new()),
            failed_at: Mutex::new(None),
            next: AtomicU64::new(0),
            pushed: Arc::default(),
            served_procs: Mutex::new(String::new()),
            interfaces: OnceLock::new(),
        }
    }

    /// The methods the daemon listed when last connected; connects first if it can.
    pub fn methods(&self) -> HashSet<String> {
        let mut guard = lock(&self.conn);
        if self.ensure(&mut guard).is_err() {
            return HashSet::new();
        }
        lock(&self.methods).clone()
    }

    fn has(&self, method: &str) -> bool {
        lock(&self.methods).contains(method)
    }

    /// The last host sample the daemon pushed, if it's fresh.
    pub fn pushed_sample(&self) -> Option<Value> {
        let s = lock(&self.pushed.sample);
        s.as_ref()
            .filter(|(at, _)| at.elapsed() < FRESH)
            .map(|(_, v)| v.clone())
    }

    /// Calls `method`, reconnecting once if the connection had dropped (the daemon restarted).
    pub fn call(
        &self,
        method: &str,
        params: Value,
        deadline: Duration,
        cancel: &AtomicBool,
    ) -> Reply {
        match self.call_once(method, &params, deadline, cancel) {
            Err(Error::Disconnected) => self.call_once(method, &params, deadline, cancel),
            r => r,
        }
    }

    fn call_once(
        &self,
        method: &str,
        params: &Value,
        deadline: Duration,
        cancel: &AtomicBool,
    ) -> Reply {
        let (id, rx) = {
            let mut guard = lock(&self.conn);
            let conn = self.ensure(&mut guard)?;
            match send(&self.next, conn, method, params) {
                Ok(sent) => sent,
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            }
        };
        let start = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                // A cancelled exec is stopped in the daemon too, not only stopped waiting for.
                if method == EXEC && self.has(EXEC_CANCEL) {
                    self.notify(EXEC_CANCEL, &json!({"id": id}));
                }
                return Err(Error::Cancelled);
            }
            let left = deadline.saturating_sub(start.elapsed());
            if left.is_zero() {
                // A daemon that stopped answering is dropped, so the next call reconnects.
                self.drop_conn();
                return Err(Error::Timeout);
            }
            match rx.recv_timeout(left.min(CHECK)) {
                Ok(r) => return r,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(Error::Disconnected),
            }
        }
    }

    /// Sends a request whose answer nobody waits for.
    fn notify(&self, method: &str, params: &Value) {
        let mut guard = lock(&self.conn);
        if let Some(conn) = guard.as_mut() {
            let _ = send(&self.next, conn, method, params);
        }
    }

    fn drop_conn(&self) {
        if let Some(c) = lock(&self.conn).take() {
            let _ = c.writer.shutdown(std::net::Shutdown::Both);
        }
    }

    /// The live connection, opening one if there's none: dial (starting the daemon once if its
    /// socket is missing), ask which methods it has, and subscribe to what it pushes.
    fn ensure<'a>(&self, guard: &'a mut Option<Conn>) -> Result<&'a mut Conn, Error> {
        if guard
            .as_ref()
            .is_some_and(|c| c.alive.load(Ordering::SeqCst))
        {
            return Ok(guard.as_mut().expect("checked"));
        }
        *guard = None;
        if let Some(at) = *lock(&self.failed_at)
            && at.elapsed() < RETRY
        {
            return Err(Error::Unavailable(
                "the daemon was unreachable a moment ago".into(),
            ));
        }
        match self.open() {
            Ok(c) => {
                *lock(&self.failed_at) = None;
                Ok(guard.insert(c))
            }
            Err(e) => {
                *lock(&self.failed_at) = Some(Instant::now());
                lock(&self.methods).clear();
                Err(e)
            }
        }
    }

    fn open(&self) -> Result<Conn, Error> {
        if !self.socket.exists() && !self.started.swap(true, Ordering::SeqCst) {
            (self.start)();
            let since = Instant::now();
            while !self.socket.exists() && since.elapsed() < START_WAIT {
                std::thread::sleep(CHECK);
            }
        }
        let stream = UnixStream::connect(&self.socket)
            .map_err(|e| Error::Unavailable(format!("{}: {e}", self.socket.display())))?;
        let reader = stream
            .try_clone()
            .map_err(|e| Error::Unavailable(e.to_string()))?;
        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let (pending, alive, pushed) = (
                Arc::clone(&pending),
                Arc::clone(&alive),
                Arc::clone(&self.pushed),
            );
            std::thread::Builder::new()
                .name("spectra-daemon".into())
                .spawn(move || read_loop(reader, &pending, &alive, &pushed))
                .map_err(|e| Error::Unavailable(e.to_string()))?;
        }
        let mut conn = Conn {
            writer: stream,
            pending,
            alive,
        };
        let wait = |rx: Receiver<Reply>| rx.recv_timeout(HELLO).unwrap_or(Err(Error::Timeout));
        let (_, rx) = send(&self.next, &mut conn, STATUS, &Value::Null)?;
        let status = wait(rx)?;
        let methods: HashSet<String> = status
            .get("methods")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        // Without a subscription the calls still work: they ask instead of reading pushes.
        let mut subscribed = Vec::new();
        for (method, params) in [
            (SUBSCRIBE, json!({"samples": true})),
            (PROCESS_SUBSCRIBE, json!({"classify": true})),
        ] {
            if methods.contains(method) {
                let (_, rx) = send(&self.next, &mut conn, method, &params)?;
                if wait(rx).is_ok() {
                    subscribed.push(method);
                }
            }
        }
        let mut methods = methods;
        // A subscription that didn't take isn't counted on to push.
        methods.retain(|m| {
            !(m.as_str() == SUBSCRIBE || m.as_str() == PROCESS_SUBSCRIBE)
                || subscribed.contains(&m.as_str())
        });
        *lock(&self.methods) = methods;
        Ok(conn)
    }

    /// Answers `args` from the daemon when [`route`] sends it there. `None` runs the CLI: the
    /// table doesn't name the call, the daemon is unreachable, or it refused or garbled the call.
    pub fn answer(
        &self,
        args: &[&str],
        deadline: Duration,
        cancel: &AtomicBool,
    ) -> Option<Result<String, Error>> {
        if matches!(args.first(), None | Some(&"daemon") | Some(&"capabilities")) {
            return None;
        }
        let methods = self.methods();
        let r = match route(args, &methods) {
            Route::Cli => return None,
            Route::Table(e) => {
                let r = (e.answer)(self, args, deadline, cancel);
                // A daemon that lists the method but can't answer this call the CLI's way (an
                // older one that doesn't classify processes) isn't asked again until it
                // reconnects: the CLI runs instead of a wasted round trip every reading.
                if matches!(r, Err(Error::Shape(_) | Error::Rpc { .. })) {
                    lock(&self.methods).remove(e.method);
                }
                r
            }
            Route::Exec => self.exec(args, deadline, cancel),
        };
        match r {
            Ok(s) => Some(Ok(s)),
            Err(e @ (Error::Cancelled | Error::Timeout | Error::Warned(_))) => Some(Err(e)),
            Err(_) => None,
        }
    }

    fn exec(
        &self,
        args: &[&str],
        deadline: Duration,
        cancel: &AtomicBool,
    ) -> Result<String, Error> {
        let interfaces = self.interfaces.get_or_init(read_interfaces);
        let name = interface_name(args, interfaces)
            .ok_or_else(|| Error::Shape(format!("no interface for {args:?}")))?;
        let params =
            json!({"interface": name, "args": args, "timeout_ms": deadline.as_millis() as u64});
        Ok(match self.call(EXEC, params, deadline, cancel)? {
            Value::String(s) => s,
            Value::Object(mut o) if o.get("stdout").is_some_and(Value::is_string) => {
                match o.remove("stdout") {
                    Some(Value::String(s)) => s,
                    _ => String::new(),
                }
            }
            v => v.to_string(),
        })
    }

    /// The next process list not handed out yet: a pushed one when subscribed (waiting for it
    /// up to `deadline`), else the daemon's current snapshot.
    fn next_procs(
        &self,
        deadline: Duration,
        cancel: &AtomicBool,
    ) -> Result<(String, String), Error> {
        if self.has(PROCESS_SUBSCRIBE) {
            let served = lock(&self.served_procs).clone();
            let start = Instant::now();
            let mut procs = lock(&self.pushed.procs);
            loop {
                match procs.as_ref() {
                    // Nothing yet: ask, rather than wait a whole interval for the first push.
                    None => break,
                    Some((at, rows)) if *at != served => return Ok((at.clone(), rows.clone())),
                    Some(_) => {}
                }
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let left = deadline.saturating_sub(start.elapsed());
                // Nothing pushed in time: ask for the current one.
                if left.is_zero() {
                    break;
                }
                procs = self
                    .pushed
                    .procs_came
                    .wait_timeout(procs, left.min(CHECK))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        // A cold classification can take the daemon about 32 s; the table stays meanwhile.
        let wait = deadline.max(FIRST_LIST);
        let v = self.call(PROCESS_LIST, json!({"classify": true}), wait, cancel)?;
        let got = process_rows(v).map_err(|warning| match warning {
            Some(why) => Error::Warned(why),
            None => Error::Shape("process.list had no classified processes".into()),
        })?;
        if self.has(PROCESS_SUBSCRIBE) {
            // The next call waits for a newer push instead of landing this one again.
            let mut procs = lock(&self.pushed.procs);
            if procs.as_ref().is_none_or(|(at, _)| *at < got.0) {
                *procs = Some(got.clone());
            }
        }
        Ok(got)
    }
}

fn send(
    next: &AtomicU64,
    conn: &mut Conn,
    method: &str,
    params: &Value,
) -> Result<(u64, Receiver<Reply>), Error> {
    let id = next.fetch_add(1, Ordering::Relaxed) + 1;
    let (tx, rx) = channel();
    lock(&conn.pending).insert(id, tx);
    let mut line =
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
    line.push('\n');
    if conn.writer.write_all(line.as_bytes()).is_err() {
        lock(&conn.pending).remove(&id);
        return Err(Error::Disconnected);
    }
    Ok((id, rx))
}

/// `{sampled_at, processes}` as (when, rows as JSON). Rows without a role weren't classified,
/// which the process feed needs: the error carries the daemon's `warning` when it said why
/// (on the answer or its rows), and is `None` for a daemon that doesn't classify at all.
fn process_rows(mut v: Value) -> Result<(String, String), Option<String>> {
    let at = v
        .get("sampled_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let warning = |v: &Value| {
        v.get("warning")
            .and_then(Value::as_str)
            .filter(|w| !w.is_empty())
            .map(str::to_owned)
    };
    let top = warning(&v);
    let rows = v.get_mut("processes").map(Value::take).ok_or(None)?;
    let list = rows.as_array().ok_or(None)?;
    if list.is_empty() || list.iter().all(|r| r.get("role").is_none()) {
        return Err(top.or_else(|| list.iter().find_map(warning)));
    }
    Ok((at, rows.to_string()))
}

/// The main process feed: `spectra process -json --classify`'s rows.
fn processes(
    d: &Daemon,
    _: &[&str],
    deadline: Duration,
    cancel: &AtomicBool,
) -> Result<String, Error> {
    let (at, rows) = d.next_procs(deadline, cancel)?;
    *lock(&d.served_procs) = at;
    Ok(rows)
}

/// `spectra jvm -json`'s list.
fn jvms(d: &Daemon, _: &[&str], deadline: Duration, cancel: &AtomicBool) -> Result<String, Error> {
    match d.call("jvm.list", json!({}), deadline, cancel)? {
        v @ Value::Array(_) => Ok(v.to_string()),
        Value::Null => Ok("[]".into()),
        Value::Object(mut o) => match o.remove("jvms") {
            Some(v @ Value::Array(_)) => Ok(v.to_string()),
            _ => Err(Error::Shape("jvm.list had no list".into())),
        },
        _ => Err(Error::Shape("jvm.list had no list".into())),
    }
}

/// The host sample: the last one pushed, else asked for.
fn sample(d: &Daemon, deadline: Duration, cancel: &AtomicBool) -> Result<Value, Error> {
    if let Some(s) = d.pushed_sample() {
        return Ok(s);
    }
    let mut v = d.call("watch.current", Value::Null, deadline, cancel)?;
    match v.get_mut("sample").map(Value::take) {
        Some(s) if s.is_object() => Ok(s),
        _ => Err(Error::Shape("watch.current had no sample".into())),
    }
}

/// `spectra load --json`'s numbers, from the host sample.
fn load(d: &Daemon, _: &[&str], deadline: Duration, cancel: &AtomicBool) -> Result<String, Error> {
    let s = sample(d, deadline, cancel)?;
    let load1 = s
        .get("load1")
        .and_then(Value::as_f64)
        .ok_or_else(|| Error::Shape("sample had no load1".into()))?;
    let cpus = s.get("ncpu").and_then(Value::as_u64).unwrap_or(0);
    Ok(json!({"load1": load1, "cpus": cpus}).to_string())
}

fn read_loop(stream: UnixStream, pending: &Pending, alive: &AtomicBool, pushed: &Pushed) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let Ok(mut v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(id) = v.get("id").and_then(Value::as_u64) {
            let reply = match v.get_mut("error").map(Value::take) {
                Some(e) if !e.is_null() => Err(Error::Rpc {
                    code: e.get("code").and_then(Value::as_i64).unwrap_or(0),
                    message: e
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }),
                _ => Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null)),
            };
            if let Some(tx) = lock(pending).remove(&id) {
                let _ = tx.send(reply);
            }
            continue;
        }
        let params = v.get_mut("params").map(Value::take).unwrap_or(Value::Null);
        match v.get("method").and_then(Value::as_str) {
            Some("watch.sample") => *lock(&pushed.sample) = Some((Instant::now(), params)),
            Some("process.update") => {
                // One that couldn't be classified isn't landed: the table before it stays.
                if let Ok(p) = process_rows(params) {
                    *lock(&pushed.procs) = Some(p);
                    pushed.procs_came.notify_all();
                }
            }
            _ => {}
        }
    }
    alive.store(false, Ordering::SeqCst);
    for (_, tx) in lock(pending).drain() {
        let _ = tx.send(Err(Error::Disconnected));
    }
}

fn bin() -> String {
    std::env::var("SPECTRA_BIN").unwrap_or_else(|_| "spectra".into())
}

/// `spectra capabilities --json`'s interfaces, read once.
fn read_interfaces() -> Vec<(String, Vec<String>)> {
    let mut cmd = Command::new(bin());
    cmd.args(["capabilities", "--json"]);
    crate::run::run(cmd, Duration::from_secs(10), 1 << 20)
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_interfaces(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Where the daemon listens: `$SPECTRA_DAEMON_DIR`, else `$XDG_RUNTIME_DIR/spectra` on Linux,
/// else `~/.spectra`, as Spectra itself decides.
pub fn socket_path() -> Option<PathBuf> {
    let dir = match std::env::var_os("SPECTRA_DAEMON_DIR").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => match std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|d| cfg!(target_os = "linux") && !d.is_empty())
        {
            Some(d) => Path::new(&d).join("spectra"),
            None => Path::new(&std::env::var_os("HOME")?).join(".spectra"),
        },
    };
    Some(dir.join("daemon.sock"))
}

/// Runs `spectra daemon start` and waits a few seconds for it to return; never kills it, since
/// what it starts is the daemon.
fn start_daemon() {
    let Ok(mut child) = Command::new(bin())
        .args(["daemon", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let since = Instant::now();
    while since.elapsed() < START_WAIT {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(CHECK);
    }
}

static DAEMON: OnceLock<Daemon> = OnceLock::new();

/// Sends the Spectra calls the daemon can answer to it from now on. Connects on the first call.
pub fn install() {
    if let Some(socket) = socket_path() {
        let _ = DAEMON.set(Daemon::new(socket, Box::new(start_daemon)));
    }
}

/// The daemon's answer for `cmd`, when it's a Spectra call the daemon takes. `None` runs `cmd`.
pub fn answer(
    cmd: &Command,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Option<Result<String, Error>> {
    answer_with(DAEMON.get()?, cmd, deadline, cancel)
}

/// A call with its own environment (the disk reading's empty home) always runs the CLI.
fn answer_with(
    d: &Daemon,
    cmd: &Command,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Option<Result<String, Error>> {
    if cmd.get_program() != OsStr::new(&bin()) || cmd.get_envs().next().is_some() {
        return None;
    }
    let args: Vec<&str> = cmd.get_args().map(OsStr::to_str).collect::<Option<_>>()?;
    d.answer(&args, deadline, cancel)
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
