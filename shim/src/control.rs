//! Client for the node's control socket: how the shim reads node state
//! (`show_*`) and sends it the two mutating commands (`connect`,
//! `disconnect`).
//!
//! This is the interface fips offers everything outside the node — `fipsctl`
//! and `fipstop` speak it — a Unix socket taking one JSON line and answering
//! one. The node is moved into its rx loop at start and cannot be asked
//! anything directly afterwards; the fips fork used to hand the embedder two
//! in-process handles for that, and the socket is what upstream has instead.
//! The file sits in the app's private directory, which no other UID can
//! enter, so it gives nothing on the phone a way in that it did not have.
//!
//! Every request is its own connection: blocking, with a deadline, so a
//! caller is never held longer than `timeout` however busy the node is.
//! Callers on the app's main thread go through [`Cached`], which answers
//! from the last reply and fetches the next one on a thread of its own. A
//! `show_*` query is answered by fips's accept task from snapshots and never
//! reaches the rx loop; it does wake the node's runtime, which the in-process
//! handle did not, so nothing should poll through this on a short timer while
//! no screen is asking.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

/// A snapshot query: answered at once or not worth waiting for.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(1);
/// A command crosses to the rx loop and back.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest answer read. `show_cache` on a busy node is the big one, far
/// below this; the bound is so a caller cannot be made to hold more.
const MAX_RESPONSE: u64 = 16 << 20;

#[derive(Debug)]
pub struct Control {
    path: PathBuf,
}

impl Control {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One request, one answer: the node's `{"status": "ok" | "error", ..}`
    /// object, or why none came.
    pub fn request(
        &self,
        command: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let mut stream =
            UnixStream::connect(&self.path).map_err(|e| format!("control socket: {e}"))?;
        let mut line = serde_json::json!({ "command": command, "params": params }).to_string();
        line.push('\n');
        stream
            .set_write_timeout(Some(timeout))
            .and_then(|()| stream.write_all(line.as_bytes()))
            .map_err(|e| format!("control socket write: {e}"))?;

        // The node writes one line and closes. Read to the end against the
        // deadline rather than per read, so a slow drip cannot outlast it.
        let mut answer = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("control socket: no answer in time".into());
            }
            stream
                .set_read_timeout(Some(left))
                .map_err(|e| format!("control socket: {e}"))?;
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    answer.extend_from_slice(&chunk[..n]);
                    if answer.len() as u64 > MAX_RESPONSE {
                        return Err("control socket: answer too large".into());
                    }
                    if answer.last() == Some(&b'\n') {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("control socket: no answer in time".into());
                }
                Err(e) => return Err(format!("control socket read: {e}")),
            }
        }
        if answer.is_empty() {
            return Err("control socket: closed without an answer".into());
        }
        serde_json::from_slice(&answer).map_err(|e| format!("control socket answer: {e}"))
    }

    /// A read-only query. Only `show_*` is sent: the socket would take a
    /// mutating command too, and callers of this pass names through from
    /// the UI.
    pub fn query(&self, command: &str, params: Option<Value>) -> Result<Value, String> {
        if !command.starts_with("show_") {
            return Err(format!("not a query: {command}"));
        }
        self.request(command, params, QUERY_TIMEOUT)
    }

    /// Wait until the node has bound the socket (it does so on a task of its
    /// own once the rx loop runs, shortly after `start` returns). True when
    /// a query was answered within `wait`.
    pub fn wait_ready(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if self.query("show_status", None).is_ok() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// How old an answer may be and still be served without asking again first.
/// Above the UI's 2 s polls, so a screen that is polling never waits.
const FRESH: Duration = Duration::from_secs(5);
/// After a query that got no answer, how long before a caller is made to
/// wait for one again.
const RETRY: Duration = Duration::from_secs(2);
/// Distinct queries remembered. The app asks a fixed handful.
const MAX_ENTRIES: usize = 32;

#[derive(Default)]
struct Entry {
    /// The last answer the node gave, and when.
    answer: Option<(Value, Instant)>,
    /// A refresh is queued or running.
    pending: bool,
    /// When the node last failed to answer this.
    failed: Option<Instant>,
}

/// A refresh for the worker: the cache key, the command and its params.
type Job = (String, String, Option<Value>);
type Entries = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Entry>>>;

fn locked(map: &Entries) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Entry>> {
    map.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Queries for callers that must not wait: Kotlin polls status and the
/// Diagnostics queries on the main thread, where the fork's in-process
/// handle answered from memory.
///
/// An answer younger than [`FRESH`] is returned at once and a worker thread
/// fetches the next one, so a poller sees the node's state one poll late and
/// never blocks. Only a query with no recent answer waits for the node
/// ([`QUERY_TIMEOUT`] at most), and when the node did not answer, nothing
/// waits for it again for [`RETRY`]: the last answer is served meanwhile. A
/// node that is slow therefore costs a poller one timeout, not one per call,
/// and an answer once given is never replaced by "no answer".
pub struct Cached {
    control: std::sync::Arc<Control>,
    entries: Entries,
    /// To the worker; it ends when this is dropped.
    jobs: std::sync::Mutex<Option<std::sync::mpsc::Sender<Job>>>,
}

impl Cached {
    pub fn new(control: std::sync::Arc<Control>) -> Self {
        let entries = Entries::default();
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let worker = {
            let control = control.clone();
            let entries = entries.clone();
            std::thread::Builder::new()
                .name("fips-control".into())
                .spawn(move || {
                    // Blocks in recv: no wakeups while nobody asks.
                    for (key, command, params) in rx {
                        let result = control.query(&command, params);
                        let mut map = locked(&entries);
                        if let Some(entry) = map.get_mut(&key) {
                            entry.pending = false;
                            match result {
                                Ok(answer) => {
                                    entry.answer = Some((answer, Instant::now()));
                                    entry.failed = None;
                                }
                                Err(_) => entry.failed = Some(Instant::now()),
                            }
                        }
                    }
                })
        };
        Self {
            control,
            entries,
            // No worker (thread limit): every query asks the node itself.
            jobs: std::sync::Mutex::new(worker.ok().map(|_| tx)),
        }
    }

    pub fn control(&self) -> &std::sync::Arc<Control> {
        &self.control
    }

    /// The node's answer to a `show_*` query: a recent one at once, else
    /// asked for now. `Err` only when the node has never answered this and
    /// does not answer now.
    pub fn query(&self, command: &str, params: Option<Value>) -> Result<Value, String> {
        let key = match &params {
            Some(p) => format!("{command}\0{p}"),
            None => command.to_string(),
        };
        let stale = {
            let mut map = locked(&self.entries);
            if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
                map.clear();
            }
            let entry = map.entry(key.clone()).or_default();
            let now = Instant::now();
            let recent_failure = entry.failed.is_some_and(|at| now.duration_since(at) < RETRY);
            match &entry.answer {
                Some((answer, at)) if now.duration_since(*at) < FRESH || recent_failure => {
                    let answer = answer.clone();
                    if !entry.pending && self.refresh(&key, command, &params) {
                        entry.pending = true;
                    }
                    return Ok(answer);
                }
                None if recent_failure => return Err("the node did not answer".into()),
                other => other.as_ref().map(|(answer, _)| answer.clone()),
            }
        };
        // Nothing recent: ask, with the map unlocked.
        let result = self.control.query(command, params);
        let mut map = locked(&self.entries);
        let entry = map.entry(key).or_default();
        match result {
            Ok(answer) => {
                entry.answer = Some((answer.clone(), Instant::now()));
                entry.failed = None;
                Ok(answer)
            }
            Err(e) => {
                entry.failed = Some(Instant::now());
                stale.ok_or(e)
            }
        }
    }

    /// Queue a background fetch; false when there is no worker to do it.
    fn refresh(&self, key: &str, command: &str, params: &Option<Value>) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.as_ref().is_some_and(|tx| {
            tx.send((key.to_string(), command.to_string(), params.clone()))
                .is_ok()
        })
    }

    /// Whether the node has ever answered `command` (without params).
    pub fn answered(&self, command: &str) -> bool {
        locked(&self.entries)
            .get(command)
            .is_some_and(|e| e.answer.is_some())
    }

    /// Wait until the node has bound the socket and answered a status query
    /// (see [`Control::wait_ready`]); the answer is kept for the first poll.
    pub fn wait_ready(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if self.control.query("show_status", None).is_ok() {
                // Through the cache this time, so it holds the answer.
                locked(&self.entries).remove("show_status");
                return self.query("show_status", None).is_ok();
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    fn socket_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fips2go-ctl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Serve `connections` requests: read the line, hand it to `answer`,
    /// write what it returns, close.
    fn serve(
        path: &Path,
        connections: usize,
        answer: impl Fn(Value) -> Vec<u8> + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let _ = stream.write_all(&answer(serde_json::from_str(&line).unwrap()));
            }
        })
    }

    #[test]
    fn a_request_is_one_line_and_the_answer_is_parsed() {
        let path = socket_path("ok.sock");
        let server = serve(&path, 1, |request| {
            assert_eq!(request["command"], "show_status");
            assert!(request["params"].is_null());
            b"{\"status\":\"ok\",\"data\":{\"peers\":2}}\n".to_vec()
        });
        let answer = Control::new(&path).query("show_status", None).unwrap();
        assert_eq!(answer["data"]["peers"], 2);
        server.join().unwrap();
    }

    #[test]
    fn params_are_sent() {
        let path = socket_path("params.sock");
        let server = serve(&path, 1, |request| {
            assert_eq!(request["command"], "connect");
            assert_eq!(request["params"]["npub"], "npub1x");
            b"{\"status\":\"error\",\"message\":\"bad npub\"}\n".to_vec()
        });
        let answer = Control::new(&path)
            .request(
                "connect",
                Some(serde_json::json!({ "npub": "npub1x" })),
                COMMAND_TIMEOUT,
            )
            .unwrap();
        assert_eq!(answer["status"], "error");
        server.join().unwrap();
    }

    #[test]
    fn a_query_never_carries_a_command() {
        let path = socket_path("nothing-listens.sock");
        let err = Control::new(&path).query("connect", None).unwrap_err();
        assert!(err.contains("not a query"), "{err}");
    }

    #[test]
    fn no_socket_is_an_error_not_a_wait() {
        let started = Instant::now();
        let err = Control::new(socket_path("absent.sock"))
            .query("show_status", None)
            .unwrap_err();
        assert!(err.contains("control socket"), "{err}");
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn a_node_that_never_answers_costs_the_timeout_and_no_more() {
        let path = socket_path("silent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let started = Instant::now();
        let err = Control::new(&path)
            .request("show_status", None, Duration::from_millis(200))
            .unwrap_err();
        assert!(err.contains("no answer in time"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(listener);
    }

    #[test]
    fn wait_ready_sees_a_socket_that_appears_late() {
        let path = socket_path("late.sock");
        let bind_at = path.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            serve(&bind_at, 1, |_| b"{\"status\":\"ok\",\"data\":{}}\n".to_vec())
                .join()
                .unwrap();
        });
        assert!(Control::new(&path).wait_ready(Duration::from_secs(5)));
        server.join().unwrap();
    }

    /// A server that answers `n` and counts up, `connections` times.
    fn counting(path: &Path, connections: usize) -> std::thread::JoinHandle<()> {
        let n = std::sync::atomic::AtomicUsize::new(0);
        serve(path, connections, move |_| {
            let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("{{\"status\":\"ok\",\"data\":{{\"n\":{i}}}}}\n").into_bytes()
        })
    }

    fn n_of(answer: &Value) -> u64 {
        answer["data"]["n"].as_u64().unwrap()
    }

    #[test]
    fn a_poller_gets_the_last_answer_at_once_and_the_next_one_a_poll_later() {
        let path = socket_path("cached.sock");
        let server = counting(&path, 3);
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        // Nothing known: this one asks the node.
        assert_eq!(n_of(&cached.query("show_status", None).unwrap()), 0);
        // Served from memory, and a refresh is under way.
        let started = Instant::now();
        assert_eq!(n_of(&cached.query("show_status", None).unwrap()), 0);
        assert!(started.elapsed() < Duration::from_millis(100));
        // The refreshed answer turns up without anyone waiting for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while n_of(&cached.query("show_status", None).unwrap()) == 0 {
            assert!(Instant::now() < deadline, "the refresh never landed");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(cached);
        drop(server); // may still be in accept: not joined
    }

    #[test]
    fn an_answer_once_given_outlives_a_node_that_stops_answering() {
        let path = socket_path("gone.sock");
        let server = counting(&path, 1);
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        assert_eq!(n_of(&cached.query("show_status", None).unwrap()), 0);
        server.join().unwrap(); // the listener is gone now
        std::fs::remove_file(&path).unwrap();
        for _ in 0..5 {
            assert_eq!(n_of(&cached.query("show_status", None).unwrap()), 0);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(cached.answered("show_status"));
    }

    #[test]
    fn a_node_that_never_answered_is_not_waited_for_on_every_call() {
        let path = socket_path("mute.sock");
        let listener = UnixListener::bind(&path).unwrap(); // accepts nothing, answers nothing
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        assert!(cached.query("show_peers", None).is_err()); // waits the timeout once
        let started = Instant::now();
        for _ in 0..5 {
            assert!(cached.query("show_peers", None).is_err());
        }
        assert!(started.elapsed() < Duration::from_millis(200), "waited again");
        assert!(!cached.answered("show_peers"));
        drop(listener);
    }

    #[test]
    fn queries_with_different_params_are_kept_apart() {
        let path = socket_path("params-cache.sock");
        let server = serve(&path, 2, |request| {
            format!("{{\"status\":\"ok\",\"data\":{}}}\n", request["params"]).into_bytes()
        });
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        let a = cached.query("show_x", Some(serde_json::json!({ "k": 1 }))).unwrap();
        let b = cached.query("show_x", Some(serde_json::json!({ "k": 2 }))).unwrap();
        assert_eq!(a["data"]["k"], 1);
        assert_eq!(b["data"]["k"], 2);
        server.join().unwrap();
    }
}
