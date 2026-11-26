//! Client for the node's control socket: how the shim reads node state
//! (`show_*`) and sends it a command (`connect`; the socket takes
//! `disconnect` too, which the shim does not use).
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
/// A command crosses to the rx loop and back. Longer than the 5 s fips
/// itself gives that round trip, so its own "timeout" answer gets here.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(7);
/// Largest answer read. `show_cache` on a busy node is the big one, far
/// below this; the bound is so a caller cannot be made to hold more.
const MAX_RESPONSE: u64 = 16 << 20;

#[derive(Debug)]
pub struct Control {
    path: PathBuf,
}

/// Connect, waiting `timeout` at most. `UnixStream::connect` has no
/// deadline: once a node that has stopped accepting has a full backlog it
/// blocks for good. A Unix socket's connect waits by the send timeout, so
/// that is set first.
fn connect(path: &Path, timeout: Duration) -> Result<UnixStream, String> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(|e| format!("control socket: {e}"))?;
    let addr = socket2::SockAddr::unix(path).map_err(|e| format!("control socket: {e}"))?;
    socket
        .set_write_timeout(Some(timeout))
        .and_then(|()| socket.connect(&addr))
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "control socket: no answer in time".to_string()
            }
            _ => format!("control socket: {e}"),
        })?;
    Ok(UnixStream::from(std::os::fd::OwnedFd::from(socket)))
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
        let mut stream = connect(&self.path, timeout)?;
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
}

/// How old an answer may be and still be served without asking again first.
/// Above the UI's 2 s polls, so a screen that is polling never waits.
const FRESH: Duration = Duration::from_secs(5);
/// After the node failed to answer anything, how long before a caller is
/// made to wait for it again.
const RETRY: Duration = Duration::from_secs(2);
/// The oldest answer ever served. Past this a node that has stopped
/// answering is reported as such, not shown with figures from long ago.
const MAX_STALE: Duration = Duration::from_secs(30);
/// Distinct queries remembered. The app asks a fixed handful.
const MAX_ENTRIES: usize = 32;

#[derive(Default)]
struct Entry {
    /// The last answer the node gave, and when.
    answer: Option<(Value, Instant)>,
    /// A refresh is queued or running.
    pending: bool,
}

#[derive(Default)]
struct State {
    entries: std::collections::HashMap<String, Entry>,
    /// When the node last failed to answer a query, any query: it is one
    /// node behind one socket, so one that is not answering `show_peers`
    /// is not asked to keep a caller waiting for `show_links` either.
    failed: Option<Instant>,
}

/// A refresh for the worker: the cache key, the command and its params.
type Job = (String, String, Option<Value>);
type Shared = std::sync::Arc<std::sync::Mutex<State>>;

fn locked(state: &Shared) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Queries for callers that must not wait: Kotlin polls status and the
/// Diagnostics queries on the main thread, where the fork's in-process
/// handle answered from memory.
///
/// An answer younger than [`FRESH`] is returned at once and a worker thread
/// fetches the next one, so a poller sees the node's state one poll late and
/// never blocks. A caller waits for the node ([`QUERY_TIMEOUT`] at most) only
/// when there is no fresh answer, no refresh of that query already under
/// way, and the node has not just failed to answer something: after a
/// failure nothing waits again for [`RETRY`], whatever the query. So a node
/// that is slow costs the main thread one timeout per [`RETRY`], not one per
/// call. Meanwhile the last answer is served, up to [`MAX_STALE`] old; past
/// that the query fails, which callers show as "no figures".
pub struct Cached {
    control: std::sync::Arc<Control>,
    state: Shared,
    /// To the worker; it ends when this is dropped.
    jobs: std::sync::Mutex<Option<std::sync::mpsc::Sender<Job>>>,
}

impl Cached {
    pub fn new(control: std::sync::Arc<Control>) -> Self {
        let state = Shared::default();
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let worker = {
            let control = control.clone();
            let state = state.clone();
            std::thread::Builder::new()
                .name("fips-control".into())
                .spawn(move || {
                    // Blocks in recv: no wakeups while nobody asks.
                    for (key, command, params) in rx {
                        let result = control.query(&command, params);
                        let mut state = locked(&state);
                        match result {
                            Ok(answer) => {
                                state.failed = None;
                                if let Some(entry) = state.entries.get_mut(&key) {
                                    entry.answer = Some((answer, Instant::now()));
                                }
                            }
                            Err(_) => state.failed = Some(Instant::now()),
                        }
                        if let Some(entry) = state.entries.get_mut(&key) {
                            entry.pending = false;
                        }
                    }
                })
        };
        Self {
            control,
            state,
            // No worker (thread limit): every query asks the node itself.
            jobs: std::sync::Mutex::new(worker.ok().map(|_| tx)),
        }
    }

    pub fn control(&self) -> &std::sync::Arc<Control> {
        &self.control
    }

    /// The node's answer to a `show_*` query: a recent one at once, else
    /// asked for now if that is worth a wait. `Err` when there is no answer
    /// younger than [`MAX_STALE`] and none could be had.
    pub fn query(&self, command: &str, params: Option<Value>) -> Result<Value, String> {
        let key = match &params {
            Some(p) => format!("{command}\0{p}"),
            None => command.to_string(),
        };
        let stale = {
            let mut state = locked(&self.state);
            if state.entries.len() >= MAX_ENTRIES && !state.entries.contains_key(&key) {
                state.entries.clear();
            }
            let now = Instant::now();
            let node_failed = state.failed.is_some_and(|at| now.duration_since(at) < RETRY);
            let entry = state.entries.entry(key.clone()).or_default();
            let (answer, age) = match &entry.answer {
                Some((answer, at)) => (Some(answer.clone()), now.duration_since(*at)),
                None => (None, Duration::MAX),
            };
            let usable = answer.filter(|_| age < MAX_STALE);
            // Wait for the node only when nothing else will bring an answer
            // and it has not just shown that it is not answering.
            let wait = age >= FRESH && !entry.pending && !node_failed;
            if !wait {
                if !entry.pending && self.refresh(&key, command, &params) {
                    entry.pending = true;
                }
                return usable.ok_or_else(|| "the node did not answer".to_string());
            }
            usable
        };
        // Ask, with the state unlocked.
        let result = self.control.query(command, params);
        let mut state = locked(&self.state);
        match result {
            Ok(answer) => {
                state.failed = None;
                state.entries.entry(key).or_default().answer =
                    Some((answer.clone(), Instant::now()));
                Ok(answer)
            }
            Err(e) => {
                state.failed = Some(Instant::now());
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

    /// Whether an answer to `command` (without params) is held.
    pub fn answered(&self, command: &str) -> bool {
        locked(&self.state)
            .entries
            .get(command)
            .is_some_and(|e| e.answer.is_some())
    }

    /// Wait, `wait` at most, until the node has bound the socket and
    /// answered a status query; that answer is kept for the first poll.
    pub fn wait_ready(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            if let Ok(answer) = self.control.request("show_status", None, left.min(QUERY_TIMEOUT)) {
                let mut state = locked(&self.state);
                state.failed = None;
                state.entries.entry("show_status".into()).or_default().answer =
                    Some((answer, Instant::now()));
                return true;
            }
            std::thread::sleep(Duration::from_millis(10).min(left));
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
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        assert!(cached.wait_ready(Duration::from_secs(5)));
        assert!(cached.answered("show_status"), "the answer is kept");
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

    #[test]
    fn waiting_for_a_socket_that_never_appears_takes_the_wait_and_no_more() {
        let cached = Cached::new(std::sync::Arc::new(Control::new(socket_path("never.sock"))));
        let started = Instant::now();
        assert!(!cached.wait_ready(Duration::from_millis(300)));
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(300) && took < Duration::from_millis(900), "{took:?}");
    }

    /// One node behind one socket: when it does not answer one query, a
    /// caller is not made to wait for each of the others in turn.
    #[test]
    fn a_node_that_does_not_answer_one_query_is_not_waited_for_on_the_others() {
        let path = socket_path("mute-many.sock");
        let listener = UnixListener::bind(&path).unwrap(); // answers nothing
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        assert!(cached.query("show_peers", None).is_err()); // the one wait
        let started = Instant::now();
        for command in ["show_sessions", "show_links", "show_lan_peers", "show_status"] {
            assert!(cached.query(command, None).is_err());
        }
        assert!(started.elapsed() < Duration::from_millis(200), "waited per query");
        drop(listener);
    }

    /// A node that has stopped accepting fills its backlog; a connect to it
    /// must come back by the deadline, not block for good.
    #[test]
    fn a_full_backlog_costs_the_timeout_and_no_more() {
        let path = socket_path("full.sock");
        let listener =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        listener.bind(&socket2::SockAddr::unix(&path).unwrap()).unwrap();
        listener.listen(1).unwrap();
        let control = Control::new(&path);
        let started = Instant::now();
        // Far more than the backlog holds; every one returns.
        for _ in 0..8 {
            let err = control
                .request("show_status", None, Duration::from_millis(100))
                .unwrap_err();
            assert!(err.contains("no answer in time"), "{err}");
        }
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
        drop(listener);
    }

    #[test]
    fn an_answer_too_old_is_not_served() {
        let path = socket_path("old.sock");
        let server = counting(&path, 1);
        let cached = Cached::new(std::sync::Arc::new(Control::new(&path)));
        assert!(cached.query("show_status", None).is_ok());
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        // Age the answer past MAX_STALE instead of waiting it out.
        {
            let mut state = locked(&cached.state);
            let entry = state.entries.get_mut("show_status").unwrap();
            let (answer, at) = entry.answer.take().unwrap();
            entry.answer = Some((answer, at - MAX_STALE - Duration::from_secs(1)));
        }
        assert!(cached.query("show_status", None).is_err());
    }
}
