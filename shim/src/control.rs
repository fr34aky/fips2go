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
//! caller is never held longer than `timeout` however busy the node is. A
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
}
