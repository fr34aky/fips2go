//! Client for the node's control socket, for the one thing the shim cannot
//! do in process: send the running node a command (`connect`, Diagnostics'
//! manual dial of an mDNS-seen peer).
//!
//! This is the interface fips offers everything outside the node — `fipsctl`
//! speaks it — a Unix socket taking one JSON line and answering one. The
//! node is moved into its rx loop at start and takes commands only there;
//! the fips fork used to hand the embedder an in-process handle for that,
//! and the socket is what upstream has instead. The file sits in the app's
//! private directory, which no other UID can enter, so it gives nothing on
//! the phone a way in that it did not have.
//!
//! Reading node state does NOT go through here. Kotlin polls status and the
//! `show_*` queries on its main thread, and a socket round trip can stall
//! where a read from memory cannot: those use the node's in-process
//! `ControlReadHandle` (`engine.rs`). A request here is its own connection,
//! blocking, with one deadline over connect, write and read — call it off
//! the main thread.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

/// A command crosses to the rx loop and back. Longer than the 5 s fips
/// itself gives that round trip, so its own "timeout" answer gets here.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(7);
/// Largest answer read: a command's is a line. The bound is so a caller
/// cannot be made to hold more.
const MAX_RESPONSE: u64 = 1 << 20;
/// How long a request keeps trying a socket that is not there yet. The node
/// binds it on a task of its own once its rx loop runs, shortly after
/// `start` returns.
const BIND_GRACE: Duration = Duration::from_secs(2);
/// The shortest wait worth starting; less is treated as the deadline passed.
const MIN_WAIT: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub struct Control {
    path: PathBuf,
}

/// Connect by `deadline`. `UnixStream::connect` has no deadline: once a node
/// that has stopped accepting has a full backlog it blocks for good. A Unix
/// socket's connect waits by the send timeout, so that is set first. A
/// socket that is not there yet is tried again for [`BIND_GRACE`].
fn connect(path: &Path, deadline: Instant) -> Result<UnixStream, String> {
    let grace = Instant::now() + BIND_GRACE;
    loop {
        // Under a millisecond counts as none: a timeout that rounds down
        // to zero means "no timeout" to the kernel.
        let left = deadline.saturating_duration_since(Instant::now());
        if left < MIN_WAIT {
            return Err("control socket: no answer in time".into());
        }
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            .map_err(|e| format!("control socket: {e}"))?;
        let addr = socket2::SockAddr::unix(path).map_err(|e| format!("control socket: {e}"))?;
        let connected = socket
            .set_write_timeout(Some(left))
            .and_then(|()| socket.connect(&addr));
        match connected {
            Ok(()) => return Ok(UnixStream::from(std::os::fd::OwnedFd::from(socket))),
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    return Err("control socket: no answer in time".into());
                }
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    if Instant::now() < grace.min(deadline) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                // A signal: a connect under a socket timeout is not
                // restarted. Again, against the same deadline.
                std::io::ErrorKind::Interrupted => {}
                _ => return Err(format!("control socket: {e}")),
            },
        }
    }
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
        let mut stream = connect(&self.path, deadline)?;
        let mut line = serde_json::json!({ "command": command, "params": params }).to_string();
        line.push('\n');
        // What is left of the one deadline, not a fresh timeout.
        let left = deadline.saturating_duration_since(Instant::now());
        if left < MIN_WAIT {
            return Err("control socket: no answer in time".into());
        }
        stream
            .set_write_timeout(Some(left))
            .and_then(|()| stream.write_all(line.as_bytes()))
            .map_err(|e| format!("control socket write: {e}"))?;

        // The node writes one line and closes. Read to the end against the
        // deadline rather than per read, so a slow drip cannot outlast it.
        let mut answer = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left < MIN_WAIT {
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
        assert_eq!(answer["message"], "bad npub");
        server.join().unwrap();
    }

    #[test]
    fn a_socket_that_never_appears_is_given_up_after_the_grace() {
        let started = Instant::now();
        let err = Control::new(socket_path("absent.sock"))
            .request("connect", None, COMMAND_TIMEOUT)
            .unwrap_err();
        assert!(err.contains("control socket"), "{err}");
        let took = started.elapsed();
        assert!(took >= BIND_GRACE && took < BIND_GRACE + Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn a_socket_that_appears_late_is_found() {
        let path = socket_path("late.sock");
        let bind_at = path.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            serve(&bind_at, 1, |_| b"{\"status\":\"ok\",\"data\":{}}\n".to_vec())
                .join()
                .unwrap();
        });
        let answer = Control::new(&path).request("connect", None, COMMAND_TIMEOUT).unwrap();
        assert_eq!(answer["status"], "ok");
        server.join().unwrap();
    }

    #[test]
    fn a_node_that_never_answers_costs_the_timeout_and_no_more() {
        let path = socket_path("silent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let started = Instant::now();
        let err = Control::new(&path)
            .request("connect", None, Duration::from_millis(200))
            .unwrap_err();
        assert!(err.contains("no answer in time"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(1));
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
                .request("connect", None, Duration::from_millis(100))
                .unwrap_err();
            assert!(err.contains("no answer in time"), "{err}");
        }
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        drop(listener);
    }
}
