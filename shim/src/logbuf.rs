//! In-memory ring buffer of recent log lines, for the app's log viewer, plus
//! the `tracing` writer that fans each line out to both the ring buffer and
//! the platform sink (logcat on Android, stderr otherwise).

use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_LINES: usize = 1000;

static BUFFER: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Whether [`Quiet`] is applied: set by `init_logging` for the levels a user
/// reads (error, warn, info), cleared for debug and trace, which show
/// everything.
static QUIET: AtomicBool = AtomicBool::new(true);
static FILTER: Mutex<Quiet> = Mutex::new(Quiet::new());

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Lines that say nothing the line before them did not. Each is logged by
/// nostr-sdk at ERROR, next to a line that carries the cause:
/// - after every lost relay connection, that the dead socket could not be
///   closed either ("Broken pipe");
/// - at every node start, once per relay, that a subscription was sent
///   before the relay had connected. A relay that then fails to connect
///   says so itself ("Connection failed").
const REDUNDANT: [&str; 2] = [
    "Can't close WebSocket connection",
    "relay is initialized but not ready",
];

/// The same message again within this long is dropped.
const REPEAT_WINDOW: Duration = Duration::from_secs(2);
/// How many recent messages are remembered for that.
const REPEAT_DEPTH: usize = 16;

/// What keeps the log readable on a phone. Android aborts every relay
/// connection when the Wi-Fi roams, and nostr-sdk reports each one two to
/// four times: a Pixel 9 Pro hopping between two bands of one access point
/// filled the viewer with "os error 103" and "Broken pipe" pairs, twenty
/// lines for three events.
struct Quiet {
    recent: VecDeque<(Instant, String)>,
}

impl Quiet {
    const fn new() -> Self {
        Self {
            recent: VecDeque::new(),
        }
    }

    /// Whether `line` is worth showing at `now`.
    fn admit(&mut self, line: &str, now: Instant) -> bool {
        if REDUNDANT.iter().any(|phrase| line.contains(phrase)) {
            return false;
        }
        // Two reports of one event differ in their timestamp only.
        let message = line.split_once(' ').map_or(line, |(_, rest)| rest);
        while self
            .recent
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > REPEAT_WINDOW)
        {
            self.recent.pop_front();
        }
        if self.recent.iter().any(|(_, seen)| seen == message) {
            return false;
        }
        if self.recent.len() >= REPEAT_DEPTH {
            self.recent.pop_front();
        }
        self.recent.push_back((now, message.to_string()));
        true
    }
}

/// `line` with the access token of every mesh relay's loopback URL
/// replaced. nostr-sdk logs the URL it dials, `ws://127.0.0.1:<port>/<token>`
/// (see `meshtcp.rs`), and that token is what admits a caller to the relay
/// connection. It is new at every node start and useless off this phone,
/// but the log is there to be copied and sent to someone. At every level:
/// debug and trace are the ones a log is shared at.
fn mask_tokens(line: &str) -> std::borrow::Cow<'_, str> {
    const MARK: &str = "ws://127.0.0.1:";
    const TOKEN_LEN: usize = 32;
    if !line.contains(MARK) {
        return line.into();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(MARK) {
        let after = &rest[at + MARK.len()..];
        let port = after.bytes().take_while(u8::is_ascii_digit).count();
        let token = after[port..].strip_prefix('/').map_or(0, |path| {
            path.bytes().take_while(u8::is_ascii_hexdigit).count()
        });
        let keep = at + MARK.len() + port;
        if port > 0 && token >= TOKEN_LEN {
            out.push_str(&rest[..keep]);
            out.push_str("/<token>");
            rest = &rest[keep + 1 + token..];
        } else {
            out.push_str(&rest[..keep]);
            rest = &rest[keep..];
        }
    }
    out.push_str(rest);
    out.into()
}

fn push_line(line: &str) {
    if line.is_empty() {
        return;
    }
    let mut buf = BUFFER.lock().unwrap();
    while buf.len() >= MAX_LINES {
        buf.pop_front();
    }
    buf.push_back(line.to_string());
}

/// The most recent `max` log lines, oldest first, newline-joined.
pub fn recent(max: usize) -> String {
    let buf = BUFFER.lock().unwrap();
    let skip = buf.len().saturating_sub(max);
    buf.iter()
        .skip(skip)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(target_os = "android")]
fn platform_write(line: &str) {
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            prio: libc::c_int,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> libc::c_int;
    }
    const ANDROID_LOG_INFO: libc::c_int = 4;
    if let Ok(text) = std::ffi::CString::new(line) {
        let tag = c"fips";
        unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
    }
}

#[cfg(not(target_os = "android"))]
fn platform_write(line: &str) {
    eprintln!("{line}");
}

/// A `tracing` writer that mirrors every line into the ring buffer and the
/// platform log sink.
pub struct FanoutWriter;

impl io::Write for FanoutWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for line in buf.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let s = String::from_utf8_lossy(line);
            let s = mask_tokens(&s);
            if QUIET.load(Ordering::Relaxed)
                && !FILTER
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .admit(&s, Instant::now())
            {
                continue;
            }
            push_line(&s);
            platform_write(&s);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct MakeFanout;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeFanout {
    type Writer = FanoutWriter;
    fn make_writer(&'a self) -> Self::Writer {
        FanoutWriter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABORT: &str = "ERROR nostr_relay_pool::relay::inner: Relay receiver exited with error. url=wss://a error=IO error: Software caused connection abort (os error 103)";

    /// One lost relay connection is one line, however often it is reported;
    /// another relay's, or the same one's later, is its own.
    #[test]
    fn a_repeated_report_is_shown_once() {
        let mut quiet = Quiet::new();
        let start = Instant::now();
        assert!(quiet.admit(&format!("2026-11-15T09:15:35.007275Z {ABORT}"), start));
        assert!(!quiet.admit(
            &format!("2026-11-15T09:15:35.010380Z {ABORT}"),
            start + Duration::from_millis(3)
        ));
        let other = ABORT.replace("wss://a", "wss://b");
        assert!(quiet.admit(
            &format!("2026-11-15T09:15:35.010400Z {other}"),
            start + Duration::from_millis(3)
        ));
        assert!(quiet.admit(
            &format!("2026-11-15T09:15:54.427677Z {ABORT}"),
            start + Duration::from_secs(19)
        ));
    }

    #[test]
    fn a_mesh_relay_token_is_not_logged() {
        let token = "16cc43dfee59ddc62aa4fe8142932890";
        let line = format!(
            "ERROR nostr_relay_pool::relay::inner: Connection failed. url=ws://127.0.0.1:46353/{token} error=x; Connected to 'ws://127.0.0.1:9/{token}/sub'"
        );
        assert_eq!(
            mask_tokens(&line),
            "ERROR nostr_relay_pool::relay::inner: Connection failed. url=ws://127.0.0.1:46353/<token> error=x; Connected to 'ws://127.0.0.1:9/<token>/sub'"
        );
        // Not a token: other hosts, a short path, no path, nothing after the port.
        for line in [
            format!("url=wss://relay.example/{token}"),
            "url=ws://127.0.0.1:7777/abc".to_string(),
            "bind=ws://127.0.0.1:7777".to_string(),
            "ws://127.0.0.1:".to_string(),
        ] {
            assert_eq!(mask_tokens(&line), line);
        }
    }

    #[test]
    fn a_line_that_only_restates_the_one_before_is_dropped() {
        let mut quiet = Quiet::new();
        let now = Instant::now();
        for line in [
            "2026-11-15T09:15:35.007443Z ERROR nostr_relay_pool::relay::inner: Can't close WebSocket connection. error=IO error: Broken pipe (os error 32)",
            "2026-11-15T08:43:24.723450Z ERROR nostr_relay_pool::pool: Failed to stream events. url=wss://a error=relay is initialized but not ready",
        ] {
            assert!(!quiet.admit(line, now), "{line}");
        }
        assert!(quiet.admit(
            "2026-11-15T08:43:24.956323Z ERROR nostr_relay_pool::relay::inner: Connection failed. url=wss://a error=failed to lookup address information",
            now
        ));
    }
}
