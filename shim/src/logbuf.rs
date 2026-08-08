//! In-memory ring buffer of recent log lines, for the app's log viewer, plus
//! the `tracing` writer that fans each line out to both the ring buffer and
//! the platform sink (logcat on Android, stderr otherwise).

use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;

const MAX_LINES: usize = 1000;

static BUFFER: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

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
