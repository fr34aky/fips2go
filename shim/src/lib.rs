//! Android embedding shim for the FIPS mesh daemon.
//!
//! The Kotlin side owns the `VpnService` and its TUN fd; this crate owns
//! everything else: node lifecycle on a dedicated thread, the fd pump
//! (with the node's own [`fips::TunPacketProcessor`] for system-TUN parity),
//! a DNS proxy that splits `.fips` queries to the in-process responder and
//! everything else to upstream resolvers, and the JNI surface.

pub mod config;
pub mod dns;
pub mod engine;
pub mod forward;
mod jni_api;
pub mod packet;
pub mod pump;

/// Initialize tracing once. On Android, log lines go to logcat (tag "fips");
/// elsewhere to stderr. Level from `level` ("error".."trace"), default info.
pub fn init_logging(level: Option<&str>) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let level = level.unwrap_or("info").to_string();
    ONCE.call_once(move || {
        let filter = tracing_subscriber::EnvFilter::try_new(&level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        #[cfg(target_os = "android")]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .without_time() // logcat timestamps already
                .with_writer(logcat::MakeLogcatWriter)
                .try_init();
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
        }
    });
}

#[cfg(target_os = "android")]
mod logcat {
    //! Minimal logcat writer: each line becomes one `__android_log_write`
    //! call with tag "fips". Links against the always-present liblog.
    use std::io;

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            prio: libc::c_int,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> libc::c_int;
    }

    const ANDROID_LOG_INFO: libc::c_int = 4;

    pub struct LogcatWriter;

    impl io::Write for LogcatWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let tag = c"fips";
            for line in buf.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                if let Ok(text) = std::ffi::CString::new(line.to_vec()) {
                    unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct MakeLogcatWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeLogcatWriter {
        type Writer = LogcatWriter;
        fn make_writer(&'a self) -> Self::Writer {
            LogcatWriter
        }
    }
}
