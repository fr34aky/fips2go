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
pub mod logbuf;
pub mod packet;
pub mod pump;

/// Initialize tracing once. Lines fan out to the in-app ring buffer plus the
/// platform sink (logcat tag "fips" on Android, stderr elsewhere). Level from
/// `level` ("error".."trace"), default info.
pub fn init_logging(level: Option<&str>) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let level = level.unwrap_or("info").to_string();
    ONCE.call_once(move || {
        let filter = tracing_subscriber::EnvFilter::try_new(&level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(logbuf::MakeFanout)
            .try_init();
    });
}
