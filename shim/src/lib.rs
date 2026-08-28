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
pub mod filter;
pub mod forward;
mod jni_api;
pub mod logbuf;
pub mod packet;
pub mod pump;

/// Initialize tracing. Lines fan out to the in-app ring buffer plus the
/// platform sink (logcat tag "fips" on Android, stderr elsewhere). Level from
/// `level` ("error".."trace"), default info.
///
/// The subscriber is installed once per process, but the level filter sits
/// behind a reload handle: calling this again (every engine start, i.e. every
/// reconnect) swaps the filter in place, so a log-level settings change takes
/// effect on the next connect without killing the app process.
pub fn init_logging(level: Option<&str>) {
    use std::sync::OnceLock;
    use tracing_subscriber::{
        layer::SubscriberExt, reload, util::SubscriberInitExt, EnvFilter, Registry,
    };
    static FILTER: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

    let filter = EnvFilter::try_new(level.unwrap_or("info"))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if let Some(handle) = FILTER.get() {
        let _ = handle.reload(filter);
        return;
    }
    let (filter_layer, handle) = reload::Layer::new(filter);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(logbuf::MakeFanout);
    if tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init()
        .is_ok()
    {
        let _ = FILTER.set(handle);
    }
    // try_init failing means another subscriber owns the process (host
    // tests); leave the handle unset and stay a no-op there.
}
