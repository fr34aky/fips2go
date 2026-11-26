//! Android embedding shim for the FIPS mesh daemon.
//!
//! The Kotlin side owns the `VpnService` and its TUN fd; this crate owns
//! everything else: node lifecycle on a dedicated thread, the fd pump
//! (with [`meshout`] as the embedder's half of fips's app-owned TUN contract),
//! a DNS proxy that splits `.fips` queries to the in-process responder and
//! everything else to upstream resolvers, and the JNI surface.

pub mod ble;
pub mod config;
pub mod control;
pub mod dns;
pub mod engine;
pub mod exit;
pub mod exitfind;
pub mod filter;
pub mod forward;
mod jni_api;
pub mod logbuf;
pub mod meshhttp;
pub mod meshout;
pub mod meshtcp;
pub mod meshudp;
pub mod names;
pub mod packet;
pub mod pump;

/// Called with the raw fd of a socket that must leave on the underlying
/// network, not through this app's own tunnel: `VpnService.protect`, plus
/// whatever else Kotlin does with it (`FipsVpnService.protectFd` moves the
/// FIPS Hotspot socket onto its network). Handed every socket the shim dials
/// itself and each UDP listen socket of the node. From any thread.
pub type SocketProtect = std::sync::Arc<dyn Fn(std::os::unix::io::RawFd) + Send + Sync>;

/// Initialize tracing. Lines fan out to the in-app ring buffer plus the
/// platform sink (logcat tag "fips" on Android, stderr elsewhere). Level from
/// `level` ("error".."trace"), default info.
///
/// The subscriber is installed once per process, but the level filter sits
/// behind a reload handle: calling this again (every engine start, i.e. every
/// reconnect) swaps the filter in place, so a log-level settings change takes
/// effect on the next connect without killing the app process.
///
/// At error, warn and info — the levels someone reads in the app's viewer —
/// the log is kept to what they can act on, see [`log_directives`] and
/// `logbuf::Quiet`. Debug and trace show everything.
pub fn init_logging(level: Option<&str>) {
    use std::sync::OnceLock;
    use tracing_subscriber::{
        EnvFilter, Registry, layer::SubscriberExt, reload, util::SubscriberInitExt,
    };
    static FILTER: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

    let (directives, quiet) = log_directives(level);
    logbuf::set_quiet(quiet);
    let filter = EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("info"));

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

/// The filter for a configured log level, and whether the log is kept quiet.
///
/// Quiet, two warnings that are routine on a phone are left out:
/// - `ipstack` warns for every forwarded connection it closes after its
///   idle timeout, twice;
/// - fips's netmon warns at every node start that kernel medium-change
///   events are unavailable. They always are: SELinux refuses apps the
///   netlink socket, and the service pokes the detector itself.
fn log_directives(level: Option<&str>) -> (String, bool) {
    let level = level.unwrap_or("info");
    match level.to_ascii_lowercase().as_str() {
        "error" | "warn" | "info" => (
            format!("{level},ipstack=error,fips::node::netmon=error"),
            true,
        ),
        _ => (level.to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::log_directives;

    #[test]
    fn only_the_levels_someone_reads_are_kept_quiet() {
        for level in [None, Some("info"), Some("warn"), Some("error"), Some("INFO")] {
            let (directives, quiet) = log_directives(level);
            assert!(quiet, "{level:?}");
            assert!(directives.ends_with(",ipstack=error,fips::node::netmon=error"));
            assert!(tracing_subscriber::EnvFilter::try_new(&directives).is_ok());
        }
        for level in ["debug", "trace", "info,fips=debug"] {
            assert_eq!(log_directives(Some(level)), (level.to_string(), false));
        }
    }
}
