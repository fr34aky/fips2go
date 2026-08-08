//! JNI surface for `org.fips.android.FipsNative` (Kotlin `external fun`s).
//!
//! Compiled on every platform (the `jni` crate is portable) so host builds
//! type-check it; only the Android app actually loads it. All entry points
//! catch errors and return them as strings — nothing panics across the FFI
//! boundary.

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring};
use std::sync::Arc;

/// Build the socket-protect hook from the Java callback object (the
/// `FipsVpnService`): each underlay fd is passed to its
/// `protectFd(int): Boolean` method. Fires from arbitrary Rust threads, so
/// the hook owns a `JavaVM` reference and attaches on demand.
fn protect_hook_from(env: &mut JNIEnv, callback: &JObject) -> Option<fips::SocketProtect> {
    if callback.is_null() {
        return None;
    }
    let vm = env.get_java_vm().ok()?;
    let callback = env.new_global_ref(callback).ok()?;
    Some(Arc::new(move |fd| {
        match vm.attach_current_thread_permanently() {
            Ok(mut env) => {
                let result = env.call_method(
                    callback.as_obj(),
                    "protectFd",
                    "(I)Z",
                    &[JValue::Int(fd as jint)],
                );
                match result {
                    Ok(value) => {
                        if !value.z().unwrap_or(false) {
                            tracing::warn!(fd, "VpnService.protect returned false");
                        }
                    }
                    Err(e) => {
                        if env.exception_check().unwrap_or(false) {
                            let _ = env.exception_clear();
                        }
                        tracing::warn!(fd, error = %e, "protectFd call failed");
                    }
                }
            }
            Err(e) => tracing::warn!(fd, error = %e, "JVM attach failed in protect hook"),
        }
    }))
}

fn to_jstring(env: &JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn from_jstring(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `deriveIdentity(nsec)` → JSON `{nsec, npub, address}` (generates when
/// `nsec` is empty) or `{"error": "..."}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_deriveIdentity(
    mut env: JNIEnv,
    _class: JClass,
    nsec: JString,
) -> jstring {
    let nsec = from_jstring(&mut env, &nsec);
    let json = match crate::config::derive_identity(&nsec) {
        Ok(info) => serde_json::to_string(&info).unwrap_or_default(),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    };
    to_jstring(&env, &json)
}

/// `start(configJson, tunFd, callback)` → `""` on success, error message
/// otherwise. `callback.protectFd(int)` is invoked for every underlay socket.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_start(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
    tun_fd: jint,
    callback: JObject,
) -> jstring {
    let config = from_jstring(&mut env, &config_json);
    let protect = protect_hook_from(&mut env, &callback);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::engine::start(&config, tun_fd, protect)
    }));
    let message = match result {
        Ok(Ok(_info)) => String::new(),
        Ok(Err(e)) => e,
        Err(_) => "panic in engine start".to_string(),
    };
    to_jstring(&env, &message)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_stop(_env: JNIEnv, _class: JClass) {
    let _ = std::panic::catch_unwind(crate::engine::stop);
}

/// `dnsServer()` → the in-tunnel DNS server address to hand
/// `VpnService.Builder.addDnsServer` (the `fd00::/8` sentinel, not the node
/// address — see `engine::DNS_SENTINEL`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_dnsServer(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&env, &crate::engine::dns_server_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_isRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    crate::engine::is_running() as jboolean
}

/// `onNetworkChanged(tunFd)` — rebuild the node on the same TUN fd after the
/// underlying network switched (Wi-Fi ↔ cellular). Blocking; call off the
/// main thread. No-op when not running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_onNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
) {
    let _ = std::panic::catch_unwind(|| {
        if let Err(e) = crate::engine::network_changed(tun_fd) {
            tracing::warn!(error = %e, "onNetworkChanged failed");
        }
    });
}

/// `status()` → JSON (see [`crate::engine::status_json`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_status(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&env, &crate::engine::status_json())
}

/// `resolveNpub(npub)` → JSON `{npub, address}` (the `.fips` mesh address) or
/// `{"error": "..."}`. Pure computation; works whether or not the node runs.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_resolveNpub(
    mut env: JNIEnv,
    _class: JClass,
    npub: JString,
) -> jstring {
    let npub = from_jstring(&mut env, &npub);
    let json = match crate::config::resolve_npub(&npub) {
        Ok((npub, address)) => serde_json::json!({ "npub": npub, "address": address }).to_string(),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    };
    to_jstring(&env, &json)
}

/// `recentLogs(maxLines)` → the most recent node log lines, newline-joined.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_recentLogs(
    env: JNIEnv,
    _class: JClass,
    max_lines: jint,
) -> jstring {
    let max = max_lines.max(0) as usize;
    to_jstring(&env, &crate::logbuf::recent(max))
}

/// `query(command, paramsJson)` → any snapshot-served `show_*` result.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_query(
    mut env: JNIEnv,
    _class: JClass,
    command: JString,
    params_json: JString,
) -> jstring {
    let command = from_jstring(&mut env, &command);
    let params = from_jstring(&mut env, &params_json);
    to_jstring(&env, &crate::engine::query_json(&command, &params))
}
