//! JNI surface for `org.fips.android.FipsNative` (Kotlin `external fun`s).
//!
//! Compiled on every platform (the `jni` crate is portable) so host builds
//! type-check it; only the Android app actually loads it. All entry points
//! catch errors and return them as strings — nothing panics across the FFI
//! boundary.

use jni::JNIEnv;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use std::sync::Arc;

/// Build the socket-protect hook from the Java callback object (the
/// `FipsVpnService`): each underlay fd is passed to its
/// `protectFd(int): Boolean` method. Fires from arbitrary Rust threads, so
/// the hook owns a `JavaVM` reference and attaches on demand.
fn protect_hook_from(env: &mut JNIEnv, callback: &JObject) -> Option<crate::SocketProtect> {
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

/// Run `f`, turning a panic into `fallback`. Every export goes through this
/// or its own `catch_unwind`: a panic that unwinds out of an
/// `extern "system"` fn aborts the process — with the VPN up.
fn guarded<T>(fallback: impl FnOnce() -> T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| fallback())
}

fn error_json(what: &str) -> String {
    serde_json::json!({ "error": format!("panic in {what}") }).to_string()
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
    let json = guarded(
        || error_json("deriveIdentity"),
        || match crate::config::derive_identity(&nsec) {
            Ok(info) => serde_json::to_string(&info).unwrap_or_default(),
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        },
    );
    to_jstring(&env, &json)
}

/// `start(configJson, tunFd, callback)` → `""` on success, error message
/// otherwise. `callback.protectFd(int)` is invoked for each UDP listen
/// socket of the node and every socket the shim dials itself.
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
    guarded(|| false, crate::engine::is_running) as jboolean
}

/// `onNetworkChanged(tunFd, configJson)` — follow a rebind: a tunnel
/// re-established with different routes or allowed apps (same config: the
/// pump moves onto `tunFd`, the node keeps running) or a FIPS Hotspot that
/// came or went (changed config: the node restarts on `tunFd`). `configJson`
/// is the freshly regenerated shim config (empty/null keeps the previous
/// one). Blocking; call off the main thread. No-op when not running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_onNetworkChanged(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) {
    let config = if config_json.is_null() {
        String::new()
    } else {
        from_jstring(&mut env, &config_json)
    };
    let _ = std::panic::catch_unwind(|| {
        let config = (!config.trim().is_empty()).then_some(config.as_str());
        if let Err(e) = crate::engine::network_changed(tun_fd, config) {
            tracing::warn!(error = %e, "onNetworkChanged failed");
        }
    });
}

/// `networkHint()`: wake the medium-change detector now (see
/// [`crate::engine::network_hint`]). Non-blocking; no-op when not running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_networkHint(_env: JNIEnv, _class: JClass) {
    let _ = std::panic::catch_unwind(crate::engine::network_hint);
}

/// `namesOnline(online)`: the public-names resolver's Internet flag (see
/// [`crate::engine::names_online`]). Non-blocking; no-op when not running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_namesOnline(
    _env: JNIEnv,
    _class: JClass,
    online: jni::sys::jboolean,
) {
    let _ = std::panic::catch_unwind(|| crate::engine::names_online(online != 0));
}

/// `status()` → JSON (see [`crate::engine::status_json`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_status(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // A panic reads as "not running", the one shape every caller handles.
    let json = guarded(
        || r#"{"running":false,"error":"panic in status"}"#.to_string(),
        crate::engine::status_json,
    );
    to_jstring(&env, &json)
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
    let json = guarded(
        || error_json("resolveNpub"),
        || match crate::config::resolve_npub(&npub) {
            Ok((npub, address)) => {
                serde_json::json!({ "npub": npub, "address": address }).to_string()
            }
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        },
    );
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
    to_jstring(&env, &guarded(String::new, || crate::logbuf::recent(max)))
}

/// `connectPeer(npub, address)` → the node's `connect` command response
/// (`{"status":"ok"|"error", ...}`). Manual UDP dial of an mDNS-seen peer;
/// blocking, call off the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_connectPeer(
    mut env: JNIEnv,
    _class: JClass,
    npub: JString,
    address: JString,
) -> jstring {
    let npub = from_jstring(&mut env, &npub);
    let address = from_jstring(&mut env, &address);
    let json = std::panic::catch_unwind(|| crate::engine::connect_peer_json(&npub, &address))
        .unwrap_or_else(|_| {
            serde_json::json!({ "status": "error", "message": "panic in connect" }).to_string()
        });
    to_jstring(&env, &json)
}

/// `meshHttpGet(npub, port, path, headersJson, timeoutMs)` → see
/// [`crate::engine::mesh_http_get_json`]. Blocking; call off the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_meshHttpGet(
    mut env: JNIEnv,
    _class: JClass,
    npub: JString,
    port: jint,
    path: JString,
    headers_json: JString,
    timeout_ms: jint,
) -> jstring {
    let npub = from_jstring(&mut env, &npub);
    let path = from_jstring(&mut env, &path);
    let headers = from_jstring(&mut env, &headers_json);
    let port = u16::try_from(port).unwrap_or(0);
    let timeout = std::time::Duration::from_millis(timeout_ms.clamp(1000, 120_000) as u64);
    let json = std::panic::catch_unwind(|| {
        crate::engine::mesh_http_get_json(&npub, port, &path, &headers, timeout)
    })
    .unwrap_or_else(|_| {
        serde_json::json!({ "error": "panic in meshHttpGet", "unreachable": false }).to_string()
    });
    to_jstring(&env, &json)
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
    let json = guarded(
        || r#"{"status":"error","message":"panic in query"}"#.to_string(),
        || crate::engine::query_json(&command, &params),
    );
    to_jstring(&env, &json)
}

/// `exitProbe(timeoutMs)` → JSON, see [`crate::engine::exit_probe_json`].
/// Blocking (up to twice the timeout); call off the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_exitProbe(
    env: JNIEnv,
    _class: JClass,
    timeout_ms: jint,
) -> jstring {
    let timeout = std::time::Duration::from_millis(timeout_ms.clamp(500, 10_000) as u64);
    let json = std::panic::catch_unwind(|| crate::engine::exit_probe_json(timeout))
        .unwrap_or_else(|_| serde_json::json!({ "error": "panic in exitProbe" }).to_string());
    to_jstring(&env, &json)
}

/// `findExits(timeoutMs)` → JSON, see [`crate::engine::find_exits_json`].
/// Blocking; call off the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_findExits(
    env: JNIEnv,
    _class: JClass,
    timeout_ms: jint,
) -> jstring {
    let timeout = std::time::Duration::from_millis(timeout_ms.clamp(1000, 30_000) as u64);
    let json = std::panic::catch_unwind(|| crate::engine::find_exits_json(timeout))
        .unwrap_or_else(|_| serde_json::json!({ "error": "panic in findExits" }).to_string());
    to_jstring(&env, &json)
}

// ============================================================================
// Bluetooth: the app's radio (see `ble.rs`)
// ============================================================================

/// The Kotlin radio (`BleRadio`), as fips's commands reach it. Called from
/// the node's runtime thread, so each call attaches on demand, like the
/// protect hook; the Kotlin methods return at once and do their work on
/// their own threads.
struct JniRadio {
    vm: jni::JavaVM,
    radio: GlobalRef,
}

impl JniRadio {
    /// Call `name` on the radio. A Java exception is cleared and logged:
    /// one left pending would abort the next JNI call on this thread.
    fn call(&self, name: &str, sig: &str, args: &[JValue]) -> Option<jint> {
        let mut env = match self.vm.attach_current_thread_permanently() {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(call = name, error = %e, "JVM attach failed for the Bluetooth radio");
                return None;
            }
        };
        match env.call_method(self.radio.as_obj(), name, sig, args) {
            Ok(value) => Some(value.i().unwrap_or(0)),
            Err(e) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                tracing::warn!(call = name, error = %e, "Bluetooth radio call failed");
                None
            }
        }
    }
}

impl crate::ble::RadioCommands for JniRadio {
    fn listen(&self) -> u16 {
        self.call("bleListen", "()I", &[])
            .and_then(|psm| u16::try_from(psm).ok())
            .unwrap_or(0)
    }
    fn connect(&self, connect_id: i64, addr: crate::ble::Mac, psm: u16) {
        let Ok(env) = self.vm.attach_current_thread_permanently() else {
            return;
        };
        let Ok(bytes) = env.byte_array_from_slice(&addr) else {
            return;
        };
        self.call(
            "bleConnect",
            "(J[BI)V",
            &[
                JValue::Long(connect_id),
                JValue::Object(&bytes),
                JValue::Int(jint::from(psm)),
            ],
        );
        // This thread stays attached for the life of the node, so nothing
        // ever pops its local references: free this one by hand.
        let _ = env.delete_local_ref(bytes);
    }
    fn start_advertising(&self, psm: u16) {
        self.call("bleStartAdvertising", "(I)V", &[JValue::Int(jint::from(psm))]);
    }
    fn stop_advertising(&self) {
        self.call("bleStopAdvertising", "()V", &[]);
    }
    fn start_scanning(&self) {
        self.call("bleStartScanning", "()V", &[]);
    }
    fn stop_scanning(&self) {
        self.call("bleStopScanning", "()V", &[]);
    }
    fn close_channel(&self, ch_id: i64) {
        self.call("bleCloseChannel", "(J)V", &[JValue::Long(ch_id)]);
    }
}

/// A 6-byte device address out of a Java `byte[]`; `None` for any other
/// length.
fn mac_from(env: &mut JNIEnv, addr: &JByteArray) -> Option<crate::ble::Mac> {
    env.convert_byte_array(addr).ok()?.try_into().ok()
}

fn mtu(value: jint) -> u16 {
    u16::try_from(value).unwrap_or(0)
}

/// `bleInstall(radio)` — the app's radio is up: fips may command it. Call
/// again with a new object to replace it. The node need not be running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleInstall(
    env: JNIEnv,
    _class: JClass,
    radio: JObject,
) {
    let handle = if radio.is_null() {
        None
    } else {
        match (env.get_java_vm(), env.new_global_ref(&radio)) {
            (Ok(vm), Ok(radio)) => Some(JniRadio { vm, radio }),
            _ => None,
        }
    };
    guarded(
        || (),
        || {
            crate::ble::GLOBAL.set_radio(
                handle.map(|r| Arc::new(r) as Arc<dyn crate::ble::RadioCommands>),
            )
        },
    );
}

/// `bleClear()` — the radio is gone (Bluetooth off, a permission withdrawn,
/// the setting turned off). Every channel it had reads as closed from now.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleClear(_env: JNIEnv, _class: JClass) {
    guarded(|| (), || crate::ble::GLOBAL.set_radio(None));
}

/// `bleInbound(addr, sendMtu, recvMtu)` → the channel id for a peer that
/// connected to our listener, or 0: close the socket.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleInbound(
    mut env: JNIEnv,
    _class: JClass,
    addr: JByteArray,
    send_mtu: jint,
    recv_mtu: jint,
) -> jlong {
    let Some(addr) = mac_from(&mut env, &addr) else {
        return 0;
    };
    guarded(
        || 0,
        || crate::ble::GLOBAL.inbound(addr, mtu(send_mtu), mtu(recv_mtu)),
    )
}

/// `bleConnectResult(connectId, ok, addr, sendMtu, recvMtu)` → the channel
/// id for a dial that succeeded, or 0 (it failed, or fips stopped waiting):
/// close the socket.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleConnectResult(
    mut env: JNIEnv,
    _class: JClass,
    connect_id: jlong,
    ok: jboolean,
    addr: JByteArray,
    send_mtu: jint,
    recv_mtu: jint,
) -> jlong {
    let Some(addr) = mac_from(&mut env, &addr) else {
        return 0;
    };
    guarded(
        || 0,
        || {
            crate::ble::GLOBAL.connect_result(
                connect_id,
                ok != 0,
                addr,
                mtu(send_mtu),
                mtu(recv_mtu),
            )
        },
    )
}

/// `bleScan(addr, psm, rssi)` — one FIPS advert. `psm` 0 when it carried
/// none; `rssi` outside an `i16` (pass `Int.MIN_VALUE`) when unknown.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleScan(
    mut env: JNIEnv,
    _class: JClass,
    addr: JByteArray,
    psm: jint,
    rssi: jint,
) {
    let Some(addr) = mac_from(&mut env, &addr) else {
        return;
    };
    guarded(
        || (),
        || crate::ble::GLOBAL.scan(addr, mtu(psm), i16::try_from(rssi).ok()),
    );
}

/// `bleRecv(chId, data, len)` → false when the channel is gone: stop
/// reading and close the socket. Blocks while fips is behind — call it from
/// the channel's own reader thread, never the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleRecv(
    env: JNIEnv,
    _class: JClass,
    ch_id: jlong,
    data: JByteArray,
    len: jint,
) -> jboolean {
    let len = usize::try_from(len).unwrap_or(0);
    if len == 0 {
        // Nothing read. Not passed on: fips reads an empty chunk as the
        // peer having closed.
        return guarded(|| false, || crate::ble::GLOBAL.channel_open(ch_id)) as jboolean;
    }
    // Only the bytes read, not the whole read buffer (a channel's is as
    // large as its biggest packet may be, tens of kilobytes).
    let mut bytes = vec![0i8; len];
    if env.get_byte_array_region(&data, 0, &mut bytes).is_err() {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        return 0;
    }
    let bytes: Vec<u8> = bytes.into_iter().map(|b| b as u8).collect();
    guarded(|| false, || crate::ble::GLOBAL.recv(ch_id, &bytes)) as jboolean
}

/// `bleNextSend(chId, timeoutMs)` → the next packet to write, or null:
/// nothing within the timeout, or the channel is gone (`bleChannelOpen`
/// tells which). Blocks up to the timeout — the channel's writer thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleNextSend(
    env: JNIEnv,
    _class: JClass,
    ch_id: jlong,
    timeout_ms: jint,
) -> jbyteArray {
    let timeout = std::time::Duration::from_millis(u64::try_from(timeout_ms).unwrap_or(0));
    let packet = guarded(|| None, || crate::ble::GLOBAL.next_send(ch_id, timeout));
    packet
        .and_then(|p| env.byte_array_from_slice(&p).ok())
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `bleChannelOpen(chId)` → whether fips still holds the channel.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleChannelOpen(
    _env: JNIEnv,
    _class: JClass,
    ch_id: jlong,
) -> jboolean {
    guarded(|| false, || crate::ble::GLOBAL.channel_open(ch_id)) as jboolean
}

/// `bleChannelClosed(chId)` — the socket closed (the peer left, an error).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_android_FipsNative_bleChannelClosed(
    _env: JNIEnv,
    _class: JClass,
    ch_id: jlong,
) {
    guarded(|| (), || crate::ble::GLOBAL.channel_closed(ch_id));
}
