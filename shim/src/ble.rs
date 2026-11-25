//! Bluetooth (BLE) as a fips transport, with the radio in the app.
//!
//! fips has a BLE transport: nodes advertise a service UUID, find each other
//! by scanning, and link over an L2CAP channel. On Android every part of that
//! — scanning, advertising, the L2CAP sockets — is a Java API behind runtime
//! permissions, so fips does not open a radio there. It drives one the
//! embedder supplies, through a small command trait and a bridge
//! (`fips::transport::ble::io_radio`): commands go up to the app, and the app
//! reports adverts, connections and bytes back down.
//!
//! This module is that seam on the shim's side:
//!
//! - [`RadioCommands`] is what the Kotlin radio answers (through JNI, see
//!   `jni_api.rs`).
//! - [`Ble`] holds the radio the app installed and the node's slot for one,
//!   and joins the two whenever both exist. Either can come or go alone: the
//!   user turns Bluetooth on after the mesh is up, or the node restarts under
//!   a radio that keeps running. Neither is a reason to restart the other.
//! - The `deliver`-side calls ([`Ble::inbound`], [`Ble::recv`], …) route what
//!   the app reports to the bridge currently installed.
//!
//! # Identifiers carry a generation
//!
//! Each joining of radio and node builds a fresh fips bridge, and a bridge
//! numbers its channels and dials from 1. The app may still hold sockets from
//! the bridge before, with reader and writer threads that know their channel
//! by number. So every identifier that crosses to the app is tagged with the
//! generation of the bridge it belongs to ([`tag`]), and a call that names an
//! older generation is answered as "that channel is gone" — which is what
//! makes those threads close their sockets — instead of landing on whichever
//! channel has the same number now.
//!
//! # What decides when the radio is used
//!
//! Not this module, and not fips: fips asks for scanning and advertising for
//! as long as the transport runs, and probes every advert it is shown. A
//! phone cannot afford that. `start_scanning` is therefore a statement that
//! scanning is wanted; the Kotlin radio decides when the chip actually scans
//! (only while the node has no link, filtered in the controller, low power),
//! and an advert it does not report is a connection fips never makes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A Bluetooth device address.
pub type Mac = [u8; 6];

/// The commands fips gives the radio. Every one returns at once; what takes
/// time is reported back later ([`Ble::connect_result`], [`Ble::inbound`],
/// [`Ble::scan`]). Called from the node's runtime thread, so an
/// implementation must not block.
pub trait RadioCommands: Send + Sync {
    /// Open the L2CAP listener and return the PSM the platform bound it to,
    /// or 0 if it could not be opened.
    fn listen(&self) -> u16;
    /// Start dialing `addr` on `psm`; answer with [`Ble::connect_result`].
    fn connect(&self, connect_id: i64, addr: Mac, psm: u16);
    /// Advertise the FIPS service, carrying `psm` for peers to dial.
    fn start_advertising(&self, psm: u16);
    fn stop_advertising(&self);
    /// Scanning is wanted; report adverts with [`Ble::scan`].
    fn start_scanning(&self);
    fn stop_scanning(&self);
    /// fips dropped this channel: close its socket.
    fn close_channel(&self, ch_id: i64);
}

/// One installed bridge, as this module uses it. Identifiers here are the
/// bridge's own (untagged). Implemented over fips's bridge on Android and by
/// a mock in the tests, since fips compiles its bridge only there.
pub trait Link: Send + Sync {
    fn inbound(&self, addr: Mac, send_mtu: u16, recv_mtu: u16) -> i64;
    fn connect_result(
        &self,
        connect_id: i64,
        ok: bool,
        addr: Mac,
        send_mtu: u16,
        recv_mtu: u16,
    ) -> i64;
    fn scan(&self, addr: Mac, psm: u16, rssi: Option<i16>);
    fn recv(&self, ch_id: i64, data: &[u8]) -> bool;
    fn next_send(&self, ch_id: i64, timeout: Duration) -> Option<Vec<u8>>;
    fn channel_open(&self, ch_id: i64) -> bool;
    fn channel_closed(&self, ch_id: i64);
}

/// A node's place for a radio (fips's `BleRadioSlot`).
pub trait Mount: Send + Sync {
    /// Build a bridge over `radio` and install it, replacing any other.
    fn install(&self, radio: Arc<dyn RadioCommands>) -> Arc<dyn Link>;
    /// Remove the installed bridge.
    fn clear(&self);
}

/// Bits of a tagged identifier that hold the bridge's own number. A bridge
/// counts up from 1 for every channel and dial; 2^40 of them is out of reach.
const ID_BITS: u32 = 40;
const ID_MASK: i64 = (1 << ID_BITS) - 1;
/// Generations wrap within what is left of a positive `i64`.
const GEN_MASK: u32 = (1 << (63 - ID_BITS)) - 1;

/// `id` as the app sees it: the bridge's number under its generation. 0 (the
/// bridge's "no channel") and anything out of range stay 0.
fn tag(generation: u32, id: i64) -> i64 {
    if id <= 0 || id > ID_MASK {
        return 0;
    }
    (i64::from(generation) << ID_BITS) | id
}

/// The generation and the bridge's own number in a tagged identifier.
fn untag(tagged: i64) -> Option<(u32, i64)> {
    if tagged <= 0 {
        return None;
    }
    let id = tagged & ID_MASK;
    (id != 0).then_some(((tagged >> ID_BITS) as u32, id))
}

/// The app's radio as one bridge sees it: identifiers going up are tagged
/// with that bridge's generation.
struct Tagged {
    generation: u32,
    radio: Arc<dyn RadioCommands>,
}

impl RadioCommands for Tagged {
    fn listen(&self) -> u16 {
        self.radio.listen()
    }
    fn connect(&self, connect_id: i64, addr: Mac, psm: u16) {
        self.radio
            .connect(tag(self.generation, connect_id), addr, psm);
    }
    fn start_advertising(&self, psm: u16) {
        self.radio.start_advertising(psm);
    }
    fn stop_advertising(&self) {
        self.radio.stop_advertising();
    }
    fn start_scanning(&self) {
        self.radio.start_scanning();
    }
    fn stop_scanning(&self) {
        self.radio.stop_scanning();
    }
    fn close_channel(&self, ch_id: i64) {
        self.radio.close_channel(tag(self.generation, ch_id));
    }
}

#[derive(Default)]
struct State {
    /// The radio the app installed, kept across node restarts.
    radio: Option<Arc<dyn RadioCommands>>,
    /// The running node's slot, if it was started with BLE.
    mount: Option<Arc<dyn Mount>>,
    /// The bridge joining the two, and its generation.
    link: Option<(u32, Arc<dyn Link>)>,
    generation: u32,
}

/// The radio seam: see the module docs.
#[derive(Default)]
pub struct Ble {
    state: Mutex<State>,
}

/// The process's one seam, shared by the engine and the JNI exports.
pub static GLOBAL: Ble = Ble {
    state: Mutex::new(State {
        radio: None,
        mount: None,
        link: None,
        generation: 0,
    }),
};

impl Ble {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The app's radio came up (`Some`) or went away (`None`: Bluetooth off,
    /// a permission withdrawn, the setting turned off).
    pub fn set_radio(&self, radio: Option<Arc<dyn RadioCommands>>) {
        let mut s = self.state();
        s.radio = radio;
        Self::join(&mut s);
    }

    /// A node started with BLE: `mount` is where its radio goes.
    pub fn attach(&self, mount: Arc<dyn Mount>) {
        let mut s = self.state();
        s.mount = Some(mount);
        Self::join(&mut s);
    }

    /// The node is gone. The radio stays for the next one; what the app
    /// still holds from this one is answered as gone.
    pub fn detach(&self) {
        let mut s = self.state();
        s.mount = None;
        s.link = None;
    }

    /// True while a radio is installed in a running node.
    pub fn active(&self) -> bool {
        self.state().link.is_some()
    }

    /// Bring the bridge in line with what exists now. Always a new
    /// generation: a bridge is never reused across a change of either side.
    fn join(s: &mut State) {
        let had_link = s.link.take().is_some();
        let Some(mount) = s.mount.clone() else {
            return;
        };
        match s.radio.clone() {
            Some(radio) => {
                s.generation = (s.generation + 1) & GEN_MASK;
                let generation = s.generation;
                let link = mount.install(Arc::new(Tagged { generation, radio }));
                s.link = Some((generation, link));
                tracing::info!(generation, "Bluetooth radio installed");
            }
            None if had_link => {
                mount.clear();
                tracing::info!("Bluetooth radio removed");
            }
            None => {}
        }
    }

    /// The current bridge. Cloned out so no call into it holds the lock —
    /// [`Self::next_send`] and [`Self::recv`] block.
    fn link(&self) -> Option<(u32, Arc<dyn Link>)> {
        self.state().link.clone()
    }

    /// The current bridge and the bridge's own number for `tagged`, if
    /// `tagged` belongs to it.
    fn link_of(&self, tagged: i64) -> Option<(Arc<dyn Link>, i64)> {
        let (generation, id) = untag(tagged)?;
        let (current, link) = self.link()?;
        (generation == current).then_some((link, id))
    }

    /// A peer connected to our listener. Returns the channel identifier, or
    /// 0: close the socket.
    pub fn inbound(&self, addr: Mac, send_mtu: u16, recv_mtu: u16) -> i64 {
        match self.link() {
            Some((generation, link)) => tag(generation, link.inbound(addr, send_mtu, recv_mtu)),
            None => 0,
        }
    }

    /// The outcome of a dial. Returns the channel identifier on success, or
    /// 0 (failed, or nobody waits for it any more): close the socket.
    pub fn connect_result(
        &self,
        connect_id: i64,
        ok: bool,
        addr: Mac,
        send_mtu: u16,
        recv_mtu: u16,
    ) -> i64 {
        let Some((generation, id)) = untag(connect_id) else {
            return 0;
        };
        match self.link() {
            Some((current, link)) if current == generation => tag(
                generation,
                link.connect_result(id, ok, addr, send_mtu, recv_mtu),
            ),
            _ => 0,
        }
    }

    /// One FIPS advert seen; `psm` 0 if it carried none.
    pub fn scan(&self, addr: Mac, psm: u16, rssi: Option<i16>) {
        if let Some((_, link)) = self.link() {
            link.scan(addr, psm, rssi);
        }
    }

    /// Bytes read from a channel. False: the channel is gone, stop reading.
    /// Blocks while fips is behind, so call it from the channel's own reader
    /// thread.
    pub fn recv(&self, ch_id: i64, data: &[u8]) -> bool {
        self.link_of(ch_id)
            .is_some_and(|(link, id)| link.recv(id, data))
    }

    /// The next packet to write to a channel, waiting up to `timeout`.
    /// `None` is "nothing yet" or "gone": [`Self::channel_open`] tells which.
    pub fn next_send(&self, ch_id: i64, timeout: Duration) -> Option<Vec<u8>> {
        let (link, id) = self.link_of(ch_id)?;
        link.next_send(id, timeout)
    }

    pub fn channel_open(&self, ch_id: i64) -> bool {
        self.link_of(ch_id)
            .is_some_and(|(link, id)| link.channel_open(id))
    }

    /// The app closed a channel's socket (the peer went away, or an error).
    pub fn channel_closed(&self, ch_id: i64) {
        if let Some((link, id)) = self.link_of(ch_id) {
            link.channel_closed(id);
        }
    }
}

/// The seam over fips's own types, which exist on Android only.
#[cfg(target_os = "android")]
pub mod android {
    use super::{Link, Mac, Mount, RadioCommands};
    use fips::transport::ble::addr::BleAddr;
    use fips::transport::ble::io_android::{AndroidBleBridge, AndroidRadio, BleRadioSlot};
    use fips::transport::ble::io_radio::RADIO_ADAPTER;
    use std::sync::Arc;
    use std::time::Duration;

    fn addr_of(device: Mac) -> BleAddr {
        BleAddr {
            adapter: RADIO_ADAPTER.to_string(),
            device,
        }
    }

    struct Radio(Arc<dyn RadioCommands>);

    impl AndroidRadio for Radio {
        fn listen(&self) -> u16 {
            self.0.listen()
        }
        fn connect(&self, connect_id: i64, addr: &BleAddr, psm: u16) {
            self.0.connect(connect_id, addr.device, psm);
        }
        fn start_advertising(&self, psm: u16) {
            self.0.start_advertising(psm);
        }
        fn stop_advertising(&self) {
            self.0.stop_advertising();
        }
        fn start_scanning(&self) {
            self.0.start_scanning();
        }
        fn stop_scanning(&self) {
            self.0.stop_scanning();
        }
        fn close_channel(&self, ch_id: i64) {
            self.0.close_channel(ch_id);
        }
    }

    struct Bridge(Arc<AndroidBleBridge>);

    impl Link for Bridge {
        fn inbound(&self, addr: Mac, send_mtu: u16, recv_mtu: u16) -> i64 {
            self.0.deliver_inbound(addr_of(addr), send_mtu, recv_mtu)
        }
        fn connect_result(
            &self,
            connect_id: i64,
            ok: bool,
            addr: Mac,
            send_mtu: u16,
            recv_mtu: u16,
        ) -> i64 {
            self.0
                .deliver_connect_result(connect_id, ok, addr_of(addr), send_mtu, recv_mtu)
        }
        fn scan(&self, addr: Mac, psm: u16, rssi: Option<i16>) {
            self.0.deliver_scan(addr_of(addr), psm, rssi);
        }
        fn recv(&self, ch_id: i64, data: &[u8]) -> bool {
            // An L2CAP socket is read as a stream of whole packets; one
            // dropped under load would desynchronise the framing above for
            // the rest of the link. Waiting pushes back on the peer instead.
            self.0.deliver_recv_blocking(ch_id, data)
        }
        fn next_send(&self, ch_id: i64, timeout: Duration) -> Option<Vec<u8>> {
            self.0.next_send(ch_id, timeout)
        }
        fn channel_open(&self, ch_id: i64) -> bool {
            self.0.channel_open(ch_id)
        }
        fn channel_closed(&self, ch_id: i64) {
            self.0.channel_closed(ch_id);
        }
    }

    /// A node's `BleRadioSlot` (`Node::enable_app_owned_ble_radio`).
    pub struct Slot(pub Arc<BleRadioSlot>);

    impl Mount for Slot {
        fn install(&self, radio: Arc<dyn RadioCommands>) -> Arc<dyn Link> {
            let bridge = AndroidBleBridge::new(Arc::new(Radio(radio)));
            self.0.install(bridge.clone());
            Arc::new(Bridge(bridge))
        }
        fn clear(&self) {
            self.0.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    /// What the "app" was told, with the identifiers as it saw them.
    #[derive(Default)]
    struct App {
        connects: Mutex<Vec<i64>>,
        closed: Mutex<Vec<i64>>,
        scans: AtomicUsize,
    }

    impl RadioCommands for App {
        fn listen(&self) -> u16 {
            0x81
        }
        fn connect(&self, connect_id: i64, _: Mac, _: u16) {
            self.connects.lock().unwrap().push(connect_id);
        }
        fn start_advertising(&self, _: u16) {}
        fn stop_advertising(&self) {}
        fn start_scanning(&self) {
            self.scans.fetch_add(1, Ordering::SeqCst);
        }
        fn stop_scanning(&self) {}
        fn close_channel(&self, ch_id: i64) {
            self.closed.lock().unwrap().push(ch_id);
        }
    }

    /// A bridge that numbers channels from 1, like fips's, and remembers
    /// what reached it.
    struct Bridge {
        radio: Arc<dyn RadioCommands>,
        next: AtomicI64,
        received: Mutex<Vec<(i64, Vec<u8>)>>,
        closed: Mutex<Vec<i64>>,
    }

    impl Link for Bridge {
        fn inbound(&self, _: Mac, _: u16, _: u16) -> i64 {
            self.next.fetch_add(1, Ordering::SeqCst)
        }
        fn connect_result(&self, _: i64, ok: bool, _: Mac, _: u16, _: u16) -> i64 {
            if ok {
                self.next.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            }
        }
        fn scan(&self, _: Mac, _: u16, _: Option<i16>) {}
        fn recv(&self, ch_id: i64, data: &[u8]) -> bool {
            self.received.lock().unwrap().push((ch_id, data.to_vec()));
            true
        }
        fn next_send(&self, ch_id: i64, _: Duration) -> Option<Vec<u8>> {
            Some(vec![ch_id as u8])
        }
        fn channel_open(&self, _: i64) -> bool {
            true
        }
        fn channel_closed(&self, ch_id: i64) {
            self.closed.lock().unwrap().push(ch_id);
        }
    }

    /// A node's slot: keeps every bridge installed in it.
    #[derive(Default)]
    struct Node {
        bridges: Mutex<Vec<Arc<Bridge>>>,
        cleared: AtomicUsize,
    }

    impl Node {
        fn bridge(&self) -> Arc<Bridge> {
            self.bridges.lock().unwrap().last().unwrap().clone()
        }
    }

    impl Mount for Node {
        fn install(&self, radio: Arc<dyn RadioCommands>) -> Arc<dyn Link> {
            let bridge = Arc::new(Bridge {
                radio,
                next: AtomicI64::new(1),
                received: Default::default(),
                closed: Default::default(),
            });
            self.bridges.lock().unwrap().push(bridge.clone());
            bridge
        }
        fn clear(&self) {
            self.cleared.fetch_add(1, Ordering::SeqCst);
        }
    }

    const PEER: Mac = [1, 2, 3, 4, 5, 6];

    #[test]
    fn tags_round_trip_and_zero_stays_zero() {
        assert_eq!(untag(tag(3, 7)), Some((3, 7)));
        assert_eq!(untag(tag(GEN_MASK, ID_MASK)), Some((GEN_MASK, ID_MASK)));
        assert!(tag(GEN_MASK, ID_MASK) > 0, "never negative: 0 and below mean failure");
        assert_eq!(tag(3, 0), 0, "the bridge's \"no channel\"");
        assert_eq!(tag(3, -1), 0);
        assert_eq!(tag(3, ID_MASK + 1), 0);
        assert_eq!(untag(0), None);
        assert_eq!(untag(-5), None);
        assert_ne!(tag(1, 1), tag(2, 1), "the same number under two bridges");
    }

    /// The radio and the node may arrive in either order, and nothing is
    /// installed until both are there.
    #[test]
    fn the_bridge_exists_once_radio_and_node_both_do() {
        for radio_first in [true, false] {
            let (ble, app, node) = (Ble::default(), Arc::new(App::default()), Arc::new(Node::default()));
            if radio_first {
                ble.set_radio(Some(app.clone()));
            } else {
                ble.attach(node.clone());
            }
            assert!(!ble.active());
            assert_eq!(ble.inbound(PEER, 100, 100), 0, "nothing to accept it");
            if radio_first {
                ble.attach(node.clone());
            } else {
                ble.set_radio(Some(app.clone()));
            }
            assert!(ble.active());
            assert_eq!(node.bridges.lock().unwrap().len(), 1);
            assert_ne!(ble.inbound(PEER, 100, 100), 0);
        }
    }

    /// Bytes and commands reach the bridge and the app under the right
    /// numbers: the bridge's own going down, tagged going up.
    #[test]
    fn identifiers_are_tagged_towards_the_app_and_plain_towards_the_bridge() {
        let (ble, app, node) = (Ble::default(), Arc::new(App::default()), Arc::new(Node::default()));
        ble.set_radio(Some(app.clone()));
        ble.attach(node.clone());
        let bridge = node.bridge();

        let ch = ble.inbound(PEER, 100, 100);
        assert_eq!(untag(ch).map(|(_, id)| id), Some(1));
        assert!(ble.recv(ch, b"hello"));
        assert_eq!(*bridge.received.lock().unwrap(), vec![(1, b"hello".to_vec())]);
        assert_eq!(ble.next_send(ch, Duration::ZERO), Some(vec![1]));
        assert!(ble.channel_open(ch));
        ble.channel_closed(ch);
        assert_eq!(*bridge.closed.lock().unwrap(), vec![1]);

        // fips dials and later drops a channel: the app sees tagged numbers,
        // and answers the dial with the one it was given.
        bridge.radio.connect(9, PEER, 0x81);
        let dial = app.connects.lock().unwrap()[0];
        assert_eq!(untag(dial).map(|(_, id)| id), Some(9));
        let ch2 = ble.connect_result(dial, true, PEER, 100, 100);
        assert_eq!(untag(ch2).map(|(_, id)| id), Some(2));
        assert_eq!(ble.connect_result(dial, false, PEER, 0, 0), 0);
        bridge.radio.close_channel(2);
        assert_eq!(*app.closed.lock().unwrap(), vec![ch2]);
    }

    /// A node restart under a running radio builds a new bridge that numbers
    /// from 1 again. What the app still holds from the old one must read as
    /// gone, not as the new bridge's channel 1.
    #[test]
    fn a_channel_of_an_earlier_bridge_is_gone_not_reused() {
        let (ble, app) = (Ble::default(), Arc::new(App::default()));
        let first = Arc::new(Node::default());
        ble.set_radio(Some(app.clone()));
        ble.attach(first.clone());
        let old = ble.inbound(PEER, 100, 100);
        first.bridge().radio.connect(4, PEER, 0x81);
        let old_dial = app.connects.lock().unwrap()[0];

        ble.detach();
        assert!(!ble.active());
        assert!(!ble.recv(old, b"x"), "no node: gone");

        let second = Arc::new(Node::default());
        ble.attach(second.clone());
        let new = ble.inbound(PEER, 100, 100);
        assert_eq!(untag(old).map(|(_, id)| id), untag(new).map(|(_, id)| id));
        assert_ne!(old, new);

        assert!(!ble.recv(old, b"stale"));
        assert_eq!(ble.next_send(old, Duration::ZERO), None);
        assert!(!ble.channel_open(old));
        ble.channel_closed(old);
        assert_eq!(ble.connect_result(old_dial, true, PEER, 100, 100), 0);
        let bridge = second.bridge();
        assert!(bridge.received.lock().unwrap().is_empty());
        assert!(bridge.closed.lock().unwrap().is_empty());
        assert!(ble.recv(new, b"fresh"));
    }

    /// Bluetooth off clears the node's slot; on again installs a new bridge
    /// in the same node.
    #[test]
    fn the_radio_going_away_clears_the_slot_and_coming_back_reinstalls() {
        let (ble, app, node) = (Ble::default(), Arc::new(App::default()), Arc::new(Node::default()));
        ble.attach(node.clone());
        ble.set_radio(Some(app.clone()));
        let ch = ble.inbound(PEER, 100, 100);

        ble.set_radio(None);
        assert!(!ble.active());
        assert_eq!(node.cleared.load(Ordering::SeqCst), 1);
        assert!(!ble.recv(ch, b"x"));

        ble.set_radio(Some(app));
        assert!(ble.active());
        assert_eq!(node.bridges.lock().unwrap().len(), 2);
        assert!(!ble.recv(ch, b"x"), "the old bridge's channel stays gone");
    }
}
