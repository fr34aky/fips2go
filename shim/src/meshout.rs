//! What the shim does to a mesh packet at the edge of the node's app-owned
//! TUN channels, in both directions.
//!
//! fips documents the contract of `Node::enable_app_owned_tun`: the embedder
//! pushes only `fd00::/8`-destined IPv6 packets, clamps the TCP MSS on
//! SYN-flagged segments in both directions, and gets ICMPv6 errors (no
//! route, Packet Too Big) back on the inbound channel. This module is that
//! contract's embedder half. It replaces the `TunPacketProcessor` the fips
//! fork used to hand out, so the shim needs nothing here that upstream fips
//! does not export.
//!
//! The ceiling is one constant, where the node's own system-TUN reader uses
//! a per-destination value: [`MAX_MSS`] is the segment that fits a 1280-byte
//! path, which every hop must carry and which is also what the node itself
//! applies to a destination it has not measured yet. A flow over a path the
//! node has learned to be wider no longer gets the larger segment (1220 at
//! most on this tunnel, whose MTU is 1280), and one over a path learned to
//! be narrower than 1280 is no longer clamped below it here: that is left
//! to the node, which splits or answers Packet Too Big.

use fips::ipv6tun::icmp::mss_ceiling;
use fips::ipv6tun::tcp_mss::clamp_tcp_mss;

/// First byte of every mesh address (`fd00::/8`).
const MESH_PREFIX: u8 = fips::identity::IPV6_ADDRESS_PREFIX;
/// The IPv6 minimum link MTU: the wire size every mesh path carries.
const MIN_PATH_MTU: u16 = 1280;

/// Largest TCP segment that fits a 1280-byte mesh path (1143).
pub fn max_mss() -> u16 {
    mss_ceiling(MIN_PATH_MTU)
}

/// What to do with a packet headed for the mesh.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Push it into the node's outbound channel (MSS clamped in place).
    Forward,
    /// Addressed to this node itself: the node has no route to itself, so
    /// the caller delivers it locally or reports it.
    Own,
    /// Not a mesh packet (not IPv6, truncated, or not for `fd00::/8`).
    Drop,
}

/// The outbound edge: cheap to clone, no state but this node's address.
#[derive(Clone, Debug)]
pub struct MeshOut {
    our_addr: [u8; 16],
}

impl MeshOut {
    pub fn new(our_addr: [u8; 16]) -> Self {
        Self { our_addr }
    }

    /// Decide one app → mesh packet; a SYN's MSS is clamped in place.
    pub fn process(&self, packet: &mut [u8]) -> Action {
        if packet.len() < 40 || packet[0] >> 4 != 6 || packet[24] != MESH_PREFIX {
            return Action::Drop;
        }
        if packet[24..40] == self.our_addr {
            return Action::Own;
        }
        clamp_tcp_mss(packet, max_mss());
        Action::Forward
    }
}

/// The inbound edge: clamp the MSS a mesh peer announced in a SYN or
/// SYN-ACK, so this side never sends it a segment a 1280-byte path cannot
/// carry. Anything that is not such a segment is left as it is.
pub fn clamp_inbound(packet: &mut [u8]) {
    if packet.len() >= 40 && packet[0] >> 4 == 6 {
        clamp_tcp_mss(packet, max_mss());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 16] = [0xfd, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
    const PEER: [u8; 16] = [0xfd, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];

    /// An IPv6 TCP SYN carrying one option, MSS = `mss`, valid checksum.
    fn syn(src: [u8; 16], dst: [u8; 16], mss: u16) -> Vec<u8> {
        let mut tcp = vec![0u8; 24];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 6 << 4; // data offset: 24 bytes
        tcp[13] = 0x02; // SYN
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());

        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet.extend_from_slice(&tcp);
        let sum = checksum(&packet);
        packet[40 + 16..40 + 18].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    /// TCP checksum over the IPv6 pseudo-header, checksum field as found.
    fn checksum(packet: &[u8]) -> u16 {
        let tcp = &packet[40..];
        let mut sum = 0u32;
        let mut add = |bytes: &[u8]| {
            for pair in bytes.chunks(2) {
                let hi = pair[0] as u32;
                let lo = *pair.get(1).unwrap_or(&0) as u32;
                sum += (hi << 8) | lo;
            }
        };
        add(&packet[8..40]);
        add(&(tcp.len() as u32).to_be_bytes());
        add(&[0, 0, 0, 6]);
        add(tcp);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn mss_of(packet: &[u8]) -> u16 {
        u16::from_be_bytes([packet[62], packet[63]])
    }

    #[test]
    fn the_ceiling_is_the_segment_of_a_1280_byte_path() {
        assert_eq!(max_mss(), 1143);
    }

    #[test]
    fn an_outbound_syn_is_clamped_and_still_checksums() {
        let out = MeshOut::new(ME);
        let mut packet = syn(ME, PEER, 1220);
        assert_eq!(out.process(&mut packet), Action::Forward);
        assert_eq!(mss_of(&packet), 1143);
        assert_eq!(checksum(&packet), 0, "checksum fixed up after the clamp");
    }

    #[test]
    fn a_smaller_mss_is_left_alone() {
        let out = MeshOut::new(ME);
        let mut packet = syn(ME, PEER, 1000);
        let before = packet.clone();
        assert_eq!(out.process(&mut packet), Action::Forward);
        assert_eq!(packet, before);
    }

    #[test]
    fn an_inbound_syn_is_clamped_too() {
        let mut packet = syn(PEER, ME, 1400);
        clamp_inbound(&mut packet);
        assert_eq!(mss_of(&packet), 1143);
        assert_eq!(checksum(&packet), 0);
    }

    #[test]
    fn this_nodes_own_address_is_not_forwarded() {
        let out = MeshOut::new(ME);
        let mut packet = syn(ME, ME, 1220);
        assert_eq!(out.process(&mut packet), Action::Own);
        assert_eq!(mss_of(&packet), 1220, "untouched");
    }

    #[test]
    fn what_is_not_a_mesh_packet_is_dropped() {
        let out = MeshOut::new(ME);
        let mut off_mesh = syn(ME, [0x20; 16], 1220);
        assert_eq!(out.process(&mut off_mesh), Action::Drop);
        assert_eq!(out.process(&mut [0x45u8; 60]), Action::Drop);
        assert_eq!(out.process(&mut [0x60u8; 20]), Action::Drop);
    }

    /// IPv4-in-IPv6 for an exit (next header 4) goes out as it came: the
    /// inner TCP is clamped by `exit.rs`, not here.
    #[test]
    fn exit_traffic_is_forwarded_unchanged() {
        let out = MeshOut::new(ME);
        let mut packet = vec![0u8; 80];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&40u16.to_be_bytes());
        packet[6] = 4;
        packet[8..24].copy_from_slice(&ME);
        packet[24..40].copy_from_slice(&PEER);
        let before = packet.clone();
        assert_eq!(out.process(&mut packet), Action::Forward);
        assert_eq!(packet, before);
    }
}
