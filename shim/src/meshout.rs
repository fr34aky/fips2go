//! The mesh → app half of the TCP MSS clamp.
//!
//! fips documents the contract of `Node::enable_app_owned_tun`: the embedder
//! clamps the TCP MSS on SYN-flagged segments in both directions. Outbound
//! is the node's own `TunPacketProcessor` (from the fips fork), because the
//! right ceiling there is per destination: the path MTU the node has learned,
//! which on a Bluetooth link is routinely below the IPv6 minimum, where no
//! Packet Too Big brings a phone's TCP down to it. That map is the node's,
//! and upstream fips does not hand it to an embedder.
//!
//! Inbound nobody clamped: the processor covers what goes out only, while
//! the daemon's system-TUN writer also clamps what comes in. This is that
//! half, as an upper bound: [`max_mss`] is the segment of a 1280-byte path,
//! which every hop must carry. A peer that announces less keeps its value
//! (its own node clamps what it sends for the path it knows); one that
//! announces more is held to this.

use fips::ipv6tun::icmp::mss_ceiling;
use fips::ipv6tun::tcp_mss::clamp_tcp_mss;

/// The IPv6 minimum link MTU: the wire size every mesh path carries.
const MIN_PATH_MTU: u16 = 1280;

/// Largest TCP segment that fits a 1280-byte mesh path (1143).
pub fn max_mss() -> u16 {
    mss_ceiling(MIN_PATH_MTU)
}

/// Clamp the MSS a mesh peer announced in a SYN or SYN-ACK, so this side
/// never sends it a segment a 1280-byte path cannot carry. Anything that is
/// not such a segment is left as it is.
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
    fn an_inbound_syn_is_clamped_and_still_checksums() {
        let mut packet = syn(PEER, ME, 1400);
        clamp_inbound(&mut packet);
        assert_eq!(mss_of(&packet), 1143);
        assert_eq!(checksum(&packet), 0, "checksum fixed up after the clamp");
    }

    #[test]
    fn a_smaller_mss_is_left_alone() {
        let mut packet = syn(PEER, ME, 400);
        let before = packet.clone();
        clamp_inbound(&mut packet);
        assert_eq!(packet, before);
    }

    #[test]
    fn what_is_not_a_tcp_syn_is_left_alone() {
        let mut udp = crate::packet::build_ipv6_udp(PEER, ME, 53, 4000, b"x");
        let before = udp.clone();
        clamp_inbound(&mut udp);
        assert_eq!(udp, before);

        // IPv4-in-IPv6 from an exit: `exit.rs` clamps the inner TCP.
        let mut tunnel = vec![0u8; 80];
        tunnel[0] = 0x60;
        tunnel[4..6].copy_from_slice(&40u16.to_be_bytes());
        tunnel[6] = 4;
        let before = tunnel.clone();
        clamp_inbound(&mut tunnel);
        assert_eq!(tunnel, before);

        let mut short = [0x60u8; 20];
        clamp_inbound(&mut short);
        assert_eq!(short, [0x60u8; 20]);
    }
}
