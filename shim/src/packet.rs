//! Minimal IPv6/UDP packet construction and parsing for the DNS proxy.

/// Build an IPv6+UDP packet with a correct UDP checksum (mandatory over IPv6).
pub fn build_ipv6_udp(
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);

    let checksum = udp_checksum(&src, &dst, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut pkt = Vec::with_capacity(40 + udp_len);
    pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, TC 0, flow 0
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.push(17); // next header: UDP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&udp);
    pkt
}

fn udp_checksum(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    };
    add(src);
    add(dst);
    add(&(udp.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 17]);
    add(udp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    match !(sum as u16) {
        0 => 0xffff,
        c => c,
    }
}

/// A parsed view of an IPv6+UDP packet (no extension-header support — FIPS
/// TUN traffic doesn't use them, and anything unparsed just isn't special-
/// cased by the DNS proxy).
pub struct Ipv6Udp<'a> {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse an IPv6 packet, returning `Some` only for plain UDP.
pub fn parse_ipv6_udp(packet: &[u8]) -> Option<Ipv6Udp<'_>> {
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }
    let udp_len = u16::from_be_bytes([packet[44], packet[45]]) as usize;
    if udp_len < 8 || udp_len > payload_len {
        return None;
    }
    Some(Ipv6Udp {
        src: packet[8..24].try_into().unwrap(),
        dst: packet[24..40].try_into().unwrap(),
        src_port: u16::from_be_bytes([packet[40], packet[41]]),
        dst_port: u16::from_be_bytes([packet[42], packet[43]]),
        payload: &packet[48..40 + udp_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_roundtrip() {
        let src = [0xfd; 16];
        let mut dst = [0xfd; 16];
        dst[15] = 2;
        let pkt = build_ipv6_udp(src, dst, 40000, 53, b"hello");
        let parsed = parse_ipv6_udp(&pkt).expect("parses");
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.src_port, 40000);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn checksum_verifies() {
        // Independent verification: summing the pseudo-header + UDP segment
        // (checksum field included) must yield 0xffff.
        let src = [1u8; 16];
        let dst = [2u8; 16];
        let pkt = build_ipv6_udp(src, dst, 1234, 53, b"abcxyz!");
        let udp = &pkt[40..];
        let mut sum = 0u32;
        for chunk in src
            .chunks(2)
            .chain(dst.chunks(2))
            .chain((udp.len() as u32).to_be_bytes().chunks(2))
            .chain([0u8, 0, 0, 17].chunks(2))
            .chain(udp.chunks(2))
        {
            sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn rejects_non_udp_and_truncated() {
        assert!(parse_ipv6_udp(&[0u8; 47]).is_none());
        let mut pkt = build_ipv6_udp([1; 16], [2; 16], 1, 2, b"x");
        pkt[6] = 6; // TCP
        assert!(parse_ipv6_udp(&pkt).is_none());
        let pkt = build_ipv6_udp([1; 16], [2; 16], 1, 2, b"payload");
        assert!(parse_ipv6_udp(&pkt[..pkt.len() - 1]).is_none());
    }
}
