use std::path::Path;

use lazy_static::*;
use md5::{self, Digest};
use pcap::Capture;
use pnet::packet::*;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocol;

// curl ja3 hash: 456523fc94726331a4d5a2e1d40b2cd7
// firefox ja3 hash: 839bbe3ed07fed922ded5aaf714d6842

lazy_static! {
    static ref IPTYPE: IpNextHeaderProtocol = IpNextHeaderProtocol::new(6);
}

#[derive(Debug)]
pub enum Error {
    ParseError,
}

type Result<T> = std::result::Result<T, Error>;

pub fn ja3_hash_client_hello(packet: &[u8]) -> Option<Digest> {
    None
}

pub fn process_pcap<P: AsRef<Path>>(pcap_path: P) -> Result<()> {
    let mut cap = Capture::from_file(pcap_path).unwrap();
    while let Ok(packet) = cap.next() {
        let ether = ethernet::EthernetPacket::new(&packet).ok_or(Error::ParseError)?;
        eprintln!("\nether packet: {:?} len: {}", ether, ether.packet_size());
        if ether.get_ethertype() != EtherType(0x0800) {
            continue;
        }

        let ip = ipv4::Ipv4Packet::new(&packet[ether.packet_size()..]).ok_or(Error::ParseError)?;
        eprintln!("\nip packet: {:?}", ip);
        if ip.get_next_level_protocol() != *IPTYPE {
            continue;
        }

        let iphl = ip.get_header_length() as usize * 4;
        let tcp_start = iphl + ether.packet_size();
        let tcp = tcp::TcpPacket::new(&packet[tcp_start..]).ok_or(Error::ParseError)?;
        eprintln!("tcp: {:?}", tcp);
        if tcp.get_destination() != 443 {
            continue;
        }

        eprintln!("pack size: {}", tcp.packet_size());
        let handshake_start = tcp_start + tcp.packet_size();
        eprintln!("handshake_start: {}", handshake_start);
        let handshake = &packet[handshake_start..];
        eprintln!("handshake: {:x?}", handshake);
        if handshake[0] != 0x22 {
            continue;
        }

        let digest = ja3_hash_client_hello(&handshake);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        process_pcap("test.pcap").unwrap();
    }

    //#[test]
    //fn test_firefox_single_packet_pcap() {
    //    let mut cap = Capture::from_file("test.pcap").unwrap();
    //    let packet = cap.next().unwrap();
    //    let ja3_digest = ja3_hash_client_hello(&packet);
    //    //assert_eq!(ja3_digest, Some([]));
    //}
}
