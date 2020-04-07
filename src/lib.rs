use std::path::Path;

use lazy_static::*;
use log::info;
use md5::{self, Digest};
use pcap::Capture;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::*;
use tls_parser::parse_tls_plaintext;
use tls_parser::tls::{TlsMessage, TlsMessageHandshake, TlsRecordType};
use tls_parser::tls_extensions::{parse_tls_extensions, TlsExtension, TlsExtensionType};

// curl ja3 hash: 456523fc94726331a4d5a2e1d40b2cd7
// "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2"
//
// firefox ja3 hash: 839bbe3ed07fed922ded5aaf714d6842
// "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0"

lazy_static! {
    static ref IPTYPE: IpNextHeaderProtocol = IpNextHeaderProtocol::new(6);
    static ref GREASE: Vec<u16> = vec![
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    ];
}

#[derive(Debug)]
pub enum Error {
    ParseError,
}

#[derive(Debug)]
pub struct Ja3 {
    pub ja3_str: String,
    pub hash: Digest,
}

type Result<T> = std::result::Result<T, Error>;

fn process_extensions(extensions: &[u8]) -> Option<String> {
    let mut ja3_exts = String::new();
    let mut supported_groups = String::new();
    let mut ec_points = String::new();
    let (_, exts) = parse_tls_extensions(extensions).unwrap();
    for extension in exts {
        let ext_val = u16::from(TlsExtensionType::from(&extension));
        if GREASE.contains(&ext_val) {
            continue;
        }
        info!("Ext: {:?}", ext_val);
        ja3_exts.push_str(&format!("{}-", ext_val));
        match extension {
            TlsExtension::EllipticCurves(curves) => {
                for curve in curves {
                    info!("curve: {}", curve.0);
                    supported_groups.push_str(&format!("{}-", curve.0));
                }
            }
            TlsExtension::EcPointFormats(points) => {
                info!("Points: {:x?}", points);
                for point in points {
                    ec_points.push_str(&format!("{}-", point));
                }
            }
            _ => {}
        }
    }
    ja3_exts.pop();
    supported_groups.pop();
    ec_points.pop();
    info!("{}", supported_groups);
    info!("{}", ec_points);
    let ret = format!("{},{},{}", ja3_exts, supported_groups, ec_points);
    Some(ret)
}

pub fn ja3_string_client_hello(packet: &[u8]) -> Option<String> {
    info!("PACKET: {:?}", packet);
    let mut ja3_string = String::new();
    let res = parse_tls_plaintext(packet);
    match res {
        Ok((rem, record)) => {
            info!("Rem: {:?}, record: {:?}", rem, record);
            info!("record type: {:?}", record.hdr.record_type);
            if record.hdr.record_type != TlsRecordType::Handshake {
                return None;
            }
            for rec in record.msg {
                if let TlsMessage::Handshake(handshake) = rec {
                    if let TlsMessageHandshake::ClientHello(contents) = handshake {
                        info!("handshake contents: {:?}", contents);
                        info!("handshake tls version: {:?}", u16::from(contents.version));
                        ja3_string.push_str(&format!("{},", u16::from(contents.version)));
                        for cipher in contents.ciphers {
                            info!("handshake cipher: {}", u16::from(cipher));
                            ja3_string.push_str(&format!("{}-", u16::from(cipher)));
                        }
                        ja3_string.pop();
                        ja3_string.push(',');
                        if let Some(extensions) = contents.ext {
                            let ext = process_extensions(extensions).unwrap();
                            ja3_string.push_str(&ext);
                        }
                    }
                }
            }
        }
        _ => {
            info!("ERROR");
        }
    }

    info!("ja3_string: {}", ja3_string);
    Some(ja3_string)
}

pub fn process_pcap<P: AsRef<Path>>(pcap_path: P) -> Result<Vec<Ja3>> {
    let mut results: Vec<Ja3> = Vec::new();
    let mut cap = Capture::from_file(pcap_path).unwrap();
    while let Ok(packet) = cap.next() {
        let ether = ethernet::EthernetPacket::new(&packet).ok_or(Error::ParseError)?;
        info!("\nether packet: {:?} len: {}", ether, ether.packet_size());
        let tcp_start = match ether.get_ethertype() {
            EtherType(0x0800) => {
                let ip = ipv4::Ipv4Packet::new(&packet[ether.packet_size()..])
                    .ok_or(Error::ParseError)?;
                info!("\nipv4 packet: {:?}", ip);
                if ip.get_next_level_protocol() != *IPTYPE {
                    continue;
                }
                let iphl = ip.get_header_length() as usize * 4;
                iphl + ether.packet_size()
            }
            EtherType(0x86dd) => {
                let ip = ipv6::Ipv6Packet::new(&packet[ether.packet_size()..])
                    .ok_or(Error::ParseError)?;
                info!("\nipv6 packet: {:?}", ip);
                if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                    continue;
                }
                let iphl = 40;
                iphl + ether.packet_size()
            }
            _ => return Err(Error::ParseError),
        };

        let tcp = tcp::TcpPacket::new(&packet[tcp_start..]).ok_or(Error::ParseError)?;
        info!("tcp: {:?}", tcp);
        if tcp.get_destination() != 443 {
            continue;
        }

        info!("pack size: {}", tcp.packet_size());
        let handshake_start = tcp_start + tcp.packet_size();
        info!("handshake_start: {}", handshake_start);
        let handshake = &packet[handshake_start..];
        if handshake.len() <= 0 {
            continue;
        }
        info!("handshake: {:x?}", handshake);
        if handshake[0] != 0x16 {
            continue;
        }

        info!("sending handshake {:?}", handshake);
        let ja3_string = ja3_string_client_hello(&handshake).unwrap();
        let hash = md5::compute(&ja3_string.as_bytes());
        let ja3_res = Ja3 {
            ja3_str: ja3_string,
            hash: hash,
        };

        results.push(ja3_res);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use pretty_assertions::assert_eq;

    // TODO: Add GREASE test case

    #[test]
    fn it_works() {
        let _ja3s = process_pcap("test.pcap").unwrap();
    }

    #[test]
    fn test_ja3_client_hello_firefox_single_packet() {
        let expected_str = "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
        let expected_hash = "839bbe3ed07fed922ded5aaf714d6842";

        let mut ja3s = process_pcap("test.pcap").unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
    }

    #[test]
    fn test_ja3_curl_full_stream() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";

        let mut ja3s = process_pcap("curl.pcap").unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
    }

    #[test]
    fn test_ja3_curl_full_stream_ipv6() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";

        let mut ja3s = process_pcap("curl-ipv6.pcap").unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
    }
}
