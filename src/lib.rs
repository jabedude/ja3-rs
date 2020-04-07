use std::path::Path;

use lazy_static::*;
use md5::{self, Digest};
use pcap::Capture;
use pnet::packet::*;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocol;
use tls_parser::parse_tls_plaintext;
use tls_parser::tls_extensions::{parse_tls_extensions, TlsExtension, TlsExtensionType};
use tls_parser::tls::{TlsRecordType, TlsMessage, TlsMessageHandshake};

// curl ja3 hash: 456523fc94726331a4d5a2e1d40b2cd7
// firefox ja3 hash: 839bbe3ed07fed922ded5aaf714d6842
// "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0"

lazy_static! {
    static ref IPTYPE: IpNextHeaderProtocol = IpNextHeaderProtocol::new(6);
}

#[derive(Debug)]
pub enum Error {
    ParseError,
}

type Result<T> = std::result::Result<T, Error>;

fn process_extensions(extensions: &[u8]) -> Option<String> {
    let mut ja3_exts = String::new();
    let mut supported_groups = String::new();
    let mut ec_points = String::new();
    let (_, exts) = parse_tls_extensions(extensions).unwrap();
    for extension in exts {
        // TODO: GREASE
        let ext_val = u16::from(TlsExtensionType::from(&extension));
        eprintln!("Ext: {:?}", ext_val);
        ja3_exts.push_str(&format!("{}-", ext_val));
        match extension {
            TlsExtension::EllipticCurves(curves) => {
                for curve in curves {
                    eprintln!("curve: {}", curve.0);
                    supported_groups.push_str(&format!("{}-", curve.0));
                }
            },
            TlsExtension::EcPointFormats(points) => {
                eprintln!("Points: {:x?}", points);
                for point in points {
                    ec_points.push_str(&format!("{}-", point));
                }
            },
            _ => {},
        }
    }
    supported_groups.pop();
    ec_points.pop();
    eprintln!("{}", supported_groups);
    eprintln!("{}", ec_points);
    let ret = format!("{},{},{}", ja3_exts, supported_groups, ec_points);
    Some(ret)
}

pub fn ja3_string_client_hello(packet: &[u8]) -> Option<String> {
    let mut ja3_string = String::new();
    let res = parse_tls_plaintext(packet);
    match res {
        Ok((rem, record)) => {
            eprintln!("Rem: {:?}, record: {:?}", rem, record);
            eprintln!("record type: {:?}", record.hdr.record_type);
            if record.hdr.record_type != TlsRecordType::Handshake {
                return None;
            }
            for rec in record.msg {
                if let TlsMessage::Handshake(handshake) = rec {
                    if let TlsMessageHandshake::ClientHello(contents) = handshake {
                        eprintln!("handshake contents: {:?}", contents);
                        eprintln!("handshake tls version: {:?}", u16::from(contents.version));
                        ja3_string.push_str(&format!("{},", u16::from(contents.version)));
                        for cipher in contents.ciphers {
                            eprintln!("handshake cipher: {}", u16::from(cipher));
                            ja3_string.push_str(&format!("{}-", u16::from(cipher)));
                        }
                        ja3_string.pop();
                        if let Some(extensions) = contents.ext {
                            let ext = process_extensions(extensions).unwrap();
                            ja3_string.push_str(&ext);
                        }
                    }
                }
            }
        },
        _ => {
            eprintln!("ERROR");
        },
    }

    eprintln!("ja3_string: {}", ja3_string);
    Some(ja3_string)
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
        if handshake[0] != 0x16 {
            continue;
        }

        eprintln!("sending handshake");
        let digest = ja3_string_client_hello(&handshake);
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

    #[test]
    fn test_process_extensions() {
    }

    //#[test]
    //fn test_firefox_single_packet_pcap() {
    //    let mut cap = Capture::from_file("test.pcap").unwrap();
    //    let packet = cap.next().unwrap();
    //    let ja3_digest = ja3_hash_client_hello(&packet);
    //    //assert_eq!(ja3_digest, Some([]));
    //}
}
