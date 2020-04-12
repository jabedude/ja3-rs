//! JA3 Hash
//!
//! A small TLS fingerprinting library written in Rust.
//!
//! This crate enables a consumer to fingerprint the ClientHello portion of a TLS handshake.
//! It can hash TLS handshakes over IPv4 and IPv6. It heavily depends on the [tls-parser
//! project](https://github.com/rusticata/tls-parser) from Rusticata.
//!
//! See the original [JA3 project](https://github.com/salesforce/ja3) for more information.
//!
//! Example:
//!
//! ```rust
//! use ja3::Ja3;
//!
//! let mut ja3 = Ja3::new("test.pcap")
//!                     .process_pcap()
//!                     .unwrap();
//!
//! // Now we have a Vec of Ja3Hash objects
//! for hash in ja3 {
//!     println!("{}", hash);
//! }
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

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

lazy_static! {
    static ref IPTYPE: IpNextHeaderProtocol = IpNextHeaderProtocol::new(6);
    static ref GREASE: Vec<u16> = vec![
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    ];
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    ParseError,
}

/// A JA3 hash builder. This provides options about how to extract a JA3 hash from a TLS handshake.
#[derive(Debug)]
pub struct Ja3 {
    i: Ja3Inner,
}

/// The output of a JA3 hash object. This consists of the JA3 string and MD5 hash.
#[derive(Debug, Eq)]
pub struct Ja3Hash {
    /// The string consisting of the SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    /// See the original [JA3 specification](https://github.com/salesforce/ja3#how-it-works) for more info.
    pub ja3_str: String,
    /// The MD5 hash of `ja3_str`.
    pub hash: Digest,
}

#[derive(Debug)]
struct Ja3Inner {
    path: PathBuf,
    tls_port: u16,
}

impl Ja3 {
    /// Creates a new Ja3 object that will extract JA3 hash/es from the packet capture
    /// located at `pcap_path`.
    pub fn new<P: AsRef<Path>>(pcap_path: P) -> Self {
        let mut path = PathBuf::new();
        path.push(pcap_path);
        let i = Ja3Inner {
            path: path,
            tls_port: 443,
        };

        Ja3 { i: i }
    }

    /// Change the hasher behavior to scan for TLS handshakes occuring on *any* TCP port. By
    /// default we only fingerprint handshakes on TCP 443.
    pub fn any_port<'a>(&'a mut self) -> &'a mut Self {
        self.i.tls_port = 0;
        self
    }

    /// Scans the provided packet capture for TLS handshakes and returns JA3 hashes for any found.
    pub fn process_pcap(&self) -> Result<Vec<Ja3Hash>> {
        let mut results: Vec<Ja3Hash> = Vec::new();
        let mut cap = Capture::from_file(&self.i.path).unwrap();
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
            if self.i.tls_port != 0 {
                if tcp.get_destination() != 443 {
                    continue;
                }
            }

            info!("pack size: {}", tcp.packet_size());
            let handshake_start = tcp_start + tcp.packet_size();
            info!("handshake_start: {}", handshake_start);
            let handshake = &packet[handshake_start..];
            if handshake.len() <= 0 {
                continue;
            }
            if handshake[0] != 0x16 {
                continue;
            }
            info!("handshake: {:x?}", handshake);

            info!("sending handshake {:?}", handshake);
            let ja3_string = self.ja3_string_client_hello(&handshake).unwrap();
            if ja3_string == "" {
                continue;
            }
            let hash = md5::compute(&ja3_string.as_bytes());
            let ja3_res = Ja3Hash {
                ja3_str: ja3_string,
                hash: hash,
            };

            info!("Adding JA3: {:?}", ja3_res);
            results.push(ja3_res);
        }

        Ok(results)
    }

    fn process_extensions(&self, extensions: &[u8]) -> Option<String> {
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
                        if !GREASE.contains(&curve.0) {
                            info!("curve: {}", curve.0);
                            supported_groups.push_str(&format!("{}-", curve.0));
                        }
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
        info!("Supported groups: {}", supported_groups);
        info!("EC Points: {}", ec_points);
        let ret = format!("{},{},{}", ja3_exts, supported_groups, ec_points);
        Some(ret)
    }

    fn ja3_string_client_hello(&self, packet: &[u8]) -> Option<String> {
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
                                if !GREASE.contains(&cipher) {
                                    ja3_string.push_str(&format!("{}-", u16::from(cipher)));
                                }
                            }
                            ja3_string.pop();
                            ja3_string.push(',');
                            if let Some(extensions) = contents.ext {
                                let ext = self.process_extensions(extensions).unwrap();
                                ja3_string.push_str(&ext);
                            }
                        }
                    }
                }
            }
            _ => {
                info!("ERROR");
                return None;
            }
        }

        info!("ja3_string: {}", ja3_string);
        Some(ja3_string)
    }
}

impl fmt::Display for Ja3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} --> {:x}", self.ja3_str, self.hash)
    }
}

impl PartialEq for Ja3Hash {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ja3_client_hello_chrome_grease_single_packet() {
        env_logger::init();
        let expected_str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0";
        let expected_hash = "66918128f1b9b03303d77c6f2eefd128";

        let mut ja3 = Ja3::new("chrome-grease-single.pcap").process_pcap().unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
    }

    #[test]
    fn test_ja3_client_hello_firefox_single_packet() {
        let expected_str = "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
        let expected_hash = "839bbe3ed07fed922ded5aaf714d6842";

        let mut ja3 = Ja3::new("test.pcap").process_pcap().unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
    }

    #[test]
    fn test_ja3_curl_full_stream() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";

        let mut ja3s = Ja3::new("curl.pcap").process_pcap().unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
    }

    #[test]
    fn test_ja3_curl_full_stream_ipv6() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";

        let mut ja3s = Ja3::new("curl-ipv6.pcap").process_pcap().unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
    }

    #[test]
    fn test_ja3_client_hello_ncat_full_stream_non_tls_port() {
        let expected_str = "771,4866-4867-4865-49196-49200-163-159-52393-52392-52394-49327-49325-49315-49311-49245-49249-49239-49235-49188-49192-107-106-49267-49271-196-195-49162-49172-57-56-136-135-157-49313-49309-49233-61-192-53-132-49195-49199-162-158-49326-49324-49314-49310-49244-49248-49238-49234-49187-49191-103-64-49266-49270-190-189-49161-49171-51-50-154-153-69-68-156-49312-49308-49232-60-186-47-150-65-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "10a6b69a81bac09072a536ce9d35dd43";

        let mut ja3 = Ja3::new("ncat-port-4450.pcap")
            .any_port()
            .process_pcap()
            .unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
    }
}
