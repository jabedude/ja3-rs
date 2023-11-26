//! JA3 Hash
//!
//! A small TLS fingerprinting library written in Rust.
//!
//! This crate enables a consumer to fingerprint the ClientHello portion of a TLS handshake.
//! It can hash TLS handshakes over IPv4 and IPv6. It heavily depends on the [tls-parser
//! project](https://github.com/rusticata/tls-parser) from Rusticata.
//!
//! It supports generating fingerprints from packet capture files as well as live-captures
//! on a network interface, both using libpcap.
//!
//! See the original [JA3 project](https://github.com/salesforce/ja3) for more information.
//!
//! Example of fingerprinting a packet capture file:
//!
//! ```rust,no_run
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
//!
//! Example of fingerprinting a live capture:
//!
//! ```rust,ignore
//! use ja3::Ja3;
//!
//! let mut ja3 = Ja3::new("eth0")
//!                     .process_live()
//!                     .unwrap();
//! while let Some(hash) = ja3.next() {
//!     println!("{}", hash);
//! }
//!
//! ```

use std::fs::File;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::IpAddr;

use lazy_static::*;
use log::{info, debug, warn};
use md5::{self, Digest};
#[cfg(feature = "live-capture")]
use pcap::{Active, Capture};
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use pcap_parser::traits::PcapReaderIterator;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::*;
use tls_parser::parse_tls_plaintext;
use tls_parser::tls::{TlsMessage, TlsMessageHandshake, TlsRecordType};
use tls_parser::tls_extensions::{parse_tls_extensions, TlsExtension, TlsExtensionType};

mod errors;
use errors::*;
use failure::Error;

lazy_static! {
    static ref IPTYPE: IpNextHeaderProtocol = IpNextHeaderProtocol::new(6);
    static ref GREASE: Vec<u16> = vec![
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    ];
}

/// A JA3 hash builder. This provides options about how to extract a JA3 hash from a TLS handshake.
#[derive(Debug)]
pub struct Ja3 {
    i: Ja3Inner,
}

// TODO: add support for RAW captures
#[derive(Debug)]
struct Ja3Inner {
    path: OsString,
    tls_port: u16,
}

/// The output of a JA3 hash object. This consists of the JA3 string and MD5 hash.
#[derive(Debug, Eq)]
pub struct Ja3Hash {
    /// The string consisting of the SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    /// See the original [JA3 specification](https://github.com/salesforce/ja3#how-it-works) for more info.
    pub ja3_str: String,
    /// The MD5 hash of `ja3_str`.
    pub hash: Digest,
    /// The destination IP address of the TLS handshake.
    pub source: IpAddr,
    /// The source IP address of the TLS handshake.
    pub destination: IpAddr,
    /// The packet size
    pub packet_size: usize,
    // is this a handshake
    pub is_handshake: bool,
}

/// Iterator of JA3 hashes captured during a live capture.
#[cfg(feature = "live-capture")]
pub struct Ja3Live {
    cap: Capture<Active>,
    ja3_inner: Ja3,
}

#[cfg(feature = "live-capture")]
impl Iterator for Ja3Live {
    type Item = Ja3Hash;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(packet) = self.cap.next() {
            match self.ja3_inner.process_packet_common(&packet) {
                Ok(ja3) => {
                    // You can now use ja3.packet_size and ja3.is_handshake
                    return Some(ja3);
                }
                Err(_) => continue,
            }
        }

        None
    }
}

impl Ja3 {
    /// Creates a new Ja3 object.
    ///
    /// It will extract JA3 hashes from the packet capture located at `pcap_path` or
    /// the network interface named `pcap_path`, depending on whether the consumer calls
    /// `process_pcap` or `process_live`.
    pub fn new<S: AsRef<OsStr>>(pcap_path: S) -> Self {
        let mut path = OsString::new();
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
    pub fn process_pcap(&self) -> Result<Vec<Ja3Hash>, Error> {
        let mut results: Vec<Ja3Hash> = Vec::new();

        let file = File::open(&self.i.path)?;
        let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {
                            // save hdr.network (linktype)
                        },
                        PcapBlockOwned::Legacy(block) => {
                            let ja3_hash = match self.process_packet_common(&block.data) {
                                Ok(s) => s,
                                Err(_) => {
                                    reader.consume(offset);
                                    continue;
                                },
                            };
                            debug!("Adding JA3: {:?}", ja3_hash);
                            results.push(ja3_hash);
                        },
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    reader.consume(offset);
                },
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                },
                Err(e) => return Err(e.into()),
            }
        }

        Ok(results)
    }

    /// Opens a live packet capture and scans packets for TLS handshakes and returns an iterator of
    /// JA3 hashes found.
    #[cfg(feature = "live-capture")]
    pub fn process_live(self) -> Result<Ja3Live, Error> {
        let cap = Capture::from_device(self.i.path.to_str().unwrap())?.open()?;
        info!("cap: {:?}", self.i.path);
        //while let Ok(packet) = cap.next() {
        //    let ja3_hash = match self.process_packet_common(&packet) {
        //        Ok(s) => s,
        //        Err(_) => continue,
        //    };

        //    info!("Calling callback with JA3: {:?}", ja3_hash);
        //    cb(&ja3_hash);
        //}

        Ok(Ja3Live {
            cap: cap,
            ja3_inner: self,
        })
    }

    fn process_packet_common(&self, packet: &[u8]) -> Result<Ja3Hash, Error> {
        let saddr;
        let daddr;
        let ether = ethernet::EthernetPacket::new(&packet).ok_or(Ja3Error::ParseError)?;
        let packet_size = ether.payload().len();

        info!("\nether packet: {:?} len: {}", ether, ether.packet_size());
        let tcp_start = match ether.get_ethertype() {
            EtherType(0x0800) => {
                let ip = ipv4::Ipv4Packet::new(&packet[ether.packet_size()..])
                    .ok_or(Ja3Error::ParseError)?;
                info!("\nipv4 packet: {:?}", ip);
                if ip.get_next_level_protocol() != *IPTYPE {
                    return Err(Ja3Error::ParseError)?;
                }
                let iphl = ip.get_header_length() as usize * 4;
                saddr = IpAddr::V4(ip.get_source());
                daddr = IpAddr::V4(ip.get_destination());
                iphl + ether.packet_size()
            }
            EtherType(0x86dd) => {
                let ip = ipv6::Ipv6Packet::new(&packet[ether.packet_size()..])
                    .ok_or(Ja3Error::ParseError)?;
                info!("\nipv6 packet: {:?}", ip);
                saddr = IpAddr::V6(ip.get_source());
                daddr = IpAddr::V6(ip.get_destination());
                if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                    return Err(Ja3Error::NotHandshake)?;
                }
                let iphl = 40;
                iphl + ether.packet_size()
            }
            _ => return Err(Ja3Error::ParseError)?,
        };

        let tcp = tcp::TcpPacket::new(&packet[tcp_start..]).ok_or(Ja3Error::ParseError)?;
        info!("tcp: {:?}", tcp);
        if self.i.tls_port != 0 {
            if tcp.get_destination() != 443 {
                return Err(Ja3Error::NotHandshake)?;
            }
        }

        info!("pack size: {}", tcp.packet_size());
        let handshake_start = tcp_start + tcp.packet_size();
        info!("handshake_start: {}", handshake_start);
        let handshake = &packet[handshake_start..];
        if handshake.len() <= 0 {
            return Err(Ja3Error::NotHandshake)?;
        }
        if handshake[0] != 0x16 {
            return Err(Ja3Error::NotHandshake)?;
        }
        info!("handshake: {:x?}", handshake);

        // mark if its a handshake, might not be needed
        let is_handshake = if handshake.len() > 0 && handshake[0] == 0x16 {
            true // It's a TLS handshake
        } else {
            false
        };

        info!("sending handshake {:?}", handshake);
        match self.ja3_string_client_hello(&handshake) {
            Some(ja3_string) if !ja3_string.is_empty() => {
                // Proceed with processing the non-empty JA3 string
                let hash = md5::compute(&ja3_string.as_bytes());
                let ja3_res = Ja3Hash {
                    ja3_str: ja3_string,
                    hash: hash,
                    source: saddr,
                    destination: daddr,
                    packet_size: packet_size,
                    is_handshake: is_handshake,
                };

                Ok(ja3_res)
            },
            _ => {
                return Err(Ja3Error::NotHandshake)?;
                // warn!("setting ja3 to none");
                // // Handle the case where the JA3 string is None or empty
                // // You can either skip this packet, log it, or handle it differently
                // let ja3_res = Ja3Hash {
                //     ja3_str: "".to_owned(),
                //     hash: Option::None,
                //     source: saddr,
                //     destination: daddr,
                //     packet_size: packet_size,
                //     is_handshake: is_handshake,
                // };
                //
                // Ok(ja3_res)
            }
        }

        // info!("sending handshake {:?}", handshake);
        // let ja3_string = self.ja3_string_client_hello(&handshake).unwrap();
        // if ja3_string == "" {
        //     return Err(Ja3Error::NotHandshake)?;
        // }


        // let hash = md5::compute(&ja3_string.as_bytes());
        // let ja3_res = Ja3Hash {
        //     ja3_str: ja3_string,
        //     hash: hash,
        //     source: saddr,
        //     destination: daddr,
        //     packet_size: packet_size,
        //     is_handshake: is_handshake,
        // };

        // Ok(ja3_res)
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
        write!(
            f,
            "[{} --> {}] {} {:?}",
            self.source, self.destination, self.ja3_str, Option::Some(self.hash)
        )
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
    use nix::unistd::{fork, ForkResult};
    use pretty_assertions::assert_eq;
    use rusty_fork::rusty_fork_id;
    use rusty_fork::rusty_fork_test;
    use rusty_fork::rusty_fork_test_name;
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::Command;

    // NOTE: Any test for the live-capture feature requires elevated privileges.

    #[cfg(feature = "live-capture")]
    rusty_fork_test! {
    #[test] #[ignore]
    fn test_ja3_client_hello_chrome_grease_single_packet_live() {
        let expected_str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0";
        let expected_hash = "66918128f1b9b03303d77c6f2eefd128";
        let expected_daddr = IpAddr::V6("2607:f8b0:4004:814::2002".parse().unwrap());

        match fork() {
            Ok(ForkResult::Parent { child: _, .. }) => {
                let mut ja3 = Ja3::new("lo")
                                .process_live().unwrap();
                if let Some(x) = ja3.next() {
                    assert_eq!(x.ja3_str, expected_str);
                    assert_eq!(format!("{:x}", x.hash), expected_hash);
                    assert_eq!(expected_daddr, x.destination);
                    std::process::exit(0);
                }
            },
            Ok(ForkResult::Child) => {
                let _out = Command::new("tcpreplay")
                            .arg("-i")
                            .arg("lo")
                            .arg("chrome-grease-single.pcap")
                            .output()
                            .expect("failed to execute process");
            },
            Err(_) => println!("Fork failed"),
        }

    }
    }

    #[test]
    fn test_ja3_client_hello_chrome_grease_single_packet() {
        let expected_str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0";
        let expected_hash = "66918128f1b9b03303d77c6f2eefd128";
        let expected_daddr = IpAddr::V6("2607:f8b0:4004:814::2002".parse().unwrap());

        let mut ja3 = Ja3::new("tests/chrome-grease-single.pcap")
            .process_pcap()
            .unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
        assert_eq!(expected_daddr, ja3_hash.destination);
    }

    #[test]
    fn test_ja3_client_hello_firefox_single_packet() {
        let expected_str = "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
        let expected_hash = "839bbe3ed07fed922ded5aaf714d6842";
        let expected_daddr = IpAddr::V4("34.209.18.179".parse().unwrap());

        let mut ja3 = Ja3::new("tests/test.pcap").process_pcap().unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
        assert_eq!(expected_daddr, ja3_hash.destination);
    }

    #[test]
    fn test_ja3_curl_full_stream() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";
        let expected_daddr = IpAddr::V4("93.184.216.34".parse().unwrap());

        let mut ja3s = Ja3::new("tests/curl.pcap").process_pcap().unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
        assert_eq!(expected_daddr, ja3.destination);
    }

    #[test]
    fn test_ja3_curl_full_stream_ipv6() {
        let expected_str = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "456523fc94726331a4d5a2e1d40b2cd7";
        let expected_daddr = IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());

        let mut ja3s = Ja3::new("tests/curl-ipv6.pcap").process_pcap().unwrap();
        let ja3 = ja3s.pop().unwrap();
        assert_eq!(ja3.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3.hash), expected_hash);
        assert_eq!(expected_daddr, ja3.destination);
    }

    #[test]
    fn test_ja3_client_hello_ncat_full_stream_non_tls_port() {
        let expected_str = "771,4866-4867-4865-49196-49200-163-159-52393-52392-52394-49327-49325-49315-49311-49245-49249-49239-49235-49188-49192-107-106-49267-49271-196-195-49162-49172-57-56-136-135-157-49313-49309-49233-61-192-53-132-49195-49199-162-158-49326-49324-49314-49310-49244-49248-49238-49234-49187-49191-103-64-49266-49270-190-189-49161-49171-51-50-154-153-69-68-156-49312-49308-49232-60-186-47-150-65-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2";
        let expected_hash = "10a6b69a81bac09072a536ce9d35dd43";

        let mut ja3 = Ja3::new("tests/ncat-port-4450.pcap")
            .any_port()
            .process_pcap()
            .unwrap();
        let ja3_hash = ja3.pop().unwrap();
        assert_eq!(ja3_hash.ja3_str, expected_str);
        assert_eq!(format!("{:x}", ja3_hash.hash), expected_hash);
        assert_eq!(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ja3_hash.destination
        );
    }
}
