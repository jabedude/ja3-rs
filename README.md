# ja3-rs

[![crates.io](https://img.shields.io/crates/v/ja3.svg)](https://crates.io/crates/ja3)
[![Build Status](https://travis-ci.org/jabedude/ja3-rs.svg?branch=master)](https://travis-ci.org/jabedude/ja3-rs)
[![Documentation](https://docs.rs/ja3/badge.svg)](https://docs.rs/ja3/)
[![license](https://img.shields.io/badge/license-BSD3.0-blue.svg)](https://github.com/jabedude/ja3-rs/LICENSE)

A small JA3 TLS fingerprinting library written in Rust.

This crate enables a consumer to fingerprint the ClientHello portion of a TLS handshake.
It can hash TLS handshakes over IPv4 and IPv6. It heavily depends on the [tls-parser
project](https://github.com/rusticata/tls-parser) from Rusticata.

It supports generating fingerprints from packet capture files as well as live-captures 
on a network interface, both using libpcap.

See the original [JA3 project](https://github.com/salesforce/ja3) for more information.

Example of fingerprinting a packet capture file:

```rust
use ja3::Ja3;

let mut ja3 = Ja3::new("test.pcap")
                    .process_pcap()
                    .unwrap();

// Now we have a Vec of Ja3Hash objects
for hash in ja3 {
    println!("{}", hash);
}
```

Example of fingerprinting a live capture:

```rust
use ja3::Ja3;

let mut ja3 = Ja3::new("eth0")
                    .process_live()
                    .unwrap();
while let Some(hash) = ja3.next() {
    println!("Hash: {}", hash);
}

```

## Benchmarks

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `ja3 huge-cap.pcap` | 153.2 ± 2.3 | 149.8 | 157.2 | 34.85 ± 2.82 |
| `./target/release/examples/ja3 huge-cap.pcap` | 4.4 ± 0.3 | 3.6 | 5.5 | 1.00 |
