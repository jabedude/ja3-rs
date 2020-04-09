# ja3-rs

[![crates.io](https://img.shields.io/crates/v/ja3.svg)](https://crates.io/crates/ja3)
[![Build Status](https://travis-ci.org/jabedude/ja3-rs.svg?branch=master)](https://travis-ci.org/jabedude/ja3-rs)
[![Documentation](https://docs.rs/ja3/badge.svg)](https://docs.rs/ja3/)
[![license](https://img.shields.io/badge/license-BSD3.0-blue.svg)](https://github.com/jabedude/ja3-rs/LICENSE)

A small TLS fingerprinting library written in Rust.

This crate enables a consumer to fingerprint the ClientHello portion of a TLS handshake.
It can hash TLS handshakes over IPv4 and IPv6. It heavily depends on the [tls-parser
project](https://github.com/rusticata/tls-parser) from Rusticata.

See the original [JA3 project](https://github.com/salesforce/ja3) for more information.

Example:

```rust
use ja3::Ja3;

let mut ja3 = Ja3::new("path-to-pcap.pcap")
                    .process_pcap()
                    .unwrap();

// Now we have a Vec of Ja3Hash objects
for hash in ja3 {
    println!("{}", hash);
}
```
