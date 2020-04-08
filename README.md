# ja3-rs

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
