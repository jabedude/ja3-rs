#[cfg(test)]
mod tests {
    use pcap::Capture;
    use pnet::packet;

    #[test]
    fn it_works() {
        let mut cap = Capture::from_file("test.pcap").unwrap();
        while let Ok(packet) = cap.next() {
            println!("pack: {:?}", packet);
        }
    }
}
