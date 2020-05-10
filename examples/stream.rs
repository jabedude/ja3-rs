use ja3::Ja3;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ja3_capture = Ja3::new(&args[1]).process_live().unwrap();
    while let Some(hash) = ja3_capture.next() {
        println!("Hash: {:?}", hash);
    }
}
