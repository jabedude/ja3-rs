use ja3::Ja3;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ja3 = Ja3::new(&args[1])
                    .process_live(|x| println!("{}", x))
                    .unwrap();
}
