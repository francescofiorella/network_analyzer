use clap::Parser;
use pcap::{Capture, Device};
use network_analyzer::sniffer::{NAPacket};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    adapter: String,
    #[clap(short, long, value_parser, default_value = "result.txt")]
    output: String,
    #[clap(short, long, value_parser, default_value = "0")]
    timeout: i32,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
}

fn main() {
    let args = Args::parse();
    println!("{}", args.adapter);
    println!("{}", args.output);
    println!("{}", args.timeout);
    println!("{}", args.filter);
    let d = Device::list().unwrap();
    let device = d.into_iter().find(|d| d.name == args.adapter).unwrap();
    // controllare se il device esiste

    //d.iter().for_each(|dev| println!("{}", dev.name));
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .timeout(args.timeout)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        let n = NAPacket::new(packet);
        println!("{:?}", n);
    }
}


