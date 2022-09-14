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

    /*
    // incoming IPv4
    let packet1 = Packet::new(
        12,
        6,
        "192.168.137.2".to_string(),
        "192.168.178.25".to_string(),
        25,
        80,
    );
    let packet2 = Packet::new(
        13,
        4,
        "192.168.137.3".to_string(),
        "192.168.178.25".to_string(),
        26,
        80,
    );

    // outgoing IPv6
    let packet3 = Packet::new(
        16,
        6,
        "fe80::4c34:b7af:2bc3:1867".to_string(),
        "fe80::535:e0cb:61bb:d1ce".to_string(),
        15,
        90,
    );
    let packet4 = Packet::new(
        12,
        5,
        "fe80::4c34:b7af:2bc3:1867".to_string(),
        "fe80::535:e0cb:61bb:d1cf".to_string(),
        16,
        90,
    );

    let devices = Device::list().unwrap();
    // let device = Device::from("\\Device\\NPF_{B2139FD3-C6E8-47EC-AD94-F18C8570AB16}");
    println!("{:?}", devices[3]);
    for addr in &devices[3].addresses {
        println!("{:?}", addr.addr.to_string());
    }
    println!("{:?}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis());

    let stats = produce_stats(devices[3].clone(), vec![&packet1, &packet2, &packet3, &packet4]);
    produce_report(stats);
     */
}
