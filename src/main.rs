use std::time::SystemTime;
use pcap::Device;
use network_analyzer::sniffer::{Packet, produce_report, produce_stats};

fn main() {
    // incoming IPv4
    let packet1 = Packet::new(
        12,
        6,
        "192.168.137.2".to_string(),
        "192.168.137.1".to_string(),
        25,
        80,
    );
    let packet2 = Packet::new(
        13,
        4,
        "192.168.137.3".to_string(),
        "192.168.137.1".to_string(),
        26,
        80,
    );

    // outgoing IPv6
    let packet3 = Packet::new(
        16,
        6,
        "fe80::535:e0cb:61bb:d1cc".to_string(),
        "fe80::535:e0cb:61bb:d1ce".to_string(),
        15,
        90,
    );
    let packet4 = Packet::new(
        12,
        5,
        "fe80::535:e0cb:61bb:d1cc".to_string(),
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
}
