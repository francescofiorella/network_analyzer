use std::io::{Read, stdin, stdout, Write};
use clap::Parser;
use pcap::{Capture, Device};
use network_analyzer::sniffer::{list_adapters, na_config, NAPacket};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    network_adapter: String,
}


fn main() {
    let d = Device::list().unwrap();
    d.iter().for_each(|dev| println!("{}", dev.name));
    let mut cap = Capture::from_device(Device::from("\\Device\\NPF_{95447BA6-2281-41C5-8C25-FC2BAF48A72C}"))
        .unwrap()
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        let n = NAPacket::new(packet);
        println!("{:?}", n);
    }
}


