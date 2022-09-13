use pcap::{Capture, Device, Packet};
use network_analyzer::sniffer::NAPacket;

fn main() {
    let requested_device = Device::from("en0");
    let mut cap = Capture::from_device(requested_device).unwrap().
        promisc(true).
        snaplen(64).
        open().
        unwrap();

    while let Ok(packet) = cap.next_packet() {
        //println!("received packet! {:?}", packet);
        let p = NAPacket::new(packet);
        p.getdestmac();
    }
}
