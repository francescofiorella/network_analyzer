use pcap::{Packet, PacketHeader};
use network_analyzer::sniffer::channel::{Message, SnifferChannel};
use network_analyzer::sniffer::format::{get_file_name, option_to_string, to_u16};
use network_analyzer::sniffer::na_error::NAError;
use network_analyzer::sniffer::na_packet::NAPacket;
use network_analyzer::sniffer::na_state::NAState;

#[test]
fn file_name_without_extensions() {
    let file_name = "file_name".to_string();
    let result = ("file_name.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_md() {
    let file_name = "file_namemd".to_string();
    let result = ("file_namemd.md".to_string(), "file_namemd.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_dot_md() {
    let file_name = "file_name.md".to_string();
    let result = ("file_name.md".to_string(), "file_name.md.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_xml() {
    let file_name = "file_namexml".to_string();
    let result = ("file_namexml.md".to_string(), "file_namexml.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_dot_xml() {
    let file_name = "file_name.xml".to_string();
    let result = ("file_name.xml.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn opt_with_num_to_string() {
    let opt = Some(20);
    let result = "20".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn opt_with_str_to_string() {
    let opt = Some("AAA");
    let result = "AAA".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn opt_with_none_to_string() {
    let opt: Option<u8> = None;
    let result = "None".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn zeros_to_u16() {
    let p = &[0, 0, 0];
    assert_eq!(to_u16(p, 0), 0);
}

#[test]
fn max_num_to_u16() {
    let p = &[255, 255, 255];
    assert_eq!(to_u16(p, 0), 65535);
}

#[test]
fn num_in_first_position_to_u16() {
    let p = &[1, 2, 3];
    assert_eq!(to_u16(p, 0), 258);
}

#[test]
fn num_in_second_position_to_u16() {
    let p = &[1, 2, 3];
    assert_eq!(to_u16(p, 1), 515);
}

#[test]
fn send_a_state_to_channel() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let message = Message::State(NAState::RESUMED);
    channel.send(message);
    assert!(sub.recv().is_ok());
}

#[test]
fn send_an_error_to_channel() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let message = Message::Error(NAError::new("Error"));
    channel.send(message);
    assert!(sub.recv().is_ok());
}

#[test]
fn send_a_packet_to_channel() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let pcap_packet = Packet{
        header: &PacketHeader { ts: libc::timeval { tv_sec: 0, tv_usec: 0 }, caplen: 2, len: 2 },
        data: &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] };
    let message = Message::Packet(NAPacket::new(pcap_packet));
    channel.send(message);
    assert!(sub.recv().is_ok());
}

#[test]
fn channel_dropped_before_sub() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let pcap_packet = Packet{
        header: &PacketHeader { ts: libc::timeval { tv_sec: 0, tv_usec: 0 }, caplen: 2, len: 2 },
        data: &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] };
    let message = Message::Packet(NAPacket::new(pcap_packet));
    channel.send(message);
    drop(channel);
    assert!(sub.recv().is_ok());
    assert!(sub.recv().is_err());
}
