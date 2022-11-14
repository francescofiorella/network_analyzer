use std::result;
use pcap::{Device, Packet, PacketHeader};
use network_analyzer::sniffer::filter::{Filter, get_filter};
use network_analyzer::sniffer::format::get_file_name;
use network_analyzer::sniffer::get_adapter;
use network_analyzer::sniffer::na_error::NAError;
use network_analyzer::sniffer::na_packet::NAPacket;
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
fn not_existing_adapter() {
    let device_list = Device::list().unwrap();
    let mut couple = Vec::<(u8, Device)>::new();
    for (index, device) in device_list.into_iter().enumerate() {
        couple.push((index as u8 + 1, device));
    }
    let last_dev_index = couple.pop().unwrap().0;
    assert!(get_adapter(100).is_err());
}

#[test]
fn test_none_filter() {
    let filter_name = "none".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::None => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_ipv4_filter(){
    let filter_name = "ipv4".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::IPv4 => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_ipv6_filter(){
    let filter_name = "ipv6".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::IPv6 => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_arp_filter(){
    let filter_name = "arp".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::ARP => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_correct_ipv4_filter(){
    let filter_name = "192.168.1.5".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::IP("192.168.1.5".to_string()) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_short_ipv4_filter(){
    let filter_name = "192.168.1".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_not_parsable1_ipv4_filter(){
    let filter_name = "192.foo.1.2".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_not_parsable2_ipv4_filter(){
    let filter_name = "192.256.1.2".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_correct_ipv6_filter(){
    let filter_name = "2001:db8::2:1".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::IP("2001:db8::2:1".to_string()) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_long_ipv6_filter(){
    let filter_name = "2001:db8::2:1::ab::fe:".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_not_parsable1_ipv6_filter(){
    let filter_name = "2001:foo::".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_biggest_ipv6_filter(){
    let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::IP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_not_parsable2_ipv6_filter(){
    let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff1".to_string();
    assert!(get_filter(&filter_name).is_err())
}

//TO DO - serie di :: maggiore di 2 in ipv6 filtering

#[test]
fn test_correct_port_filter(){
    let filter_name = "8080".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::Port(8080) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_last_u16_parsable_port_number(){
    let filter_name = "65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::Port(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_port_number(){
    let filter_name = "0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::Port(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_not_u16_parsable_port_number(){
    let filter_name = "65536".to_string();
    assert!(get_filter(&filter_name).is_err())
}

#[test]
fn test_negative_port_number(){
    let filter_name = "-1".to_string();
    assert!(get_filter(&filter_name).is_err())
}

//NOTA: si fa il parsing a 32 bit, per cui anche oltre 65535 va bene

#[test]
fn test_lt_filter(){
    let filter_name = "<65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::LT(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_lt_filter(){
    let filter_name = "<0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::LT(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_wrong_lt_spaced_filter(){
    let filter_name = "< 65535".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_negative_lt_filter(){
    let filter_name = "<-1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_unparsable_lt_filter(){
    let filter_name = "<192.168.1.1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_le_filter(){
    let filter_name = "<=65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::LE(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_le_filter(){
    let filter_name = "<=0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::LE(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_wrong_le_spaced_filter(){
    let filter_name = "<= 65535".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_negative_le_filter(){
    let filter_name = "<=-1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_unparsable_le_filter(){
    let filter_name = "<=192.168.1.1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_eq_filter(){
    let filter_name = "=65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::EQ(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_eq_filter(){
    let filter_name = "=0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::EQ(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_wrong_eq_spaced_filter(){
    let filter_name = "= 65535".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_negative_eq_filter(){
    let filter_name = "=-1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_unparsable_eq_filter(){
    let filter_name = "=192.168.1.1".to_string();
    assert!(get_filter(&filter_name).is_err());
}



#[test]
fn test_ge_filter(){
    let filter_name = ">=65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::GE(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_ge_filter(){
    let filter_name = ">=0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::GE(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_wrong_ge_spaced_filter(){
    let filter_name = ">= 65535".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_negative_ge_filter(){
    let filter_name = ">=-1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_unparsable_ge_filter(){
    let filter_name = ">=192.168.1.1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_gt_filter(){
    let filter_name = ">65535".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::GT(65535) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_0_gt_filter(){
    let filter_name = ">0".to_string();
    let result = match get_filter(&filter_name) {
        Err(_) => false,
        Ok(filter) if filter == Filter::GT(0) => true,
        _ => false
    };
    assert!(result)
}

#[test]
fn test_wrong_gt_spaced_filter(){
    let filter_name = "> 65535".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_negative_gt_filter(){
    let filter_name = ">-1".to_string();
    assert!(get_filter(&filter_name).is_err());
}

#[test]
fn test_unparsable_gt_filter(){
    let filter_name = ">192.168.1.1".to_string();
    assert!(get_filter(&filter_name).is_err());
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
