use std::result;
use pcap::{Device, Packet, PacketHeader};
use network_analyzer::sniffer::filter::{Filter, get_filter};
use network_analyzer::sniffer::get_adapter;
use network_analyzer::sniffer::na_error::NAError;
use network_analyzer::sniffer::na_packet::NAPacket;
use network_analyzer::sniffer::channel::{Message, SnifferChannel};
use network_analyzer::sniffer::format::{get_file_name, option_to_string, to_u16};
use network_analyzer::sniffer::na_state::NAState;

#[test]
fn test_file_name_without_extensions() {
    let file_name = "file_name".to_string();
    let result = ("file_name.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn test_file_name_ending_with_md() {
    let file_name = "file_namemd".to_string();
    let result = ("file_namemd.md".to_string(), "file_namemd.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn test_file_name_ending_with_dot_md() {
    let file_name = "file_name.md".to_string();
    let result = ("file_name.md".to_string(), "file_name.md.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn test_file_name_ending_with_xml() {
    let file_name = "file_namexml".to_string();
    let result = ("file_namexml.md".to_string(), "file_namexml.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn test_file_name_ending_with_dot_xml() {
    let file_name = "file_name.xml".to_string();
    let result = ("file_name.xml.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}
/* MOD SNIFFER */

#[test]
#[should_panic(expected = "Device not found")]
fn test_not_existing_adapter() {
    let device_list = Device::list().unwrap();
    let mut couple = Vec::<(u8, Device)>::new();
    for (index, device) in device_list.into_iter().enumerate() {
        couple.push((index as u8 + 1, device));
    }
    let last_dev_index = couple.pop().unwrap().0;
    get_adapter(last_dev_index+1).unwrap();
}

/* MOD FILTER */

#[test]
fn test_none_filter() {
    let filter_name = "none".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::None));
}

#[test]
fn test_ipv4_filter(){
    let filter_name = "ipv4".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::IPv4));
}

#[test]
fn test_ipv6_filter(){
    let filter_name = "ipv6".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::IPv6));
}

#[test]
fn test_arp_filter(){
    let filter_name = "arp".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::ARP));
}

#[test]
fn test_correct_ipv4_filter(){
    let filter_name = "192.168.1.5".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::IP(filter_name)));
}

#[test]
#[should_panic(expected = "Not an IP addr. as filter")]
fn test_short_ipv4_filter(){
    let filter_name = "192.168.1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid IPv4 addr. as filter")]
fn test_not_parsable1_ipv4_filter(){
    let filter_name = "192.foo.1.2".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid IPv4 addr. as filter")]
fn test_not_parsable2_ipv4_filter(){
    let filter_name = "192.256.1.2".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_correct_ipv6_filter(){
    let filter_name = "2001:db8::2:1".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::IP(filter_name)));
}

#[test]
#[should_panic(expected = "Not a valid IPv6 addr. as filter")]
fn test_long_ipv6_filter(){
    let filter_name = "2001:db8::2:1::ab::fe:".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid IPv6 addr. as filter")]
fn test_not_parsable1_ipv6_filter(){
    let filter_name = "2001:foo::".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_biggest_ipv6_filter(){
    let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::IP(filter_name)));
}

#[test]
#[should_panic(expected = "Not a valid IPv6 addr. as filter")]
fn test_not_parsable2_ipv6_filter(){
    let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_correct_port_filter(){
    let filter_name = "8080".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::Port(8080)));
}

#[test]
fn test_last_u16_parsable_port_number(){
    let filter_name = "65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::Port(65535)));
}

#[test]
fn test_0_port_number(){
    let filter_name = "0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::Port(0)));
}

#[test]
#[should_panic(expected = "Unavailable filter")]
fn test_not_u16_parsable_port_number(){
    let filter_name = "65536".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Unavailable filter")]
fn test_negative_port_number(){
    let filter_name = "-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_lt_filter(){
    let filter_name = "<65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::LT(65535)));
}

#[test]
fn test_0_lt_filter(){
    let filter_name = "<0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::LT(0)));
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_wrong_lt_spaced_filter(){
    let filter_name = "< 65535".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_negative_lt_filter(){
    let filter_name = "<-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_unparsable_lt_filter(){
    let filter_name = "<foo".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_le_filter(){
    let filter_name = "<=65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::LE(65535)));
}

#[test]
fn test_0_le_filter(){
    let filter_name = "<=0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::LE(0)));
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_wrong_le_spaced_filter(){
    let filter_name = "<= 65535".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_negative_le_filter(){
    let filter_name = "<=-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_unparsable_le_filter(){
    let filter_name = "<=foo".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_eq_filter(){
    let filter_name = "=65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::EQ(65535)));
}

#[test]
fn test_0_eq_filter(){
    let filter_name = "=0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::EQ(0)));
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_wrong_eq_spaced_filter(){
    let filter_name = "= 65535".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_negative_eq_filter(){
    let filter_name = "=-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_unparsable_eq_filter(){
    let filter_name = "=foo".to_string();
    get_filter(&filter_name).unwrap();
}



#[test]
fn test_ge_filter(){
    let filter_name = ">=65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::GE(65535)));
}

#[test]
fn test_0_ge_filter(){
    let filter_name = ">=0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::GE(0)));
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_wrong_ge_spaced_filter(){
    let filter_name = ">= 65535".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_negative_ge_filter(){
    let filter_name = ">=-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_unparsable_ge_filter(){
    let filter_name = ">=foo".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_gt_filter(){
    let filter_name = ">65535".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::GT(65535)));
}

#[test]
fn test_0_gt_filter(){
    let filter_name = ">0".to_string();
    matches!(get_filter(&filter_name), Ok(Filter::GT(0)));
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_wrong_gt_spaced_filter(){
    let filter_name = "> 65535".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_negative_gt_filter(){
    let filter_name = ">-1".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
#[should_panic(expected = "Not a valid packet length")]
fn test_unparsable_gt_filter(){
    let filter_name = ">foo".to_string();
    get_filter(&filter_name).unwrap();
}

#[test]
fn test_opt_with_num_to_string() {
    let opt = Some(20);
    let result = "20".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn test_opt_with_str_to_string() {
    let opt = Some("AAA");
    let result = "AAA".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn test_opt_with_none_to_string() {
    let opt: Option<u8> = None;
    let result = "None".to_string();
    assert_eq!(option_to_string(opt), result);
}

#[test]
fn test_zeros_to_u16() {
    let p = &[0, 0, 0];
    assert_eq!(to_u16(p, 0), 0);
}

#[test]
fn test_max_num_to_u16() {
    let p = &[255, 255, 255];
    assert_eq!(to_u16(p, 0), 65535);
}

#[test]
fn test_num_in_first_position_to_u16() {
    let p = &[1, 2, 3];
    assert_eq!(to_u16(p, 0), 258);
}

#[test]
fn test_num_in_second_position_to_u16() {
    let p = &[1, 2, 3];
    assert_eq!(to_u16(p, 1), 515);
}

#[test]
fn test_send_a_state_to_channel() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let message = Message::State(NAState::RESUMED);
    channel.send(message);
    assert!(sub.recv().is_ok());
}

#[test]
fn test_send_an_error_to_channel() {
    let mut channel = SnifferChannel::new();
    let sub = channel.subscribe();
    let message = Message::Error(NAError::new("Error"));
    channel.send(message);
    assert!(sub.recv().is_ok());
}

#[test]
fn test_send_a_packet_to_channel() {
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
fn test_channel_dropped_before_sub() {
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
