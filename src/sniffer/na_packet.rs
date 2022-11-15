mod protocols;

use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use pcap::Packet;
use crate::sniffer::filter::Filter;
use crate::sniffer::format::{option_to_string, to_u16};
use crate::sniffer::na_packet::protocols::{get_ipv6_transported_protocol, to_ip_address, to_ipv6_address, to_level_three_protocol, to_mac_address, to_transported_protocol};

/// The struct `NAPacket` describes the packet sniffed and keeps the most relevant network information like:
/// * source and destination MAC addresses
/// * level 3 protocol type
/// * source and destination level 3 addresses (IPv4 or IPv6)
/// * packet length (in bytes)
/// * transported protocol
/// * source and destination ports (if any)
/// * timestamp.
///
/// Moreover, it is also responsible for:
/// 1) formatting the `NAPacket` information to be printed out better on the screen
/// 2) filtering the `NAPacket` using a filter tag defining transported protocol, IP addresses, ports or packet
/// 3) casting integers extracted from pcap `Packet` library into MAC addresses, IP addresses (v4 and v6) and level 3 and 4 transported protocols.
#[derive(Debug, Clone)]
pub struct NAPacket {
    //level 2 header
    pub(crate) destination_mac_address: String,
    pub(crate) source_mac_address: String,

    //level 3 header
    pub(crate) level_three_type: String,
    pub(crate) total_length: u32,
    pub(crate) source_address: Option<String>,
    pub(crate) destination_address: Option<String>,

    //level 4 header
    pub(crate) transported_protocol: Option<String>,
    pub(crate) source_port: Option<u16>,
    pub(crate) destination_port: Option<u16>,

    pub(crate) timestamp: u128,
}

impl NAPacket {
    /// Creates a new `NAPacket` object starting from a `Packet` of `pcap` library.
    ///
    /// This function accesses specific bytes of the `pcap::Packet` object containing relevant information
    /// such as transported protocols, source and destination ports, addresses etc ... which are casted using appropriate functions.

    pub fn new(pcap_packet: Packet) -> Self {
        let mut source_address = None;
        let mut destination_address = None;
        let mut transported_protocol = None;
        let mut source_port = None;
        let mut destination_port = None;

        let eth_type = to_u16(&pcap_packet, 12);
        match eth_type {
            // IPv4
            0x0800 => {
                source_address = Some(to_ip_address(&pcap_packet, 26));
                destination_address = Some(to_ip_address(&pcap_packet, 30));
                let prot_num = pcap_packet[23];
                transported_protocol = Some(to_transported_protocol(prot_num));
                if prot_num == 6 || prot_num == 17 { // TCP o UDP
                    source_port = Some(to_u16(&pcap_packet, 34));
                    destination_port = Some(to_u16(&pcap_packet, 36));
                }

                //UDP
                if prot_num == 17 {
                    match (source_port.unwrap(), destination_port.unwrap()) {
                        //well known ports (0-1023)
                        (53, _) => transported_protocol = Some("UDP (DNS Response)".to_string()),
                        (_, 53) => transported_protocol = Some("UDP (DNS Query)".to_string()),
                        (67, _) | (_, 67) => transported_protocol = Some("UDP (DHCP Server)".to_string()),
                        (68, _) | (_, 68) => transported_protocol = Some("UDP (DHCP Client)".to_string()),
                        (137, _) => transported_protocol = Some("UDP (NETBIOS name)".to_string()),
                        (138, _) => transported_protocol = Some("UDP (NETBIOS data)".to_string()),
                        (443, _) | (_, 443) => transported_protocol = Some("UDP (HTTPS)".to_string()),
                        (1900, _) | (_, 1900) => transported_protocol = Some("UDP (SSDP)".to_string()),
                        //others
                        (5353, _) | (_, 5353) => transported_protocol = Some("UDP (MDNS)".to_string()),
                        _ => (),
                    }
                }

                //TCP
                if prot_num == 6 {
                    match (source_port.unwrap(), destination_port.unwrap()) {
                        //well known ports (0-1023)
                        (20, _) | (_, 20) => transported_protocol = Some("TCP (FTP Data)".to_string()),
                        (21, _) | (_, 21) => transported_protocol = Some("TCP (FTP Control)".to_string()),
                        (22, _) | (_, 22) => transported_protocol = Some("TCP (SSH)".to_string()),
                        (23, _) | (_, 23) => transported_protocol = Some("TCP (Telnet)".to_string()),
                        (25, _) | (_, 25) => transported_protocol = Some("TCP (SMTP)".to_string()),
                        (80, _) | (_, 80) => transported_protocol = Some("TCP (HTTP)".to_string()),
                        (110, _) | (_, 110) => transported_protocol = Some("TCP (POP)".to_string()),
                        (143, _) | (_, 143) => transported_protocol = Some("TCP (IMAP4)".to_string()),
                        (443, _) | (_, 443) => transported_protocol = Some("TCP (HTTPS)".to_string()),
                        (465, _) | (_, 465) => transported_protocol = Some("TCP (SMTPS)".to_string()),
                        (587, _) | (_, 587) => transported_protocol = Some("TCP (SMTP Subm)".to_string()),
                        (993, _) | (_, 993) => transported_protocol = Some("TCP (IMAP4S)".to_string()),
                        (995, _) | (_, 995) => transported_protocol = Some("TCP (POP3S)".to_string()),
                        (1900, _) | (_, 1900) => transported_protocol = Some("TCP (SSDP)".to_string()),
                        //others
                        (5353, _) | (_, 5353) => transported_protocol = Some("TCP (MDNS)".to_string()),
                        _ => (),
                    }
                }
            }

            // IPv6
            0x86DD => {
                source_address = Some(to_ipv6_address(&pcap_packet, 22));
                destination_address = Some(to_ipv6_address(&pcap_packet, 38));

                let (prot, port_index) = get_ipv6_transported_protocol(&pcap_packet, (20, 34));
                transported_protocol = Some(prot.clone());
                if prot == "TCP".to_string() || prot == "UDP".to_string() { // TCP o UDP
                    source_port = Some(to_u16(&pcap_packet, port_index));
                    destination_port = Some(to_u16(&pcap_packet, port_index + 2));
                }


                //UDP
                if prot == "UDP" {
                    match (source_port.unwrap(), destination_port.unwrap()) {
                        //well known ports (0-1023)
                        (53, _) => transported_protocol = Some("UDP (DNS Response)".to_string()),
                        (_, 53) => transported_protocol = Some("UDP (DNS Query)".to_string()),
                        (67, _) | (_, 67) => transported_protocol = Some("UDP (DHCP Server)".to_string()),
                        (68, _) | (_, 68) => transported_protocol = Some("UDP (DHCP Client)".to_string()),
                        (137, _) => transported_protocol = Some("UDP (NETBIOS name)".to_string()),
                        (138, _) => transported_protocol = Some("UDP (NETBIOS data)".to_string()),
                        (443, _) | (_, 443) => transported_protocol = Some("UDP (HTTPS)".to_string()),
                        (546, 547) => transported_protocol = Some("UDP (DHCPv6 req.)".to_string()),
                        (547, 546) => transported_protocol = Some("UDP (DHCPv6 resp.)".to_string()),
                        (1900, _) | (_, 1900) => transported_protocol = Some("UDP (SSDP)".to_string()),
                        //others
                        (5353, _) | (_, 5353) => transported_protocol = Some("UDP (MDNS)".to_string()),
                        _ => (),
                    }
                }

                //TCP
                if prot == "TCP" {
                    match (source_port.unwrap(), destination_port.unwrap()) {
                        //well known ports (0-1023)
                        (20, _) | (_, 20) => transported_protocol = Some("TCP (FTP Data)".to_string()),
                        (21, _) | (_, 21) => transported_protocol = Some("TCP (FTP Control)".to_string()),
                        (22, _) | (_, 22) => transported_protocol = Some("TCP (SSH)".to_string()),
                        (23, _) | (_, 23) => transported_protocol = Some("TCP (Telnet)".to_string()),
                        (25, _) | (_, 25) => transported_protocol = Some("TCP (SMTP)".to_string()),
                        (80, _) | (_, 80) => transported_protocol = Some("TCP (HTTP)".to_string()),
                        (110, _) | (_, 110) => transported_protocol = Some("TCP (POP)".to_string()),
                        (143, _) | (_, 143) => transported_protocol = Some("TCP (IMAP4)".to_string()),
                        (443, _) | (_, 443) => transported_protocol = Some("TCP (HTTPS)".to_string()),
                        (465, _) | (_, 465) => transported_protocol = Some("TCP (SMTPS)".to_string()),
                        (546, 547) => transported_protocol = Some("TCP (DHCPv6 req.)".to_string()),
                        (547, 546) => transported_protocol = Some("TCP (DHCPv6 resp.)".to_string()),
                        (587, _) | (_, 587) => transported_protocol = Some("TCP (SMTP Subm)".to_string()),
                        (993, _) | (_, 993) => transported_protocol = Some("TCP (IMAP4S)".to_string()),
                        (995, _) | (_, 995) => transported_protocol = Some("TCP (POP3S)".to_string()),
                        (1900, _) | (_, 1900) => transported_protocol = Some("TCP (SSDP)".to_string()),
                        //others
                        (5353, _) | (_, 5353) => transported_protocol = Some("TCP (MDNS)".to_string()),
                        _ => (),
                    }
                }
            }

            // ARP | RARP
            0x0806 | 0x8035 => {
                // Sender IP
                source_address = Some(to_ip_address(&pcap_packet, 28));
                // Target IP
                destination_address = Some(to_ip_address(&pcap_packet, 38));
            }
            _ => ()
        }

        NAPacket {
            destination_mac_address: to_mac_address(&pcap_packet, 0),
            source_mac_address: to_mac_address(&pcap_packet, 6),
            level_three_type: to_level_three_protocol(to_u16(&pcap_packet, 12)),
            source_address,
            destination_address,
            total_length: pcap_packet.header.len,
            transported_protocol,
            source_port,
            destination_port,
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
        }
    }
    /// Formats the `NAPacket` source and destination MAC addresses.
    ///
    /// This function returns a [String] containing source and destination MAC addresses properly formatted to appear on the terminal.
    pub fn to_string_mac(&self) -> String {
        let mut s = String::new();
        s.push_str(&*("MAC_s: ".to_owned() + &self.source_mac_address + "  "
            + &*" MAC_d: ".to_owned() + &self.destination_mac_address));
        s
    }

    /// Formats the `NAPacket` source and destination level 3 addresses (IPv4 or IPv6).
    ///
    /// This function returns a [`String`] containing source and destination addresses properly formatted to appear on the terminal.
    ///
    /// Since IPv6 addresses can be longer then IPv4 ones, they cannot appear in the same line
    /// otherwise can generate issues when displayed on the terminal.
    ///
    /// It evaluates the space to put between the addresses based on their length, and then inserts it in the middle of the two.
    pub fn to_string_endpoints(&self) -> String {
        let mut s = String::new();
        let source = option_to_string(self.source_address.clone());
        let dest = option_to_string(self.destination_address.clone());
        let space = match (source, dest) {
            (s, _) if s.eq("None") => "\t\t",
            (s, d) if s.contains(":") && d.contains(":") => {
                let svec = s.as_str().split(":").collect::<Vec<&str>>();
                let dvec = d.as_str().split(":").collect::<Vec<&str>>();
                let sp = if svec.len() > 4 && dvec.len() > 4 { "\n" } else { "\t" };
                sp
            }
            _ => "\t"
        };

        s.push_str(&*("IP_s: ".to_owned() + &option_to_string(self.source_address.clone()) + space
            + &*"IP_d: ".to_owned() + &option_to_string(self.destination_address.clone())));
        s
    }

    /// Formats the `NAPacket` source and destination ports.
    ///
    /// This function returns a [`String`] containing the source and destination ports properly formatted to appear on the terminal.

    pub fn to_string_ports(&self) -> String {
        let mut s = String::new();
        s.push_str(&*("Port_s: ".to_owned() + &option_to_string(self.source_port) + "\t\t  "
            + &*"Port_d: ".to_owned() + &option_to_string(self.destination_port)));
        s
    }

    /// Formats the `NAPacket` transported protocols, length and timestamp.
    ///
    /// This function returns a [`String`] containing protocols transported, length and timestamp properly formatted to appear on the terminal.

    pub fn info(&self) -> String {
        let mut s = String::new();
        s.push_str(&*("L3_type: ".to_owned() + &self.level_three_type.to_string()
            + &*" Len: ".to_owned() + &self.total_length.to_string()
            + &*" Prot: ".to_owned() + &option_to_string(self.transported_protocol.clone())
            + &*" TS: ".to_owned() + &self.timestamp.to_string()));
        s
    }

    ///* Returns `true` if the given `NAPacket` passes the given filter
    ///* Returns `false` if the given `NAPacket` doesn't pass the given filter
    ///
    /// This function receives a `Filter` tag and checks if the receiver (`NAPacket`)
    /// passes or not the filter.
    ///
    ///<br></br>
    ///<i>Example:</i>
    ///- The filter is `Filter::IP(192.168.1.1)` => if a 192.168.1.1 ip address is found
    /// to be either the level 3 source or destination of the packet, `true` is returned.
    ///- The filter is `Filter::ARP` => if the level three type of the packet is found to be
    ///"ARP", `true` is returned.
    ///- The filter is `Filter::None` => `true` is returned whatever packet is inspected
    pub fn filter(&self, filter: Filter) -> bool {
        match filter {
            Filter::None => true,
            Filter::IPv4 if self.level_three_type == "IPv4" => true,
            Filter::IPv6 if self.level_three_type == "IPv6" => true,
            Filter::ARP if self.level_three_type == "ARP" => true,
            Filter::IP(ip) => {
                if self.source_address.is_some() && self.destination_address.is_some() {
                    return ip == *self.destination_address.as_ref().unwrap() || ip == *self.source_address.as_ref().unwrap();
                }
                false
            }
            Filter::Port(port) => {
                if self.source_port.is_some() && self.destination_port.is_some() {
                    return port == self.source_port.unwrap() || port == self.destination_port.unwrap();
                }
                false
            }

            Filter::LT(len) => self.total_length < len,

            Filter::LE(len) => self.total_length <= len,

            Filter::EQ(len) => self.total_length == len,

            Filter::GT(len) => self.total_length > len,

            Filter::GE(len) => self.total_length >= len,

            _ => false,
        }
    }
}

impl Display for NAPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let format = self.to_string_mac().as_str().to_owned() + "\n" +
            self.to_string_endpoints().as_str() + "\n" +
            self.to_string_ports().as_str() + "\n" +
            self.info().as_str() + "\n";
        write!(f, "{}", format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_packet_by_type(l3type: &str) -> Option<NAPacket> {
        match l3type {
            "IPv4" => Some(NAPacket {
                destination_mac_address: "DE:25:50:20:C3:C1".to_string(),
                source_mac_address: "01:00:5E:00:00:FB".to_string(),
                level_three_type: "IPv4".to_string(),
                total_length: 191,
                source_address: Some("192.168.1.249".to_string()),
                destination_address: Some("224.0.0.251".to_string()),
                transported_protocol: Some("UDP (MDNS)".to_string()),
                source_port: Some(5353),
                destination_port: Some(5353),
                timestamp: 1168461365594,
            }),

            "IPv6" => Some(NAPacket {
                destination_mac_address: "DE:25:50:20:C3:C1".to_string(),
                source_mac_address: "01:00:5E:00:00:FB".to_string(),
                level_three_type: "IPv6".to_string(),
                total_length: 86,
                source_address: Some("fe80::1213:31ff:fed6:8cca".to_string()),
                destination_address: Some("ff02::1:fffb:12b5".to_string()),
                transported_protocol: Some("UDP (MDNS)".to_string()),
                source_port: Some(5353),
                destination_port: Some(5353),
                timestamp: 1168461365594,
            }),

            "ARP" => Some(NAPacket {
                destination_mac_address: "DE:25:50:20:C3:C1".to_string(),
                source_mac_address: "FF:FF:FF:FF:FF:FF".to_string(),
                level_three_type: "ARP".to_string(),
                total_length: 60,
                source_address: Some("192.168.1.249".to_string()),
                destination_address: Some("192.168.1.248".to_string()),
                transported_protocol: None,
                source_port: None,
                destination_port: None,
                timestamp: 1168461365594,
            }),

            _ => None
        }
    }

    #[test]
    fn test_filter_ipv4_1() {
        assert!(get_packet_by_type("IPv4").unwrap().filter(Filter::IPv4))
    }

    #[test]
    fn test_filter_ipv6_1() {
        assert!(!get_packet_by_type("IPv4").unwrap().filter(Filter::IPv6))
    }

    #[test]
    fn test_filter_arp_1() {
        assert!(!get_packet_by_type("IPv4").unwrap().filter(Filter::ARP))
    }

    #[test]
    fn test_filter_port_1_1() {
        assert!(get_packet_by_type("IPv4").unwrap().filter(Filter::Port(5353)))
    }

    #[test]
    fn test_filter_ip_1_1() {
        assert!(!get_packet_by_type("IPv4").unwrap().filter(Filter::IP("192.168.1.5".to_string())))
    }

    #[test]
    fn test_filter_ip_1_2() {
        assert!(get_packet_by_type("IPv4").unwrap().filter(Filter::IP("192.168.1.249".to_string())))
    }

    #[test]
    fn test_filter_port_1_2() {
        assert!(!get_packet_by_type("IPv4").unwrap().filter(Filter::Port(8080)))
    }

    #[test]
    fn test_filter_ipv4_2() {
        assert!(!get_packet_by_type("IPv6").unwrap().filter(Filter::IPv4))
    }

    #[test]
    fn test_filter_ipv6_2() {
        assert!(get_packet_by_type("IPv6").unwrap().filter(Filter::IPv6))
    }

    #[test]
    fn test_filter_arp_2() {
        assert!(!get_packet_by_type("IPv6").unwrap().filter(Filter::ARP))
    }

    #[test]
    fn test_filter_ip_2_1() {
        assert!(get_packet_by_type("IPv6").unwrap().filter(Filter::IP("fe80::1213:31ff:fed6:8cca".to_string())))
    }

    #[test]
    fn test_filter_ip_2_2() {
        assert!(!get_packet_by_type("IPv6").unwrap().filter(Filter::IP("fe80::1213:31ff:fed6:ffff".to_string())))
    }

    #[test]
    fn test_filter_arp_3() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::ARP))
    }

    #[test]
    fn test_filter_ge_1() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::GE(61)))
    }

    #[test]
    fn test_filter_ge_2() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::GE(59)))
    }

    #[test]
    fn test_filter_ge_3() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::GE(60)))
    }

    #[test]
    fn test_filter_gt_1() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::GT(59)))
    }

    #[test]
    fn test_filter_gt_2() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::GT(60)))
    }

    #[test]
    fn test_filter_gt_3() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::GT(61)))
    }

    #[test]
    fn test_filter_eq_1() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::EQ(59)))
    }

    #[test]
    fn test_filter_eq_2() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::EQ(60)))
    }

    #[test]
    fn test_filter_eq_3() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::EQ(61)))
    }

    #[test]
    fn test_filter_le_1() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::LE(59)))
    }

    #[test]
    fn test_filter_le_2() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::LE(60)))
    }

    #[test]
    fn test_filter_le_3() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::LE(61)))
    }

    #[test]
    fn test_filter_lt_1() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::LT(59)))
    }

    #[test]
    fn test_filter_lt_2() {
        assert!(!get_packet_by_type("ARP").unwrap().filter(Filter::LT(60)))
    }

    #[test]
    fn test_filter_lt_3() {
        assert!(get_packet_by_type("ARP").unwrap().filter(Filter::LT(61)))
    }
}
