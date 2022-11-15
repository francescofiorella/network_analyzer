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


mod protocols {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use mac_address::MacAddress;
    use crate::sniffer::format::to_u16;

    /// Casts a sequence of bytes into a MAC address.
    ///
    /// This function takes a `&[u8]` representing a `Packet` of `pcap` library and a [usize] as index from which start to extract the MAC address and
    /// returns a [String] containing the MAC address properly formatted.

    pub fn to_mac_address(p: &[u8], start: usize) -> String {
        MacAddress::new([
            p[start],
            p[start + 1],
            p[start + 2],
            p[start + 3],
            p[start + 4],
            p[start + 5]
        ]).to_string()
    }

    /// Casts a sequence of bytes into an IPv4 address.
    ///
    /// This function takes a `&[u8]` representing a `Packet` of `pcap` library and a [usize] as index from which start to extract the IPv4 address and
    /// returns a [String] containing the IPv4 address properly formatted.

    pub fn to_ip_address(p: &[u8], start: usize) -> String {
        Ipv4Addr::new(
            p[start],
            p[start + 1],
            p[start + 2],
            p[start + 3],
        ).to_string()
    }

    /// Casts a sequence of bytes into an IPv6 address.
    ///
    /// This function takes a `&[u8]` representing a `Packet` of `pcap` library and a [usize] as index from which start to extract the IPv6 address and
    /// returns a [String] containing the IPv6 address properly formatted.
    pub fn to_ipv6_address(p: &[u8], start: usize) -> String {
        Ipv6Addr::new(
            to_u16(p, start),
            to_u16(p, start + 2),
            to_u16(p, start + 4),
            to_u16(p, start + 6),
            to_u16(p, start + 8),
            to_u16(p, start + 10),
            to_u16(p, start + 12),
            to_u16(p, start + 14),
        ).to_string()
    }

    /// Converts an integer value into the corresponding transported protocol.
    ///
    /// This function takes a [u8] representing the value written inside the protocol field of a pcap `Packet` and returns a [String]
    /// containing the actual transported protocol's name.
    ///
    /// The range of admissible values ranges from 1 to 142 (extremes included) excluding 43, 44, 51, 60 and 135.
    /// All the values outside this range will return a [String] containing "Unknown".

    pub fn to_transported_protocol(prot_num: u8) -> String {
        match prot_num {
            // 0, 43, 44, 51, 60, 135 have already been managed (SHOULD NOT BE POSSIBLE)
            6 => "TCP", // Transmission Control Protocol
            17 => "UDP", // User Datagram Protocol

            // No Ports
            1 => "ICMP", // Internet Control Message Protocol
            2 => "IGMP", // Internet Group Management Protocol
            4 => "IP-in-IP", // IP in IP (encapsulation)
            41 => "IPv6", // IPv6 Encapsulation
            50 => "ESP", // Encapsulating Security Payload [IPv6]
            58 => "ICMPv6", // ICMP for IPv6
            59 => "NoNxt", // No Next Header [IPv6]

            3 => "GGP", // Gateway-to-Gateway Protocol
            5 => "ST", // Internet Stream Protocol
            7 => "CBT", // Core-based trees
            8 => "EGP", // Exterior Gateway Protocol
            9 => "IGP", // Interior Gateway Protocol
            10 => "BBN-RCC-MON", // BBN RCC Monitoring
            11 => "NVP-II", // Network Voice Protocol
            12 => "PUP", // Xerox PUP
            13 => "ARGUS",
            14 => "EMCON",
            15 => "XNET", // Cross Net Debugger
            16 => "CHAOS",
            18 => "MUX", // Multiplexing
            19 => "DCN-MEAS", // DCN Measurement Subsystems
            20 => "HMP", // Host Monitoring Protocol
            21 => "PRM", // Packet Radio Measurement
            22 => "XNS-IDP", // XEROX NS IDP
            23 => "TRUNK-1",
            24 => "TRUNK-2",
            25 => "LEAF-1",
            26 => "LEAF-2",
            27 => "RDP", // Reliable Data Protocol
            28 => "IRTP", // Internet Reliable Transaction Protocol
            29 => "ISO-TP4", // ISO Transport Protocol Class 4
            30 => "NETBLT", // Bulk Data Transfer Protocol
            31 => "MFE-NSP", // MFE Network Services Protocol
            32 => "MERIT-INP", // MERIT Internodal Protocol
            33 => "DCCP", // Datagram Congestion Control Protocol
            34 => "3PC", // Third Party Connect Protocol
            35 => "IDPR", // Inter-Domain Policy Routing Protocol
            36 => "XTP", // Xpress Transport Protocol
            37 => "DDP", // Datagram Delivery Protocol
            38 => "IDPR-CMTP", // IDPR Control Message Transport Protocol
            39 => "TP++", // TP++ Transport Protocol
            40 => "IL", // IL Transport Protocol
            42 => "SDRP", // Source Demand Routing Protocol
            45 => "IDRP", // Inter-Domain Routing Protocol
            46 => "RSVP", // Resource Reservation Protocol
            47 => "GRE", // Generic Routing Encapsulation
            48 => "DSR", // Dynamic Source Routing Protocol
            49 => "BNA", // Burroughs Network Architecture
            52 => "I-NLSP", // Integrated Net Layer Security Protocol
            53 => "SwIPe",
            54 => "NARP", // NBMA Address Resolution Protocol
            55 => "MOBILE", // IP Mobility
            56 => "TLSP", // Transport Layer Security Protocol
            57 => "SKIP", // Simple Key-Management for Internet Protocol
            62 => "CFTP",
            64 => "SAT-EXPAK", // SATNET and Backroom EXPAK
            65 => "KRYPTOLAN",
            66 => "RVD", // MIT Remote Virtual Disk Protocol
            67 => "IPPC", // Internet Pluribus Packet Core
            69 => "SAT-MON", // SATNET Monitoring
            70 => "VISA", // VISA Protocol
            71 => "IPCU", // Internet Packet Core Utility
            72 => "CPNX", // Computer Protocol Network Executive
            73 => "CPHB", // Computer Protocol Heart Beat
            74 => "WSN", // Wang Span Network
            75 => "PVP", // Packet Video Protocol
            76 => "BR-SAT-MON", // Backroom SATNET Monitoring
            77 => "SUN-ND", // SUN ND PROTOCOL-Temporary
            78 => "WB-MON", // WIDEBAND Monitoring
            79 => "WB-EXPAK", // WIDEBAND EXPAK
            80 => "ISO-IP", // International Organization for Standardization Internet Protocol
            81 => "VMTP", // Versatile Message Transaction Protocol
            82 => "SECURE-VMTP", // Secure Versatile Message Transaction Protocol
            83 => "VINES",
            84 => "TTP", // Time-Triggered Protocol
            85 => "NSFNET-IGP",
            86 => "DGP", // Dissimilar Gateway Protocol
            87 => "TCF",
            88 => "EIGRP",
            89 => "OSPF", // Open Shortest Path First
            90 => "Sprite-RPC", // Sprite RPC Protocol
            91 => "LARP", // Locus Address Resolution Protocol
            92 => "MTP", // Multicast Transport Protocol
            93 => "AX.25",
            94 => "OS", // KA9Q NOS compatible IP over IP tunneling
            95 => "MICP", // Mobile Internetworking Control Protocol
            96 => "SCC-SP", // Semaphore Communications Sec. Pro
            97 => "ETHERIP", // Ethernet-within-IP Encapsulation
            98 => "ENCAP", // Encapsulation Header
            100 => "GMTP",
            101 => "IFMP", // Ipsilon Flow Management Protocol
            102 => "PNNI", // PNNI over IP
            103 => "PIM", // Protocol Independent Multicast
            104 => "ARIS", // IBM's ARIS (Aggregate Route IP Switching) Protocol
            105 => "SCPS", // Space Communications Protocol Standards
            106 => "QNX",
            107 => "A/N", // Active Networks
            108 => "IPComp", // IP Payload Compression Protocol
            109 => "SNP", // Sitara Networks Protocol
            110 => "Compaq-Peer", // Compaq Peer Protocol
            111 => "IPX-in-IP", // IPX in IP
            112 => "VRRP", // Virtual Router Redundancy Protocol
            113 => "PGM", // PGM Reliable Transport Protocol
            115 => "L2TP", // Layer Two Tunneling Protocol Version 3
            116 => "DDX", // D-II Data Exchange (DDX)
            117 => "IATP", // Interactive Agent Transfer Protocol
            118 => "STP", // Schedule Transfer Protocol
            119 => "SRP", // SpectraLink Radio Protocol
            120 => "UTI", // Universal Transport Interface Protocol
            121 => "SMP", // Simple Message Protocol
            122 => "SM", // Simple Multicast Protocol
            123 => "PTP", // Performance Transparency Protocol
            124 => "IS-IS over IPv4", // Intermediate System to Intermediate System Protocol over IPv4
            125 => "FIRE", // Flexible Intra-AS Routing Environment
            126 => "CRTP", // Combat Radio Transport Protocol
            127 => "CRUDP", // Combat Radio User Datagram
            128 => "SSCOPMCE", // Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment
            129 => "IPLT",
            130 => "SPS", // Secure Packet Shield
            131 => "PIPE", // Private IP Encapsulation within IP
            132 => "SCTP", // Stream Control Transmission Protocol
            133 => "FC", // Fibre Channel
            134 => "RSVP-E2E-IGNORE", // Reservation Protocol (RSVP) End-to-End Ignore
            136 => "UDPLite", // Lightweight User Datagram Protocol
            137 => "MPLS-in-IP", // Multiprotocol Label Switching Encapsulated in IP
            138 => "manet", // MANET Protocols
            139 => "HIP", // Host Identity Protocol
            140 => "Shim6", // Site Multihoming by IPv6 Intermediation
            141 => "WESP", // Wrapped Encapsulating Security Payload
            142 => "ROHC", // Robust Header Compression

            _ => "Unknown"
        }.to_string()
    }

    /// Converts an integer value into the corresponding level 3 protocol.
    ///
    /// This function takes a [u16] representing the hexadecimal value written inside the 2 bytes of the protocol field of a pcap `Packet` and returns a [String]
    /// containing the actual level 3 protocol's name.
    ///
    /// The list of the accepted hexadecimal values is: 0x0800, 0x86DD, 0x0806, 0x8035, 0x0842, 0x22F0, 0x22F3, 0x22EA, 0x6002, 0x6003, 0x6004
    /// 0x809B, 0x80F3, 0x8100, 0x8102, 0x8103, 0x8137, 0x8204, 0x8808, 0x8809, 0x8819, 0x8847, 0x8848, 0x8863, 0x8864, 0x887B, 0x888E, 0x8892, 0x889A,
    /// 0x88A2, 0x88A4, 0x88A8, 0x88AB, 0x88B8, 0x88B9, 0x88BA, 0x88BF, 0x88CC, 0x88CD, 0x88E1, 0x88E3, 0x88E5, 0x88E7, 0x88F7, 0x88F8, 0x88FB, 0x8902,
    /// 0x8906, 0x8914, 0x8915, 0x891D, 0x893A, 0x892F, 0x9000, 0xF1C1.
    ///
    /// All the values outside this range will return a [String] containing "Unknown".

    pub fn to_level_three_protocol(prot_num: u16) -> String {
        match prot_num {
            0x0800 => "IPv4", // Internet Protocol version 4
            0x86DD => "IPv6", // Internet Protocol version 6

            // No Ports
            0x0806 => "ARP", // Address Resolution Protocol
            0x8035 => "RARP", // Reverse ARP

            // No IP Addresses, No Ports
            0x0842 => "WOL", // Wake-on-Lan
            0x22F0 => "AVTP", // Audio Video Transport Protocol
            0x22F3 => "TRILL", // IETF TRILL Protocol
            0x22EA => "SRP", // Stream Reservation Protocol
            0x6002 => "MOP", // DEC MOP RC
            0x6003 => "DECnet", // DECnet Phase IV, DNA Routing
            0x6004 => "LAT", // DEC LAT
            0x809B => "Ethertalk", // AppleTalk Ethertalk
            0x80F3 => "AARP", // AppleTalk ARP
            0x8100 => "IEEE 802.1Q",
            0x8102 => "SLPP", // Simple Loop Prevention Protocol
            0x8103 => "VLACP", // Virtual Link Aggregation Control Protocol
            0x8137 => "IPX", // Internetwork Packet Exchange (It has addresses, but not IP)
            0x8204 => "QNX Qnet", // QNX Qnet
            0x8808 => "EFC", // Ethernet Flow Control
            0x8809 => "LACP", // Link Aggregation Control Protocol
            0x8819 => "CobraNet",
            0x8847 => "MPLS U", // Multiprotocol Label Switching Unicast
            0x8848 => "MPLS M", // MPLS Multicast
            0x8863 => "PPPoE DS", // Point-to-Point Protocol over Ethernet Discovery Stage
            0x8864 => "PPPoE SS", // PPPoE Session Stage
            0x887B => "HomePlug 1.0 MME",
            0x888E => "EAPoL", // EAP over LAN (IEEE 802.1X)
            0x8892 => "PROFINET",
            0x889A => "SCSIoE", // HyperSCSI (SCSI over Ethernet)
            0x88A2 => "ATAoE", // ATA over Ethernet
            0x88A4 => "EtherCAT", // Ethernet for Control Automation Technology Protocol
            0x88A8 => "IEEE 802.1ad", // Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.
            0x88AB => "Ethernet Powerlink",
            0x88B8 => "GOOSE", // Generic Object Oriented Substation Event
            0x88B9 => "GSE", // Generic Substation Events Management Services
            0x88BA => "SV", // Sampled Value Transmission
            0x88BF => "RoMON", // MikroTik RoMON
            0x88CC => "LLDP", // Link Layer Discovery Protocol
            0x88CD => "SERCOS III",
            0x88E1 => "HomePlug Green PHY",
            0x88E3 => "MRP", // Media Redundancy Protocol (IEC62439-2)
            0x88E5 => "MACsec", // IEEE 802.1AE MAC security
            0x88E7 => "PBB", // Provider Backbone Bridges (IEEE 802.1ah)
            0x88F7 => "PTP", // Precision Time Protocol over IEEE 802.3 Ethernet
            0x88F8 => "NC-SI", // Network Controller Sideband Interface
            0x88FB => "PRP", // Parallel Redundancy Protocol
            0x8902 => "CFM/OAM", // IEEE 802.1ag Connectivity Fault Management Protocol / ITU-T Recommendation Y.1731
            0x8906 => "FCoE", // Fibre Channel over Ethernet
            0x8914 => "FCoE IP", // FCoE Initialization Protocol
            0x8915 => "RoCE", // RDMA over Converged Ethernet
            0x891D => "TTE", // TTEthernet Protocol Control Frame
            0x893a => "IEEE 1905",
            0x892F => "HSR", // High-availability Seamless Redundancy
            0x9000 => "ECTP", // Ethernet Configuration Testing Protocol
            0xF1C1 => "TSN", // Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)

            _ => "Unknown"
        }.to_string()
    }

    /// Slides the IPv6 headers until it finds another protocol, so it returns a pair
    /// composed by the transported protocol's name and the index of the first byte
    /// of its header.
    ///
    /// This function gets two arguments:
    /// * The packet to be processed as an array of u8.
    /// * A pair composed by the "next header index" which refers to the first byte
    /// of the next header to be processed and by the "remaining size" which is the
    /// remaining dimension (in bytes) of the header.
    ///
    /// The function slides the IPv6 header until it finds the "Next Header" field,
    /// if it indicates an IPv6 Extension Header, it calculates the remaining length
    /// of the first header and then calls again the function (in a recursive call),
    /// otherwise it calls `to_transported_protocol(prot_num)` and returns.
    ///
    /// It panics if the index exceed the array length.
    pub fn get_ipv6_transported_protocol(p: &[u8], (next_header_index, remaining_size): (usize, usize)) -> (String, usize) {
        let new_start = next_header_index + remaining_size;
        match p[next_header_index] {
            // Hop-by-Hop Options | Routing | Destination Options | Mobility
            0 | 43 | 60 | 135 => get_ipv6_transported_protocol(p, (new_start, (p[new_start + 1] * 8 + 8) as usize)),
            // Fragment
            44 => get_ipv6_transported_protocol(p, (new_start, 8)),
            // Authentication Header (AH)
            51 => get_ipv6_transported_protocol(p, (new_start, ((p[new_start + 1] + 2) * 4) as usize)),
            // Other
            prot_num => (to_transported_protocol(prot_num), new_start)
        }
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
