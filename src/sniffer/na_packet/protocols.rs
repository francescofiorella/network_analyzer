use std::net::{Ipv4Addr, Ipv6Addr};
use mac_address::MacAddress;
use crate::sniffer::format::to_u16;

/// Casts a sequence of bytes into a MAC address.
///
/// This function takes a `&[u8]` representing a `Packet` of `pcap` library and a [usize] as index from which start to extract the MAC address and
/// returns a [String] containing the MAC address properly formatted.

pub(crate) fn to_mac_address(p: &[u8], start: usize) -> String {
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

pub(crate) fn to_ip_address(p: &[u8], start: usize) -> String {
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
pub(crate) fn to_ipv6_address(p: &[u8], start: usize) -> String {
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

pub(crate) fn to_transported_protocol(prot_num: u8) -> String {
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

pub(crate) fn to_level_three_protocol(prot_num: u16) -> String {
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
pub(crate) fn get_ipv6_transported_protocol(p: &[u8], (next_header_index, remaining_size): (usize, usize)) -> (String, usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample_packet(n: u32) -> &'static [u8] {
        match n {
            0 => &[16, 19, 49, 214, 140, 202, 144, 156, 74, 210, 12, 51, 134, 221, 96, 11, 14, 0, 0, 41, 17, 64, 32, 1, 11, 7, 10, 150, 30, 12, 172, 137, 153, 5, 61, 147, 27, 58, 42, 0, 20, 80, 64, 2, 4, 17, 0, 0, 0, 0, 0, 0, 32, 14, 220, 116, 1, 187, 0, 41, 236, 84, 94, 214, 127, 43, 147, 16, 131, 228, 17, 147, 83, 124, 249, 204, 188, 18, 239, 231, 24, 152, 231, 25, 129, 214, 69, 36, 167, 48, 253, 75, 153, 167, 156],
            1 => &[255, 255, 255, 255, 255, 255, 16, 19, 49, 214, 140, 202, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1, 16, 19, 49, 214, 140, 202, 192, 168, 1, 254, 0, 0, 0, 0, 0, 0, 192, 168, 1, 231],
            2 => &[1, 0, 94, 0, 0, 251, 222, 37, 80, 32, 195, 193, 8, 0, 69, 0, 2, 111, 181, 177, 0, 0, 255, 17, 96, 47, 192, 168, 1, 249, 224, 0, 0, 251, 20, 233, 20, 233, 2, 91, 166, 37, 0, 0, 132, 0, 0, 0, 0, 10, 0, 0, 0, 6, 9, 95, 115, 101, 114, 118, 105, 99, 101, 115, 7, 95, 100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 0, 0, 17, 148, 0, 15, 7, 95, 114, 100, 108, 105, 110, 107, 4, 95, 116, 99, 112, 192, 35, 192, 52, 0, 12, 0, 1, 0, 0, 17, 148, 0, 22, 19, 105, 80, 104, 111, 110, 101, 32, 100, 105, 32, 65, 110, 116, 111, 110, 101, 108, 108, 111, 192, 52, 19, 105, 80, 104, 111, 110, 101, 32, 100, 105, 32, 65, 110, 116, 111, 110, 101, 108, 108, 111, 12, 95, 100, 101, 118, 105, 99, 101, 45, 105, 110, 102, 111, 192, 60, 0, 16, 0, 1, 0, 0, 17, 148, 0, 13, 12, 109, 111, 100, 101, 108, 61, 68, 51, 50, 49, 65, 80, 192, 79, 0, 33, 128, 1, 0, 0, 0, 120, 0, 28, 0, 0, 0, 0, 192, 2, 19, 105, 80, 104, 111, 110, 101, 45, 100, 105, 45, 65, 110, 116, 111, 110, 101, 108, 108, 111, 192, 35, 1, 54, 1, 68, 1, 66, 1, 69, 1, 51, 1, 70, 1, 52, 1, 52, 1, 57, 1, 48, 1, 50, 1, 67, 1, 48, 1, 65, 1, 56, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 56, 1, 69, 1, 70, 3, 105, 112, 54, 4, 97, 114, 112, 97, 0, 0, 12, 128, 1, 0, 0, 0, 120, 0, 2, 192, 177, 1, 67, 1, 55, 1, 50, 1, 49, 1, 54, 1, 69, 1, 48, 1, 66, 1, 55, 1, 67, 1, 49, 1, 66, 1, 55, 1, 66, 1, 52, 1, 49, 1, 67, 1, 48, 1, 69, 1, 49, 1, 54, 1, 57, 1, 65, 1, 48, 1, 55, 1, 48, 1, 66, 1, 48, 1, 49, 1, 48, 1, 48, 1, 50, 193, 7, 0, 12, 128, 1, 0, 0, 0, 120, 0, 2, 192, 177, 3, 50, 52, 57, 1, 49, 3, 49, 54, 56, 3, 49, 57, 50, 7, 105, 110, 45, 97, 100, 100, 114, 193, 11, 0, 12, 128, 1, 0, 0, 0, 120, 0, 2, 192, 177, 192, 177, 0, 28, 128, 1, 0, 0, 0, 120, 0, 16, 254, 128, 0, 0, 0, 0, 0, 0, 8, 160, 194, 9, 68, 243, 235, 214, 192, 177, 0, 28, 128, 1, 0, 0, 0, 120, 0, 16, 32, 1, 11, 7, 10, 150, 30, 12, 20, 183, 177, 199, 176, 230, 18, 124, 192, 177, 0, 1, 128, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 249, 192, 79, 0, 47, 128, 1, 0, 0, 0, 120, 0, 9, 192, 79, 0, 5, 0, 0, 128, 0, 64, 192, 199, 0, 47, 128, 1, 0, 0, 0, 120, 0, 6, 192, 199, 0, 2, 0, 8, 193, 29, 0, 47, 128, 1, 0, 0, 0, 120, 0, 6, 193, 29, 0, 2, 0, 8, 193, 107, 0, 47, 128, 1, 0, 0, 0, 120, 0, 6, 193, 107, 0, 2, 0, 8, 192, 177, 0, 47, 128, 1, 0, 0, 0, 120, 0, 8, 192, 177, 0, 4, 64, 0, 0, 8, 0, 0, 41, 5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 18, 66, 183, 190, 175, 252, 41, 222, 37, 80, 32, 195, 193],
            3 => &[144, 156, 74, 210, 12, 51, 16, 19, 49, 214, 140, 202, 134, 221, 104, 13, 1, 33, 0, 32, 6, 123, 42, 0, 20, 80, 64, 19, 12, 7, 0, 0, 0, 0, 0, 0, 0, 188, 32, 1, 11, 7, 10, 150, 30, 12, 172, 137, 153, 5, 61, 147, 27, 58, 20, 108, 220, 159, 19, 96, 56, 166, 80, 187, 215, 91, 128, 16, 1, 9, 114, 40, 0, 0, 1, 1, 8, 10, 115, 22, 6, 117, 43, 14, 124, 156],
            _ => &[]
        }
    }

    #[test]
    fn test_valid_dst_mac_address(){
        let packet = create_sample_packet(0);
        let result = "10:13:31:D6:8C:CA";
        assert_eq!(to_mac_address(packet,0), result);
    }

    #[test]
    fn test_wrong_dst_mac_address(){
        let packet = create_sample_packet(0);
        let result = "10:13:31:D6:8C:AA";
        assert_ne!(to_mac_address(&packet,0), result);
    }

    #[test]
    fn test_valid_src_mac_address(){
        let packet = create_sample_packet(0);
        let result = "90:9C:4A:D2:0C:33";
        assert_eq!(to_mac_address(&packet,6), result);
    }

    #[test]
    fn test_wrong_src_mac_address(){
        let packet = create_sample_packet(0);
        let result = "10:13:31:D6:8C:BB";
        assert_ne!(to_mac_address(&packet,6), result);
    }

    #[test]
    fn test_wrong_start_value_to_mac_address(){
        let packet = create_sample_packet(0);
        let result = "10:13:31:D6:8C:CA";
        assert_ne!(to_mac_address(&packet,3), result);
    }

    #[test]
    fn test_valid_src_ip_address_arp(){
        let packet = create_sample_packet(1);
        let result = "192.168.1.254";
        assert_eq!(to_ip_address(&packet,28),result);
    }

    #[test]
    fn test_valid_dst_ip_address_arp(){
        let packet = create_sample_packet(1);
        let result = "192.168.1.231";
        assert_eq!(to_ip_address(&packet,38),result);
    }

    #[test]
    fn test_wrong_src_ip_address_arp(){
        let packet = create_sample_packet(1);
        let result = "192.168.1.1";
        assert_ne!(to_ip_address(&packet,28),result);
    }

    #[test]
    fn test_wrong_dst_ip_address_arp(){
        let packet = create_sample_packet(1);
        let result = "192.168.1.1";
        assert_ne!(to_ip_address(&packet,38),result);
    }

    #[test]
    fn test_valid_src_ip_address(){
        let packet = create_sample_packet(2);
        let result = "192.168.1.249";
        assert_eq!(to_ip_address(&packet,26),result);
    }

    #[test]
    fn test_valid_dst_ip_address(){
        let packet = create_sample_packet(2);
        let result = "224.0.0.251";
        assert_eq!(to_ip_address(&packet,30),result);
    }

    #[test]
    fn test_wrong_src_ip_address(){
        let packet = create_sample_packet(2);
        let result = "192.168.1.1";
        assert_ne!(to_ip_address(&packet,26),result);
    }

    #[test]
    fn test_wrong_dst_ip_address(){
        let packet = create_sample_packet(2);
        let result = "224.0.0.1";
        assert_ne!(to_ip_address(&packet,30),result);
    }

    #[test]
    fn test_wrong_start_value_to_ip_address(){
        let packet = create_sample_packet(2);
        let result = "224.0.0.1";
        assert_ne!(to_ip_address(&packet,29),result);
    }

    #[test]
    fn test_valid_src_ipv6_address(){
        let packet = create_sample_packet(3);
        let result = "2a00:1450:4013:c07::bc";
        assert_eq!(to_ipv6_address(&packet,22),result);
    }

    #[test]
    fn test_valid_dst_ipv6_address(){
        let packet = create_sample_packet(3);
        let result = "2001:b07:a96:1e0c:ac89:9905:3d93:1b3a";
        assert_eq!(to_ipv6_address(&packet,38),result);
    }

    #[test]
    fn test_wrong_src_ipv6_address(){
        let packet = create_sample_packet(3);
        let result = "2a00:1450:4013:c07::cc";
        assert_ne!(to_ipv6_address(&packet,22),result);
    }

    #[test]
    fn test_wrong_dst_ipv6_address(){
        let packet = create_sample_packet(3);
        let result = "2001:b07:a96:1e0c:ac89:9905:3d93:1b33";
        assert_ne!(to_ipv6_address(&packet,38),result);
    }

    #[test]
    fn test_wrong_start_value_to_ipv6_address(){
        let packet = create_sample_packet(3);
        let result = "2a00:1450:4013:c07::bc";
        assert_ne!(to_ipv6_address(&packet,20),result);
    }

    #[test]
    fn test_valid_transported_protocol(){
        let prot_num = 1;
        let result = "ICMP";
        assert_eq!(to_transported_protocol(prot_num),result);
    }

    #[test]
    fn test_wrong_transported_protocol(){
        let prot_num = 250;
        let result = "Unknown";
        assert_eq!(to_transported_protocol(prot_num),result);
    }

    #[test]
    fn test_valid_level_3_protocol(){
        let prot_num = 0x0800;
        let result = "IPv4";
        assert_eq!(to_level_three_protocol(prot_num),result);
    }

    #[test]
    fn test_wrong_transported_protocol_value(){
        let prot_num = 0x0888;
        let result = "Unknown";
        assert_eq!(to_level_three_protocol(prot_num),result);
    }
}