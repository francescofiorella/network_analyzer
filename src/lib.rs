pub mod sniffer {
    use pcap::{Capture, Device};
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::mpsc::Receiver;
    use std::thread::{JoinHandle, sleep, spawn};
    use std::time::Duration;
    use pcap::Error::TimeoutExpired;
    use crate::sniffer::channel::{Message, SnifferChannel};
    use crate::sniffer::filter::get_filter;
    use crate::sniffer::format::get_file_name;
    use crate::sniffer::na_error::NAError;
    use crate::sniffer::na_packet::NAPacket;
    use crate::sniffer::na_state::NAState;
    use crate::sniffer::na_state::NAState::{PAUSED, RESUMED, STOPPED};
    use crate::sniffer::stats::{produce_report, Stats};

    ///Returns the nth `Device` of the device list, or an error if it doesn't exist
    ///
    ///This function takes an u8 representing the index associated to a device within
    ///the network device list and returns a Result, containing either a proper pcap
    /// `Device` object, or a `NAError`
    pub fn get_adapter(adapter: u8) -> Result<Device, NAError> {
        let device_list = Device::list().unwrap();
        let mut couple = Vec::<(u8, Device)>::new();
        for (index, device) in device_list.into_iter().enumerate() {
            couple.push((index as u8 + 1, device));
        }
        let device = match couple.into_iter().find(|c| c.0 == adapter) {
            Some((_, dev)) => dev,
            None => return Err(NAError::new("Device not found")),
        };

        Ok(device)
    }

    ///The struct `Sniffer` initializes the sniffing and reporting process, by
    ///* Finding the `pcap::Device` associated to the given `adapter`
    ///* Properly setting up (in promisc mode) and activating a `pcap::Capture` on the given `adapter`.
    ///* Associating (if possible) the given `filter` string to a `network_analyzer::Filter` tag
    ///* Creating a `network_analyzer::channel::SnifferChannel` to transfer informations from the
    ///internal threads to the subscribed one (where the Sniffer is created).
    ///
    ///
    ///Moreover, the struct `Sniffer` is responsible for the initialization of two threads:
    /// 1) <i>timer_thread</i>: while the sniffer isn't paused/stopped, every `update_time` milliseconds, updates the sniffing report contained in a `output` (.xml and .md) file
    /// 2) <i>sniffing_thread</i>: while the sniffer isn't paused/stopped, waits for the capturing of a packet, takes the captured `pcap::Packet`, transforms it in a readable `NAPacket`, filters it (following the given `filter`) and eventually transfers it to the subscribed thread(s) via `SnifferChannel`.
    ///
    /// The `Sniffer` also implements the `Drop` trait, so that the `drop(&mut self)` function waits for the proper termination
    /// of the two threads initialized by the struct.
    pub struct Sniffer {
        m: Arc<Mutex<(NAState, Vec<NAPacket>, Vec<Stats>, SnifferChannel)>>,
        jh: Option<(JoinHandle<()>, JoinHandle<()>)>,
        cv: Arc<Condvar>,
        report_file_name: (String, String),
    }

    impl Sniffer {

        ///Creates a new `Sniffer` object given four parameters (network adapter to sniff (u8), output filename (String),
        /// output file update time (u64), filter (String)) or returns an `NAError`.

        pub fn new(adapter: u8, output: String, update_time: u64, filter: String) -> Result<Self, NAError> {
            let report_file_name = get_file_name(output.clone());
            let report_file_name_cl = report_file_name.clone();
            let report_file_name_cl_2 = report_file_name.clone();

            let device = get_adapter(adapter)?;
            let enum_filter = get_filter(&filter.trim().to_ascii_lowercase())?;

            let sniffer_channel = SnifferChannel::new();

            let stats_vec = Vec::<Stats>::new();
            let vec = Vec::<NAPacket>::new();

            let m = Arc::new(Mutex::new((RESUMED, vec, stats_vec, sniffer_channel)));
            let m_cl = m.clone();
            let m_cl_2 = m.clone();
            let cv = Arc::new(Condvar::new());
            let cv_cl = cv.clone();
            let cv_cl_2 = cv.clone();

            // report update thread (timer)
            let timer_thread = spawn(move || {
                loop {
                    sleep(Duration::from_millis(update_time));
                    let mg_res = m_cl_2.lock();
                    match mg_res {
                        Ok(mut mg) if mg.0.is_resumed() => {
                            mg.2 = produce_report(report_file_name_cl_2.0.clone(), report_file_name_cl_2.1.clone(), mg.1.clone(), mg.2.clone());
                            mg.1 = Vec::new();
                        }
                        Ok(mut mg) if mg.0.is_paused() => {
                            mg = cv_cl_2.wait_while(mg, |mg| !mg.0.is_resumed()).unwrap();
                            drop(mg);
                            continue;
                        }
                        _ => break
                    }
                }
                //println!("Timer thread exiting")
            });

            let sniffing_thread = spawn(move || {
                let mut cap = Capture::from_device(device.clone())
                    .unwrap()
                    .timeout(5000)
                    .promisc(true)
                    .open()
                    .unwrap();

                loop {
                    let mut mg = m_cl.lock().unwrap();
                    if mg.0.is_resumed() {
                        // rilascia il lock prima di next_packet() (bloccante)
                        drop(mg);
                        match cap.next_packet() {
                            Ok(packet) => {
                                mg = m_cl.lock().unwrap();
                                if mg.0.is_paused() {
                                    drop(cap);
                                    mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                                    cap = Capture::from_device(device.clone())
                                        .unwrap()
                                        .timeout(5000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    drop(mg);
                                    continue;
                                } else if mg.0.is_stopped() {
                                    break;
                                }

                                let p = NAPacket::new(packet.clone());

                                if p.filter(enum_filter.clone()) {
                                    mg.3.send(Message::Packet(p.clone()));
                                    mg.1.push(p);
                                }
                            }
                            Err(e) => {
                                if e == TimeoutExpired {
                                    cap = Capture::from_device(device.clone())
                                        .unwrap()
                                        .timeout(5000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    continue;
                                }

                                // send the error to the ui
                                let mut mg = m_cl.lock().unwrap();
                                mg.3.send(Message::Error(NAError::new(&e.to_string())));
                                break;
                            }
                        }
                    } else if mg.0.is_paused() {
                        drop(cap);
                        mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                        cap = Capture::from_device(device.clone())
                            .unwrap()
                            .timeout(5000)
                            .promisc(true)
                            .open()
                            .unwrap();
                    } else {
                        break;
                    }
                    drop(mg);
                }

                let mut mg = m_cl.lock().unwrap();
                mg.0 = STOPPED;
                mg.2 = produce_report(report_file_name_cl.0.clone(), report_file_name_cl.1.clone(), mg.1.clone(), mg.2.clone());

                cv_cl.notify_all();

                //println!("Sniffing thread exiting");
            });

            Ok(Sniffer { m, jh: Some((sniffing_thread, timer_thread)), cv, report_file_name })
        }

        ///Pauses both sniffing and reporting threads within the `Sniffer` struct
        ///
        ///This function performs different tasks in order to correctly pause the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::PAUSED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Forces the writing of a report before the pause
        pub fn pause(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = PAUSED;
            mg.3.send(Message::State(PAUSED));
            mg.2 = produce_report(self.report_file_name.0.clone(), self.report_file_name.1.clone(), mg.1.clone(), mg.2.clone());
            mg.1 = Vec::new();
        }

        ///Resumes both sniffing and reporting threads within the `Sniffer` struct
        ///
        /// This function performs different tasks in order to correctly resume the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::RESUMED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Notifies both sniffing and reporting threads in wait on the `Sniffer`'s condition variable
        pub fn resume(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = RESUMED;
            mg.3.send(Message::State(RESUMED));
            self.cv.notify_all();
        }

        ///Forces the exiting of both sniffing and reporting threads within the `Sniffer` struct
        ///
        /// This function performs different tasks in order to terminate of the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::STOPPED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Notifies both sniffing and reporting threads (if paused, otherwise the notification is lost)
        pub fn stop(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = STOPPED;
            mg.3.send(Message::State(STOPPED));
            self.cv.notify_all();
        }

        /// Returns a `Receiver<Message>`.<br>
        /// It can be used to receive all the updates from the `Sniffer`.
        ///
        /// This method tries to acquire the inner Mutex, so it blocks until it is free.
        /// Then it calls the `subscribe()` function of the `SnifferChannel` and returns
        /// the new receiver.
        pub fn subscribe(&mut self) -> Receiver<Message> {
            let mut mg = self.m.lock().unwrap();
            mg.3.subscribe()
        }

        /// Returns the current state of the sniffer.
        ///
        /// This method tries to acquire the inner Mutex, so it blocks until it is free.
        /// Then the NAState is cloned and returned.
        pub fn get_state(&self) -> NAState {
            self.m.lock().unwrap().0.clone()
        }
    }

    impl Drop for Sniffer {
        fn drop(&mut self) {
            let (t1, t2) = std::mem::replace(&mut self.jh, None).unwrap();
            t1.join().unwrap();
            t2.join().unwrap();
        }
    }


    pub mod na_packet {
        use std::fmt::{Display, Formatter};
        use std::time::SystemTime;
        use pcap::Packet;
        use crate::sniffer::filter::Filter;
        use crate::sniffer::format::{option_to_string, to_u16};
        use crate::sniffer::na_packet::protocols::{get_ipv6_transported_protocol, to_ip_address, to_ipv6_address, to_level_three_protocol, to_mac_address, to_transported_protocol};

        #[derive(Debug, Clone)]
        pub struct NAPacket {
            //level 2 header
            destination_mac_address: String,
            source_mac_address: String,

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
                            match (source_port.unwrap(),destination_port.unwrap()) {
                                (53,_) => transported_protocol = Some("UDP (DNS Response)".to_string()),
                                (_,53) => transported_protocol = Some("UDP (DNS Query)".to_string()),
                                (67,_) | (_,67) => transported_protocol = Some("UDP (DHCP Server)".to_string()),
                                (68,_) | (_,68) => transported_protocol = Some("UDP (DHCP Client)".to_string()),
                                _ => () ,
                            }
                        }

                        //TCP
                        if prot_num == 6 {
                            match (source_port.unwrap(),destination_port.unwrap()) {
                                (20,_) | (_,20) => transported_protocol = Some("TCP (FTP Data)".to_string()),
                                (21,_) | (_,21) => transported_protocol = Some("TCP (FTP Control)".to_string()),
                                (22,_) | (_,22) => transported_protocol = Some("TCP (SSH)".to_string()),
                                (23,_) | (_,23) => transported_protocol = Some("TCP (Telnet)".to_string()),
                                (25,_) | (_,25) => transported_protocol = Some("TCP (SMTP)".to_string()),
                                (80,_) | (_,80) => transported_protocol = Some("TCP (HTTP)".to_string()),
                                (110,_) | (_,110) => transported_protocol = Some("TCP (POP)".to_string()),
                                (143,_) | (_,143) => transported_protocol = Some("TCP (IMAP4)".to_string()),
                                (443,_) | (_,443) => transported_protocol = Some("TCP (HTTPS)".to_string()),
                                (465,_) | (_,465) => transported_protocol = Some("TCP (SMTPS)".to_string()),
                                (587,_) | (_,587) => transported_protocol = Some("TCP (SMTP Subm)".to_string()),
                                (993,_) | (_,993) => transported_protocol = Some("TCP (IMAP4S)".to_string()),
                                (995,_) | (_,995) => transported_protocol = Some("TCP (POP3S)".to_string()),
                                _ => () ,
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

            pub fn to_string_mac(&self) -> String {
                let mut s = String::new();
                s.push_str(&*("MAC_s: ".to_owned() + &self.source_mac_address + "  "
                    + &*" MAC_d: ".to_owned() + &self.destination_mac_address));
                s
            }

            pub fn to_string_endpoints(&self) -> String {
                let mut s = String::new();
                let mut space = "\t ";
                if option_to_string(self.source_address.clone()) == "None" {
                    space = "\t\t "
                }
                s.push_str(&*("IP_s: ".to_owned() + &option_to_string(self.source_address.clone()) + space
                    + &*" IP_d: ".to_owned() + &option_to_string(self.destination_address.clone())));
                s
            }

            pub fn to_string_ports(&self) -> String {
                let mut s = String::new();
                s.push_str(&*("Port_s: ".to_owned() + &option_to_string(self.source_port) + "\t\t  "
                    + &*"Port_d: ".to_owned() + &option_to_string(self.destination_port)));
                s
            }

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
                    },

                    Filter::LT(len) => self.total_length < len as u32,

                    Filter::LE(len) => self.total_length <= len as u32,

                    Filter::EQ(len) => self.total_length == len as u32,

                    Filter::GT(len) => self.total_length > len as u32,

                    Filter::GE(len) => self.total_length >= len as u32,

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

            pub(crate) fn to_ip_address(p: &[u8], start: usize) -> String {
                Ipv4Addr::new(
                    p[start],
                    p[start + 1],
                    p[start + 2],
                    p[start + 3],
                ).to_string()
            }

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
        }
    }

    pub mod na_error {
        use std::error::Error;
        use std::fmt::{Display, Formatter};

        #[derive(Debug, Clone)]
        pub struct NAError {
            message: String,
        }

        impl NAError {
            pub(crate) fn new(msg: &str) -> Self { NAError { message: msg.to_string() } }
        }

        impl Display for NAError {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "NAError: {}", self.message)
            }
        }

        impl Error for NAError {}
    }

    pub mod filter {
        use crate::sniffer::na_error::NAError;

        /// Enumerates the different filtering categories offered by the network_analyzer library.
        /// It also implements the `ToString` trait, allowing a correct transformation of `Filter`'s
        /// tag (and possible detail) into a proper string representation.
        ///
        /// <br></br>
        /// <i> Example </i>
        /// * `Filter::IP(192.168.1.1)` is converted into "IP 192.168.1.1"
        /// * `Filter::Port(443)` is converted into "port 443"
        #[derive(Clone)]
        pub enum Filter {
            None,
            IPv4,
            IPv6,
            ARP,
            IP(String),
            Port(u16),
            LT(u16),
            LE(u16),
            EQ(u16),
            GT(u16),
            GE(u16)
        }

        impl ToString for Filter {
            fn to_string(&self) -> String {
                match self {
                    Filter::None => "None".to_string(),
                    Filter::IPv4 => "IPv4".to_string(),
                    Filter::IPv6 => "IPv6".to_string(),
                    Filter::ARP => "ARP".to_string(),
                    Filter::IP(ip) => ("IP ".to_owned() + ip).to_string(),
                    Filter::Port(port) => {
                        let mut s = String::from("port ");
                        s.push_str(&port.to_string());
                        s
                    },
                    Filter::LT(len) => ("length < ".to_owned() + len.to_string().as_str()).to_string(),
                    Filter::LE(len) => ("length <= ".to_owned() + len.to_string().as_str()).to_string(),
                    Filter::EQ(len) => ("length = ".to_owned() + len.to_string().as_str()).to_string(),
                    Filter::GT(len) => ("length > ".to_owned() + len.to_string().as_str()).to_string(),
                    Filter::GE(len) => ("length >= ".to_owned() + len.to_string().as_str()).to_string(),
                }
            }
        }

        ///Associates a received string to a `Filter` (if possible), or returns an `NAError`
        ///
        ///This function associates a string to a filter, by analyzing the correctness of the
        ///passed parameter.
        ///
        /// <br></br>
        ///<i>Example</i>:
        ///* "ipv4" can be associated to a `Filter::IPv4` filter
        ///* "192.168.1.1" can be associated to  `Filter::IP(String)`
        ///* "2001:db8::2:1" can be associated to a `Filter::IP(String)`
        ///* "foo.192 foo" cannot be associated to any filter
        pub fn get_filter(filter: &String) -> Result<Filter, NAError> {
            //Actually available filters
            let f = filter.as_str();
            match f {
                "none" => Ok(Filter::None),
                "ipv4" => Ok(Filter::IPv4),
                "ipv6" => Ok(Filter::IPv6),
                "arp" => Ok(Filter::ARP),

                //ipv4 addr
                string if string.contains('.') => {
                    let v: Vec<&str> = string.split('.').collect();
                    if v.len() == 4 {
                        for u8_block in v {
                            if u8_block.parse::<u8>().is_err() {
                                return Err(NAError::new("Not a valid IPv4 addr. as filter"));
                            }
                        }
                        return Ok(Filter::IP(string.to_string()));
                    }
                    return Err(NAError::new("Not an IP addr. as filter"));
                }

                //ipv6 addr
                string if string.contains(':') => {
                    let v: Vec<&str> = string.split(':').collect();
                    if v.len() <= 8 {
                        for u16_block in v {
                            if u16::from_str_radix(u16_block, 16).is_err() && !u16_block.is_empty() {
                                return Err(NAError::new("Not a valid IPv6 addr. as filter"));
                            }
                        }
                        return Ok(Filter::IP(string.to_string()));
                    }
                    return Err(NAError::new("Not a valid IPv6 addr. as filter"));
                }

                //port
                string if string.parse::<u16>().is_ok() => Ok(Filter::Port(string.parse::<u16>().unwrap())),

                //length (le)
                string if string.starts_with("<=") => {
                    let mut string = string.to_string();
                    string.remove(0);
                    string.remove(0);
                    match string.parse::<u16>() {
                        Err(_) => Err(NAError::new("Not a valid packet length")),
                        Ok(len) => Ok(Filter::LE(len))
                    }
                },

                //length (ge)
                string if string.starts_with(">=") => {
                    let mut string = string.to_string();
                    string.remove(0);
                    string.remove(0);
                    match string.parse::<u16>() {
                        Err(_) => Err(NAError::new("Not a valid packet length")),
                        Ok(len) => Ok(Filter::GE(len))
                    }
                },

                //length (eq)
                string if string.starts_with("=") => {
                    let mut string = string.to_string();
                    string.remove(0);
                    match string.parse::<u16>() {
                        Err(_) => Err(NAError::new("Not a valid packet length")),
                        Ok(len) => Ok(Filter::EQ(len))
                    }
                },
                //length (gt)
                string if string.starts_with(">") => {
                    let mut string = string.to_string();
                    string.remove(0);
                    match string.parse::<u16>() {
                        Err(_) => Err(NAError::new("Not a valid packet length")),
                        Ok(len) => Ok(Filter::GT(len))
                    }
                },

                //length (lt)
                string if string.starts_with("<") => {
                    let mut string = string.to_string();
                    string.remove(0);
                    match string.parse::<u16>() {
                        Err(_) => Err(NAError::new("Not a valid packet length")),
                        Ok(len) => Ok(Filter::LT(len))
                    }
                },


                _ => Err(NAError::new("Unavailable filter")),
            }
        }
    }

    mod stats {
        use std::fs::File;
        use crate::sniffer::format::option_to_string;
        use crate::sniffer::na_packet::NAPacket;
        use std::io::Write;

        /// The `Stats` type.
        ///
        /// It is used to store information about the (ISO/OSI) level four packet flow,
        /// needed to produce the sniffer report.<br>
        /// This type implements the `Debug` and `Clone` traits.
        ///
        /// It contains:
        /// * The pair of socket
        /// * The level three protocol's name
        /// * The transported protocol's name
        /// * The flow's total number of bytes
        /// * The timestamp of the first packet received
        /// * The timestamp of the last packet received
        #[derive(Debug, Clone)]
        pub(crate) struct Stats {
            sockets: [(Option<String>, Option<u16>); 2],
            l3_protocol: String,
            transported_protocol: Option<String>,
            total_bytes: u128,
            first_timestamp: u128,
            last_timestamp: u128,
        }

        impl Stats {
            /// Creates a new `Stats` from a `NAPacket`.
            ///
            /// This method extracts the needed field from the packet and populate
            /// the new object, by using the timestamp twice, both for the first
            /// and last packet fields.
            ///
            /// It is typically used by passing as argument the first packet of a flow.
            pub(crate) fn new(packet: NAPacket) -> Self {
                Stats {
                    sockets: [(packet.source_address, packet.source_port), (packet.destination_address, packet.destination_port)],
                    l3_protocol: packet.level_three_type,
                    transported_protocol: packet.transported_protocol,
                    total_bytes: packet.total_length as u128,
                    first_timestamp: packet.timestamp,
                    last_timestamp: packet.timestamp,
                }
            }
        }

        /// Produces two report files (<i>.xml</i> and <i>.md</i>) and returns the updated
        /// vector of `Stats`.
        ///
        /// The function takes as argument two file name (one for each format), a vector of
        /// packets and a vector of (old) stats; these are used to produce an updated version
        /// of the stats by calling the function `produce_stats(stats, packets)`.<br>
        /// Then, it creates the files and writes them by using the `writeln!` macro.<br>
        /// At the end, it returns the updated stats.
        ///
        /// It panics if it is unable to write correctly the files and show the message
        /// `"Unable to write the report file!"`.
        pub(crate) fn produce_report(file_name_md: String, file_name_xml: String, packets: Vec<NAPacket>, stats: Vec<Stats>) -> Vec<Stats> {
            // define the path
            let vec = produce_stats(stats, packets);

            // crea il file o tronca al byte 0 se il file esiste già
            let mut report_md = File::create(file_name_md.clone()).unwrap(); // returns a Result
            let mut report_xml = File::create(file_name_xml.clone()).unwrap();

            // scrivi le stringhe nel report
            writeln!(report_md).expect("Unable to write the report file!");
            writeln!(report_md, "# Sniffer report").expect("Unable to write the report file!");
            writeln!(report_md).expect("Unable to write the report file!");

            if vec.is_empty() {
                writeln!(report_md, "No traffic detected!").expect("Unable to write the report file!");
                writeln!(report_xml, "<report>No traffic detected!</report>").expect("Unable to write the report file!");
                /*if !tui {
                    println!("Report produced!");
                }*/
                return vec;
            }

            // HEADLINE
            writeln!(report_md, "| Endpoint 1 IP | Endpoint 1 Port | Endpoint 2 IP | Endpoint 2 Port | Level Three Protocol | Transported Protocol | Bytes Transmitted | First Timestamp | Last Timestamp |")
                .expect("Unable to write the report file!");
            writeln!(report_md, "|:----:|:----:|:----:|:----:|:----:|:----:|:----:|:----:|:----:|")
                .expect("Unable to write the report file!");
            writeln!(report_xml, "<report>").expect("Unable to write the report file!");

            for stat in vec.clone() {

                // write the first ip address
                let first_ip = option_to_string(stat.sockets[0].0.clone());
                write!(report_md, "| {} ", first_ip).expect("Unable to write the report file!");
                write!(report_xml, "<data_flow>").expect("Unable to write the report file!");
                write!(report_xml, "<endpoint1_ip>{}</endpoint1_ip>", first_ip).expect("Unable to write the report file!");

                // write the first port
                let first_port = option_to_string(stat.sockets[0].1);
                write!(report_md, "| {} ", first_port).expect("Unable to write the report file!");
                write!(report_xml, "<endpoint1_port>{}</endpoint1_port>", first_port).expect("Unable to write the report file!");

                // write the second ip address
                let second_ip = option_to_string(stat.sockets[1].0.clone());
                write!(report_md, "| {} ", second_ip).expect("Unable to write the report file!");
                write!(report_xml, "<endpoint2_ip>{}</endpoint2_ip>", second_ip).expect("Unable to write the report file!");

                // write the second port
                let second_port = option_to_string(stat.sockets[1].1);
                write!(report_md, "| {} ", second_port).expect("Unable to write the report file!");
                write!(report_xml, "<endpoint2_port>{}</endpoint2_port>", second_port).expect("Unable to write the report file!");

                // write the l3 protocol
                write!(report_md, "| {} ", stat.l3_protocol).expect("Unable to write the report file!");
                write!(report_xml, "<l3_prot>{}</l3_prot>", stat.l3_protocol).expect("Unable to write the report file!");


                // write the transported protocol
                let transp_prot = option_to_string(stat.transported_protocol);
                write!(report_md, "| {} ", transp_prot).expect("Unable to write the report file!");
                write!(report_xml, "<transp_prot>{}</transp_prot>", transp_prot).expect("Unable to write the report file!");

                // write the total number of bytes
                write!(report_md, "| {} ", stat.total_bytes).expect("Unable to write the report file!");
                write!(report_xml, "<total_bytes>{}</total_bytes>", stat.total_bytes).expect("Unable to write the report file!");

                // write the first timestamp
                write!(report_md, "| {} ", stat.first_timestamp).expect("Unable to write the report file!");
                write!(report_xml, "<first_ts>{}</first_ts>", stat.first_timestamp).expect("Unable to write the report file!");

                // write the last timestamp
                write!(report_md, "| {} |", stat.last_timestamp).expect("Unable to write the report file!");
                write!(report_xml, "<last_ts>{}</last_ts>", stat.first_timestamp).expect("Unable to write the report file!");

                write!(report_xml, "</data_flow>").expect("Unable to write the report file!");
                writeln!(report_md).expect("Unable to write the report file!");
                writeln!(report_xml).expect("Unable to write the report file!");
            }

            write!(report_xml, "</report>").expect("Unable to write the report file!");
            /*if !tui {
                println!("Report produced!");
            }*/
            vec
        }

        /// Produces an updated version of the stats and returns a vector of `Stats` objects.
        ///
        /// This function takes as argument a vector of old stats and a vector of packets
        /// to be processed and added.
        ///
        /// It slides the packets, checks if its pair of socket is already recorded
        /// in the stats, then it updates the relative `Stats` object by adding the
        /// number of bytes and replacing the last packet timestamp.<br>
        /// Otherwise, it creates a new object by calling the `new(packet)` static
        /// function of `Stats`.
        ///
        /// At the end, it returns the updated vector of stats.
        fn produce_stats(mut stats: Vec<Stats>, packets: Vec<NAPacket>) -> Vec<Stats> {
            for packet in packets {
                // controlla il socket del pacchetto
                if stats.is_empty() {
                    let stat = Stats::new(packet.clone());
                    stats.push(stat);
                } else {
                    let first_socket = (packet.source_address.clone(), packet.source_port.clone());
                    let second_socket = (packet.destination_address.clone(), packet.destination_port.clone());
                    // check if the socket is contained in old_stats
                    let mut modified = false;
                    'inner: for stat in stats.iter_mut() {
                        if stat.sockets.contains(&first_socket)
                            && stat.sockets.contains(&second_socket)
                            && stat.transported_protocol == packet.transported_protocol
                            && stat.l3_protocol == packet.level_three_type
                        {
                            stat.total_bytes += packet.total_length as u128;
                            stat.last_timestamp = packet.timestamp;
                            modified = true;
                            break 'inner;
                        }
                    }
                    if !modified {
                        let stat = Stats::new(packet.clone());
                        stats.push(stat);
                    }
                }
            }
            stats
        }
    }

    pub mod na_state {
        #[derive(Debug, Clone)]
        pub enum NAState {
            RESUMED,
            PAUSED,
            STOPPED,
        }

        impl NAState {
            pub fn is_resumed(&self) -> bool {
                matches!(self, NAState::RESUMED)
            }
            pub fn is_paused(&self) -> bool {
                matches!(self, NAState::PAUSED)
            }
            pub fn is_stopped(&self) -> bool {
                matches!(self, NAState::STOPPED)
            }
        }
    }

    mod format {
        use std::fmt::Display;

        pub(crate) fn get_file_name(string: String) -> (String, String) {
            let mut string_md = string.trim().to_string();
            let mut string_xml = string.trim().to_string();

            if !string_md.ends_with(".md") {
                string_md.push_str(".md");
            }
            if !string_xml.ends_with(".xml") {
                string_xml.push_str(".xml");
            }
            (string_md, string_xml)
        }

        pub(crate) fn option_to_string<T: Display>(opt: Option<T>) -> String {
            match opt {
                Some(num) => num.to_string(),
                None => String::from("None")
            }
        }

        pub(crate) fn to_u16(p: &[u8], start: usize) -> u16 {
            let param1: u16 = p[start] as u16 * 256;
            let param2 = p[start + 1] as u16;
            param1 + param2
        }
    }

    pub mod channel {
        use std::sync::mpsc::{channel, Receiver, Sender};
        use crate::sniffer::na_error::NAError;
        use crate::sniffer::na_packet::NAPacket;
        use crate::sniffer::na_state::NAState;

        /// The `SnifferChannel` type.
        ///
        /// It is used to let the sniffer communicate with its subscribers by sending messages.<br>
        /// It contains a vector of `Sender<Message>`, one for each subscriber.
        pub(crate) struct SnifferChannel {
            senders: Vec<Sender<Message>>,
        }

        impl SnifferChannel {
            /// Creates a new `SnifferChannel` object and populate it with an empty array
            /// of senders.
            pub(crate) fn new() -> Self {
                SnifferChannel { senders: Vec::new() }
            }

            /// Creates a new communication channel and returns the receiver.
            ///
            /// This method use the `std::sync::mpsc::channel()` function to create
            /// a `Sender`, which will be added to the `SnifferChannel` and a `Receiver`,
            /// which will be returned to the subscriber.
            pub(crate) fn subscribe(&mut self) -> Receiver<Message> {
                let (sx, rx) = channel::<Message>();
                self.senders.push(sx);
                rx
            }

            /// Sends a `Message` to all the subscribers.
            ///
            /// The method slides the senders vector and checks if each of them is still valid.<br>
            /// It calls the `send(message)` method of the `Sender` that attempts to send the
            /// message and returns an error if the `Receiver` has been already deallocated.<br>
            /// In this case, the sender is removed from the vector.
            pub(crate) fn send(&mut self, message: Message) {
                let mut i = 0;
                loop {
                    if i < self.senders.len() {
                        match self.senders[i].send(message.clone()) {
                            Err(_) => drop(self.senders.remove(i)),
                            _ => i += 1
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        /// The `Message` type.
        ///
        /// It is an enumeration that contains the message sent in the `SnifferChannel`,
        /// that can be either a `NAError`, a `NAState` or a `NAPacket`.<br>
        /// This type implements the `Clone` trait.
        #[derive(Clone)]
        pub enum Message {
            Error(NAError),
            State(NAState),
            Packet(NAPacket),
        }
    }
}
