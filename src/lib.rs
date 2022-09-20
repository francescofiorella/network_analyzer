extern crate core;

pub mod sniffer {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use std::fs::File;
    use std::io::{stdin, Write};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::process::Command;
    use pcap::{Capture, Device, Packet};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{JoinHandle, sleep, spawn};
    use std::time::{Duration, SystemTime};
    use cursive::backends::curses::pan::pancurses::{A_REVERSE, COLOR_BLACK, COLOR_BLUE, COLOR_GREEN, COLOR_PAIR, COLOR_RED, COLOR_WHITE, COLOR_YELLOW, curs_set, init_pair, initscr, Input, newwin, noecho, resize_term, start_color, Window};
    use mac_address::MacAddress;
    use pcap::Error::TimeoutExpired;
    use crate::sniffer::format::{get_file_name, option_to_string};
    use crate::sniffer::NAState::{PAUSED, RESUMED, STOPPED};

    const RUN: &str = "****** SNIFFING PACKETS... ******";
    const PAUSE: &str = "****** SNIFFING PAUSED ******";
    const QUIT: &str = "****** SNIFFING CONCLUDED ******";

    fn get_filter(filter: &String) -> Result<Filter, NAError> {
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
                            return Err(NAError::new("Not a valid IPv4 addr. as filter"))
                        }
                    }
                    return Ok(Filter::IP(string.to_string()))
                }
                return Err(NAError::new("Not an IP addr. as filter"))
            }

            //ipv6 addr
            string if string.contains(':') => {
                let v: Vec<&str> = string.split(':').collect();
                if v.len() <= 8 {
                    for u16_block in v {
                        if u16::from_str_radix(u16_block, 16).is_err() && !u16_block.is_empty(){
                            return Err(NAError::new("Not a valid IPv6 addr. as filter"))
                        }
                    }
                    return Ok(Filter::IP(string.to_string()))
                }
                return Err(NAError::new("Not a valid IPv6 addr. as filter"))
            }

            //port
            string if string.parse::<u16>().is_ok() => Ok(Filter::Port(string.parse::<u16>().unwrap())),
            _ => Err(NAError::new("Unavailable filter")),
        }
    }

    fn tui_init(adapter: &str, filter: &Filter, output: &str, update_time: u64) -> Window {
        //screen initialization
        if cfg!(target_os = "macos") {
            Command::new("/usr/X11/bin/resize").arg("-s").arg("43").arg("80").output().unwrap();
        } else if cfg!(target_os="linux"){
            Command::new("resize").arg("-s").arg("43").arg("80").output().unwrap();
        }
        let window = initscr();
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_RED, COLOR_BLACK);
        init_pair(4, COLOR_GREEN, COLOR_BLACK);
        init_pair(5, COLOR_BLUE, COLOR_BLACK);

        //screen settings
        if cfg!(target_os = "linux") {
            resize_term(0, 0);
        } else {
            resize_term(42, 80);
        }
        noecho();
        curs_set(0);
        window.keypad(true);
        window.refresh();

        //subwindow 2
        let sub2 = window.subwin(6, 67, 0, 12).unwrap();
        sub2.draw_box(0, 0);
        sub2.attron(COLOR_PAIR(4));
        sub2.mvprintw(1, 1, "Adapter: ");
        sub2.mvprintw(1, 9, adapter);
        sub2.mvprintw(2, 1, "Filter: ");
        sub2.mvprintw(2, 9, filter.to_string());
        sub2.mvprintw(3, 1, "Output file: ");
        sub2.mvprintw(3, 14, output);
        sub2.mvprintw(4, 1, "Output upd. time (ms): ");
        sub2.mvprintw(4, 24, update_time.to_string().as_str());
        sub2.attroff(COLOR_PAIR(4));
        sub2.refresh();

        //subwindow 3
        let sub3 = newwin(33, 78, 9, 1);
        sub3.draw_box(0, 0);
        sub3.refresh();

        window
    }

    fn state_win_init() -> Window {
        let state_window = newwin(3, 78, 6, 1);
        state_window.draw_box(0, 0);
        state_window.mvprintw(1, 22, RUN);
        state_window.refresh();
        state_window
    }

    fn notui_show_commands() {
        let commands = "\
        ****** Commands ******\n\
        Press \"P + Enter\" to pause\n\
        Press \"R + Enter\" to resume\n\
        Press \"Q + Enter\" to quit \n\
        **********************\n\
        Starting sniffing...";

        println!("{}", commands);

        sleep(Duration::from_secs(3));
    }

    fn print_state(state_window: Option<&Window>, state: &NAState) {
        let msg = match state {
            PAUSED => PAUSE,
            STOPPED => QUIT,
            RESUMED => RUN,
        };

        match state_window {
            Some(sw) => {
                sw.clear();
                sw.draw_box(0, 0);
                sw.mvprintw(1, 22, msg);
                sw.refresh();
            }

            None => println!("{}", msg),
        }
    }

    #[derive(Clone)]
    enum Filter {
        None,
        IPv4,
        IPv6,
        ARP,
        IP(String),
        Port(u16),
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
                }

            }
        }
    }


    #[derive(Debug, Clone)]
    enum NAState {
        RESUMED,
        PAUSED,
        STOPPED,
    }

    impl NAState {
        fn is_resumed(&self) -> bool {
            matches!(self, NAState::RESUMED)
        }
        fn is_paused(&self) -> bool {
            matches!(self, NAState::PAUSED)
        }
        fn is_stopped(&self) -> bool {
            matches!(self, NAState::STOPPED)
        }
    }

    pub struct Sniffer {
        m: Arc<Mutex<(NAState, Vec<NAPacket>, Vec<Stats>)>>,
        pub jh: JoinHandle<()>,
        cv: Arc<Condvar>,
        report_file_name: (String, String),
        tui_handler: (Option<Window>, bool, Option<Window>),
    }

    impl Sniffer {
        pub fn new(adapter: u8, output: String, update_time: u64, filter: String, tui: bool) -> Result<Self, NAError> {
            let report_file_name = get_file_name(output.clone());
            let report_file_name_cl = report_file_name.clone();
            let report_file_name_cl_2 = report_file_name.clone();

            let device_list = Device::list().unwrap();
            let mut couple = Vec::<(u8, Device)>::new();
            for (index, device) in device_list.into_iter().enumerate() {
                couple.push((index as u8 + 1 , device));
            }
            let device = match couple.into_iter().find(|c| c.0 == adapter) {
                Some((_, dev)) => dev,
                None => return Err(NAError::new("Device not found")),
            };

            let enum_filter = match get_filter(&filter.to_ascii_lowercase()) {
                Ok(f) => f,
                Err(e) => return Err(e),
            };

            let mut main_window = None;
            let mut state_window = None;
            let mut tui_handler = (main_window, false, state_window);

            match tui {
                true => {
                    main_window = Some(tui_init(&device.name, &enum_filter, &output, update_time));
                    state_window = Some(state_win_init());
                    tui_handler = (main_window, true, state_window);
                }
                false => {
                    notui_show_commands();
                }
            }

            let stats_vec = Vec::<Stats>::new();

            let vec = Vec::new();

            let m = Arc::new(Mutex::new((RESUMED, vec, stats_vec)));
            let m_cl = m.clone();
            let m_cl_2 = m.clone();
            let cv = Arc::new(Condvar::new());
            let cv_cl = cv.clone();
            let cv_cl_2 = cv.clone();

            // report update thread (timer)
            spawn(move || {
                loop {
                    sleep(Duration::from_millis(update_time));
                    let mg_res = m_cl_2.lock();
                    match mg_res {
                        Ok(mut mg) if mg.0.is_resumed() => {
                            mg.2 = produce_report(report_file_name_cl_2.0.clone(), report_file_name_cl_2.1.clone(), mg.1.clone(), mg.2.clone(), tui);
                            mg.1 = Vec::new();
                        }
                        Ok(mut mg) if mg.0.is_paused() => {
                            mg = cv_cl_2.wait_while(mg, |mg| !mg.0.is_resumed()).unwrap();
                            continue;
                        }
                        _ => break
                    }
                }
            });

            let jh = spawn(move || {
                let mut sub4 = None;

                //subwindow 4
                if tui {
                    sub4 = Some(newwin(31, 76, 10, 2));
                    sub4.as_ref().unwrap().scrollok(true);
                    sub4.as_ref().unwrap().setscrreg(0, 30);
                }

                let mut cap = Capture::from_device(device.clone())
                    .unwrap()
                    .timeout(10000)
                    .promisc(true)
                    .open()
                    .unwrap();

                //println!("****** SNIFFING STARTED ******");
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
                                        .timeout(10000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    continue;
                                } else if mg.0.is_stopped() {
                                    break;
                                }

                                let p = NAPacket::new(packet.clone());

                                if p.filter(enum_filter.clone()) {
                                    match tui {
                                        true => p.print_packet(sub4.as_ref()),
                                        false => p.print_packet(None),
                                    }

                                    mg.1.push(p);
                                }

                            }
                            Err(e) => {
                                if e == TimeoutExpired {
                                    cap = Capture::from_device(device.clone())
                                        .unwrap()
                                        .timeout(10000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    continue;
                                }
                                match tui {
                                    true => {
                                        sub4.as_ref().unwrap().clear();
                                        sub4.as_ref().unwrap().printw(e.to_string().as_str());
                                        sub4.as_ref().unwrap().printw("\n");
                                        sub4.as_ref().unwrap().printw("Press any key to quit");
                                        sub4.as_ref().unwrap().refresh();
                                        //to make the error visible
                                        sleep(Duration::from_secs(2));
                                    }
                                    false => println!("ERROR: {}", e),
                                }
                                break;
                            }
                        }
                    } else if mg.0.is_paused() {
                        drop(cap);
                        mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                        cap = Capture::from_device(device.clone())
                            .unwrap()
                            .timeout(10000)
                            .promisc(true)
                            .open()
                            .unwrap();
                    } else {
                        break;
                    }
                }

                let mut mg = m_cl.lock().unwrap();
                mg.2 = produce_report(report_file_name_cl.0.clone(), report_file_name_cl.1.clone(), mg.1.clone(), mg.2.clone(), tui);

                // change the mutex, just in case of internal error
                mg.0 = STOPPED;
                cv_cl.notify_all();

                println!("Sniffing thread exiting");
            });

            Ok(Sniffer { m, jh, cv, report_file_name, tui_handler })
        }

        pub fn pause(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = PAUSED;

            print_state(self.tui_handler.2.as_ref(), &(mg.0));

            mg.2 = produce_report(self.report_file_name.0.clone(), self.report_file_name.1.clone(), mg.1.clone(), mg.2.clone(), self.tui_handler.1);
            mg.1 = Vec::new();
        }

        pub fn resume(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = RESUMED;

            print_state(self.tui_handler.2.as_ref(), &(mg.0));

            self.cv.notify_all();
        }

        pub fn stop(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = STOPPED;

            print_state(self.tui_handler.2.as_ref(), &(mg.0));

            self.cv.notify_all();
        }

        pub fn enable_commands(&self) {
            match self.tui_handler.1 {
                true => {
                    self.tui_event_handler(); //blocking function until stop
                }
                false => {
                    self.notui_event_handler(); //blocking function until stop
                }
            }

            println!("Closing event handler loop");
        }

        fn tui_event_handler(&self) {

            //drawing subwindow 1
            let sub1 = self.tui_handler.0.as_ref().unwrap().subwin(6, 11, 0, 1).unwrap();
            sub1.draw_box(0, 0);
            sub1.mvprintw(1, 2, "Command");
            sub1.keypad(true);
            sub1.refresh();

            //commands definition
            let commands = vec![
                "PAUSE",
                "RESUME",
                "QUIT",
            ];

            //Event loop
            let mut menu = 0u8;
            let mut running = 0u8;

            loop {
                if !self.m.lock().unwrap().0.is_stopped() {
                    for (mut index, command) in commands.iter().enumerate() {
                        if menu == index as u8 {
                            sub1.attron(A_REVERSE);
                        } else {
                            sub1.attroff(A_REVERSE);
                        }
                        sub1.mvprintw({
                                          index += 2;
                                          index as i32
                                      }, 2, command);
                    }
                    match sub1.getch() { //getch waits for user key input -> returns Input value assoc. to the key
                        Some(Input::KeyUp) => {
                            if menu != 0 {
                                menu -= 1;
                                continue;
                            }
                        }
                        Some(Input::KeyDown) =>
                            {
                                if menu != 2 {
                                    menu += 1;
                                    continue;
                                }
                            }

                        Some(Input::KeyRight) => {
                            running = menu
                        }

                        Some(Input::Character('\n')) => {
                            running = menu
                        }

                        Some(_) => continue,

                        None => (),
                    }

                    if running == 0 {
                        self.pause();
                    } else if running == 1 {
                        self.resume();
                    } else {
                        self.stop();
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        fn notui_event_handler(&self) {
            //event loop
            loop {
                if !self.jh.is_finished() {
                    let mut cmd = String::new();
                    stdin().read_line(&mut cmd).unwrap();
                    if cmd.chars().nth(0).unwrap().to_ascii_lowercase() == 'p' {
                        self.pause();
                    } else if cmd.chars().nth(0).unwrap().to_ascii_lowercase() == 'r' {
                        self.resume();
                    } else if cmd.chars().nth(0).unwrap().to_ascii_lowercase() == 'q' {
                        self.stop();
                        break;
                    } else {
                        println!("Undefined command!");
                        continue;
                    }
                } else {
                    break;
                }
            }
        }
    }


    #[derive(Debug, Clone)]
    struct NAPacket {
        //level 2 header
        destination_mac_address: String, // 0 - 5
        source_mac_address: String, // 6 - 11

        //level 3 header
        level_three_type: String, // 12 - 13
        total_length: u32, // 16 - 17
        source_address: Option<String>, // 26 - 29
        destination_address: Option<String>, // 30 - 33

        //level 4 header
        transported_protocol: Option<String>, // 23
        source_port: Option<u16>, // 34 - 35
        destination_port: Option<u16>, // 36 - 37

        timestamp: u128,
        other: Option<String>,
    }

    fn to_mac_address(p: &Packet, start: usize) -> String {
        MacAddress::new([
            p[start],
            p[start + 1],
            p[start + 2],
            p[start + 3],
            p[start + 4],
            p[start + 5]
        ]).to_string()
    }

    fn to_ip_address(p: &Packet, start: usize) -> String {
        Ipv4Addr::new(
            p[start],
            p[start + 1],
            p[start + 2],
            p[start + 3]
        ).to_string()
    }

    fn to_ipv6_address(p: &Packet, start: usize) -> String {
        Ipv6Addr::new(
            to_u16(p, start),
            to_u16(p, start+2),
            to_u16(p, start+4),
            to_u16(p, start+6),
            to_u16(p, start+8),
            to_u16(p, start+10),
            to_u16(p, start+12),
            to_u16(p, start+14),
        ).to_string()
    }

    fn to_u16(p: &Packet, start: usize) -> u16 {
        let param1: u16 = p[start] as u16 * 256;
        let param2 = p[start + 1] as u16;
        param1 + param2
    }

    fn to_transported_protocol(prot_num: u8) -> String {
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

            // Da verificare
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

    fn to_level_three_protocol(prot_num: u16) -> String {
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

    fn get_ipv6_transported_protocol(p: &Packet, (next_header_index, remaining_size): (usize, usize)) -> (String, usize) {
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

    impl NAPacket {
        fn new(pcap_packet: Packet) -> Self {
            let mut source_address = None;
            let mut destination_address = None;
            let mut transported_protocol = None;
            let mut source_port = None;
            let mut destination_port = None;
            let mut other = None;
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
                },
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
                },
                // ARP | RARP
                0x0806 | 0x8035 => {
                    // Sender IP
                    source_address = Some(to_ip_address(&pcap_packet, 28));
                    // Target IP
                    destination_address = Some(to_ip_address(&pcap_packet, 38));
                    // Request / Reply
                    other = match pcap_packet[21] {
                        1 => Some("ARP Request".to_string()),
                        2=> Some("ARP Reply".to_string()),
                        3=> Some("RARP Request".to_string()),
                        4=> Some("RARP Reply".to_string()),
                        _ => None
                    }
                },
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
                other
            }
        }

        fn to_string_mac(&self) -> String {
            let mut s = String::new();
            s.push_str(
                &*("MAC_s: ".to_owned() + &self.source_mac_address
                    + &*" MAC_d: ".to_owned() + &self.destination_mac_address));
            s
        }

        fn to_string_source_socket(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("IP_s: ".to_owned() + &option_to_string(self.source_address.clone())
                + &*" Port_s: ".to_owned() + &option_to_string(self.source_port)));
            s
        }

        fn to_string_dest_socket(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("IP_d: ".to_owned() + &option_to_string(self.destination_address.clone())
                + &*" Port_d: ".to_owned() + &option_to_string(self.destination_port)));
            s
        }

        fn info(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("L3_type: ".to_owned() + &self.level_three_type.to_string()
                + &*" Len: ".to_owned() + &self.total_length.to_string()
                + &*" L4_Prot: ".to_owned() + &option_to_string(self.transported_protocol.clone())
                + &*" TS: ".to_owned() + &self.timestamp.to_string()));
            s
        }

        fn print_packet(&self, tui_window: Option<&Window>) {
            if tui_window.is_some() {
                tui_window.unwrap().attron(COLOR_PAIR(2));
                tui_window.as_ref().unwrap().printw(self.to_string_mac());
                tui_window.as_ref().unwrap().printw("\n");
                tui_window.unwrap().attroff(COLOR_PAIR(2));
                tui_window.unwrap().attron(COLOR_PAIR(3));
                tui_window.as_ref().unwrap().printw(self.to_string_source_socket());
                tui_window.as_ref().unwrap().printw("\n");
                tui_window.as_ref().unwrap().printw(self.to_string_dest_socket());
                tui_window.as_ref().unwrap().printw("\n");
                tui_window.unwrap().attroff(COLOR_PAIR(3));
                tui_window.unwrap().attron(COLOR_PAIR(5));
                tui_window.as_ref().unwrap().printw(self.info());
                tui_window.unwrap().attroff(COLOR_PAIR(5));
                tui_window.as_ref().unwrap().printw("\n");
                tui_window.as_ref().unwrap().printw("\n");
                tui_window.as_ref().unwrap().refresh();
            } else {
                let format =
                    self.to_string_mac().as_str().to_owned() + "\n" +
                        self.to_string_source_socket().as_str() + "\n" +
                        self.to_string_dest_socket().as_str() + "\n" +
                        self.info().as_str() + "\n"
                    ;
                println!("{}", format);
            }
        }

        fn filter(&self, filter: Filter) -> bool {
            match filter {
                Filter::None => true,
                Filter::IPv4 if self.level_three_type == "IPv4" => true,
                Filter::IPv6 if self.level_three_type == "IPv6" => true,
                Filter::ARP if self.level_three_type == "ARP" => true,
                Filter::IP(ip) => {
                    if self.source_address.is_some() && self.destination_address.is_some() {
                        return ip == *self.destination_address.as_ref().unwrap() || ip == *self.source_address.as_ref().unwrap()
                    }
                    false
                },
                Filter::Port(port) => {
                    if self.source_port.is_some() && self.destination_port.is_some() {
                        return port == self.source_port.unwrap() || port == self.destination_port.unwrap()
                    }
                    false
                }
                _ => false,
            }
        }
    }


    #[derive(Debug)]
    pub struct NAError {
        message: String,
    }

    impl NAError {
        fn new(msg: &str) -> Self { NAError { message: msg.to_string() } }
    }

    impl Display for NAError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "NAError: {}", self.message)
        }
    }

    impl Error for NAError {}


    pub fn list_adapters() -> Result<String, NAError> {
        let mut dev_names = String::new();
        let devices = match Device::list() {
            Ok(vec) => vec,
            Err(_) => return Err(NAError::new("Error while searching for network adapters"))
        };

        devices.into_iter().for_each(|dev| {
            dev_names.push_str(dev.name.as_str());
            dev_names.push('\n');
        });

        Ok(dev_names)
    }


    #[derive(Debug, Clone)]
    struct Stats {
        sockets: [(Option<String>, Option<u16>); 2],
        l3_protocol: String,
        transported_protocol: Option<String>,
        total_bytes: u128,
        first_timestamp: u128,
        last_timestamp: u128,
    }

    impl Stats {
        fn new(packet: NAPacket) -> Self {
            Stats {
                sockets: [(packet.source_address, packet.source_port), (packet.destination_address, packet.destination_port)],
                l3_protocol: packet.level_three_type,
                transported_protocol: packet.transported_protocol,
                total_bytes: packet.total_length as u128,
                first_timestamp: packet.timestamp,
                last_timestamp: packet.timestamp
            }
        }
    }

    fn produce_report(file_name_md: String, file_name_xml: String, packets: Vec<NAPacket>, stats: Vec<Stats>, tui: bool) -> Vec<Stats> {
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
            writeln!(report_xml, "No traffic detected!").expect("Unable to write the report file!");
            if !tui {
                println!("Report produced!");
            }
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
        if !tui {
            println!("Report produced!");
        }
        vec
    }

    mod format {
        use std::fmt::Display;

        pub fn get_file_name(string: String) -> (String, String) {
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

        pub fn option_to_string<T: Display>(opt: Option<T>) -> String {
            match opt {
                Some(num) => num.to_string(),
                None => String::from("None")
            }
        }
    }
}
