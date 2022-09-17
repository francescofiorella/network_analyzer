pub mod sniffer {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use std::fs::File;
    use std::io::{stdin, Write};
    use pcap::{Capture, Device, Packet};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{JoinHandle, sleep, spawn};
    use std::time::{Duration, SystemTime};
    use cursive::backends::curses::pan::pancurses::{A_BLINK, A_REVERSE, ALL_MOUSE_EVENTS, COLOR_BLACK, COLOR_BLUE, COLOR_GREEN, COLOR_PAIR, COLOR_RED, COLOR_WHITE, COLOR_YELLOW, curs_set, getmouse, init_pair, initscr, Input, mousemask, newwin, noecho, resize_term, start_color, Window};
    use rustc_serialize::hex::ToHex;
    use crate::sniffer::format::get_file_name;
    use crate::sniffer::NAState::{PAUSED, RESUMED, STOPPED};

    const RUN: &str = "****** SNIFFING PACKETS... ******";
    const PAUSE: &str = "****** SNIFFING PAUSED ******";
    const QUIT: &str = "****** SNIFFING CONCLUDED ******";


    fn tui_init(adapter: &str, filter: &str, output: &str, update_time: u64) -> Window {
        //screen initialization
        let mut window = initscr();
        start_color();
        init_pair(1,COLOR_WHITE,COLOR_BLACK);
        init_pair(2,COLOR_YELLOW,COLOR_BLACK);
        init_pair(3,COLOR_RED,COLOR_BLACK);
        init_pair(4,COLOR_GREEN,COLOR_BLACK);
        init_pair(5,COLOR_BLUE,COLOR_BLACK);

        //screen settings
        if cfg!(target_os = "macos") {
            resize_term(0, 0);
        } else {
            resize_term(42,80);
        }

        noecho();
        curs_set(0);
        window.keypad(true);
        window.refresh();

        //subwindow 2
        let sub2 = window.subwin(6, 67, 0, 12).unwrap();
        sub2.draw_box(0,0);
        sub2.attron(COLOR_PAIR(4));
        sub2.mvprintw(1, 1, "Adapter: ");
        sub2.mvprintw(1, 9, adapter);
        sub2.mvprintw(2, 1, "Filter: ");
        sub2.mvprintw(2, 9, filter);
        sub2.mvprintw(3, 1, "Output file: ");
        sub2.mvprintw(3, 14, output);
        sub2.mvprintw(4, 1, "Output upd. time (ms): ");
        sub2.mvprintw(4, 24, update_time.to_string().as_str());
        sub2.attroff(COLOR_PAIR(4));
        sub2.refresh();

        //subwindow 3
        let sub3 = newwin(33, 78, 9, 1);
        sub3.draw_box(0,0);
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

    #[derive(Debug, Clone)]
    enum NAState {
        RESUMED,
        PAUSED,
        STOPPED
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
        m: Arc<Mutex<(NAState, Vec<NAPacket>, [Vec<Stats>; 4])>>,
        pub jh: JoinHandle<()>,
        cv: Arc<Condvar>,
        device: Device,
        report_file_name: String,
        tui_handler: (Option<Window>, bool, Option<Window>),
    }

    impl Sniffer {
        pub fn new(adapter: String, output: String, update_time: u64, filter: String, tui: bool) -> Result<Self, NAError> {
            let report_file_name = get_file_name(output.clone());
            let report_file_name_cl = report_file_name.clone();
            let report_file_name_cl_2 = report_file_name.clone();


            let device_list = Device::list().unwrap();
            let device = match device_list.into_iter().find(|d| d.name == adapter) {
                Some(dev) => dev,
                None => return Err(NAError::new("Device not found")),
            };

            let mut main_window = None;
            let mut state_window = None;
            let mut tui_handler = (main_window, false, state_window);

            match tui {
                true => {
                    main_window = Some(tui_init(&adapter, &filter, &output, update_time));
                    state_window = Some(state_win_init());
                    tui_handler = (main_window, true, state_window);
                }
                false => {
                    notui_show_commands();
                }
            }

            let device_cl = device.clone();
            let device_cl_2 = device.clone();

            let device_ipv4_address = device.addresses[0].addr.to_string();
            let device_ipv6_address = device.addresses[1].addr.to_string();
            let incoming_ipv4_stats = vec![
                Stats::new(device_ipv4_address.clone()),
            ];
            let incoming_ipv6_stats = vec![
                Stats::new(device_ipv6_address.clone()),
            ];
            let outgoing_ipv4_stats = vec![
                Stats::new(device_ipv4_address),
            ];
            let outgoing_ipv6_stats = vec![
                Stats::new(device_ipv6_address),
            ];
            let stats = [incoming_ipv4_stats, incoming_ipv6_stats, outgoing_ipv4_stats, outgoing_ipv6_stats];

            let vec = Vec::new();

            let m = Arc::new(Mutex::new((RESUMED, vec, stats)));
            let m_cl = m.clone();
            let m_cl_2 = m.clone();
            let cv = Arc::new(Condvar::new());
            let cv_cl = cv.clone();
            let cv_cl_2 = cv.clone();

            // timeout thread
            spawn(move || {
                loop {
                    sleep(Duration::from_millis(update_time));
                    let mg_res = m_cl_2.lock();
                    match mg_res {
                        Ok(mut mg) if mg.0.is_resumed() => {
                            mg.2 = produce_report(report_file_name_cl_2.clone(), device_cl_2.clone(), mg.1.clone(), mg.2.clone());
                            mg.1 = Vec::new();
                        }
                        Ok(mut mg) if mg.0.is_paused() => {
                            mg = cv_cl_2.wait_while(mg, |mg| !mg.0.is_resumed()).unwrap();
                            continue
                        },
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

                let mut cap = Capture::from_device(device_cl.clone())
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
                                    cap = Capture::from_device(device_cl.clone())
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

                                // now check the filter

                                match tui {
                                    true => p.print_packet(sub4.as_ref()),
                                    false => p.print_packet(None),
                                }

                                mg.1.push(p);

                                // end of the filter check
                            }
                            Err(e) => {
                               match tui {
                                   true => {
                                       sub4.as_ref().unwrap().clear();
                                       sub4.as_ref().unwrap().printw(e.to_string().as_str());
                                       sub4.as_ref().unwrap().printw("\n");
                                       sub4.as_ref().unwrap().printw("Press any key to quit");
                                       sub4.as_ref().unwrap().refresh();
                                       //to make the error visible
                                       sleep(Duration::from_secs(2));
                                   },
                                   false => println!("ERROR: {}", e),
                               }
                                break;
                            }
                        }
                    } else if mg.0.is_paused() {
                        drop(cap);
                        mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                        cap = Capture::from_device(device_cl.clone())
                            .unwrap()
                            .timeout(10000)
                            .promisc(true)
                            .open()
                            .unwrap();
                    } else {
                        break
                    }
                }

                let mut mg = m_cl.lock().unwrap();
                mg.2 = produce_report(report_file_name_cl.clone(), device_cl.clone(), mg.1.clone(), mg.2.clone());

                // change the mutex, just in case of internal error
                mg.0 = STOPPED;
                cv_cl.notify_all();

                println!("Sniffing thread exiting");
            });

            Ok(Sniffer { m, jh, cv, device, report_file_name, tui_handler })
        }

        pub fn pause(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = PAUSED;

            print_state(self.tui_handler.2.as_ref(), &(mg.0));

            mg.2 = produce_report(self.report_file_name.clone(), self.device.clone(), mg.1.clone(), mg.2.clone());
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
            sub1.draw_box(0,0);
            sub1.mvprintw(1,2, "Command");
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
            let mut running= 0u8;

            loop {
                if !self.m.lock().unwrap().0.is_stopped() {
                    for (mut index, command) in commands.iter().enumerate() {
                        if menu == index as u8 {
                            sub1.attron(A_REVERSE);
                        } else {
                            sub1.attroff(A_REVERSE);
                        }
                        sub1.mvprintw({index += 2; index as i32}, 2, command);
                    }
                    match sub1.getch() { //getch waits for user key input -> returns Input value assoc. to the key
                        Some(Input::KeyUp) => {
                            if menu != 0 {
                                menu -= 1;
                                continue;
                            }
                        },
                        Some(Input::KeyDown) =>
                            {
                                if menu != 2 {
                                    menu += 1;
                                    continue;
                                }
                            },

                        Some(Input::KeyRight) => {
                            running = menu
                        },

                        Some(Input::Character('\n')) => {
                            running = menu
                        },

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
                    } else if cmd.chars().nth(0).unwrap().to_ascii_lowercase() == 'q'{
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
        source_address: String, // 26 - 29
        destination_address: String, // 30 - 33

        //level 4 header
        level_four_protocol: String, // 23
        source_port: u16, // 34 - 35
        destination_port: u16, // 36 - 37

        timestamp: u128,
        other: String
    }

    fn to_mac_address(p: &Packet, start: usize, end: usize) -> String {
        let mut s = String::new();
        (start..=end).for_each(|byte| {
            s.push_str(&[p[byte]].to_hex());
            if byte != end {
                s.push_str(":");
            }
        });
        s
    }

    //da gestire la casistica in cui level_three_type: 6
    fn to_ip_address(p: &Packet, start: usize, end: usize) -> String {
        let mut s = String::new();
        (start..=end).for_each(|byte| {
            s.push_str(&p[byte].to_string());
            if byte != end {
                s.push_str(".");
            }
        });
        s
    }

    fn to_ipv6_address(p: &Packet, start: usize, end: usize)-> String{
        let mut s = String::new();
        let mut count = 0;
        (start..end).for_each(|byte|{
                if &p[byte].to_string() == "0" {
                    count += 1;
                }else{
                    if count!=0{
                        if count==1 {
                            s.push_str("0:");
                        }else{
                            s.push_str(":");
                        }
                        count = 0;
                    }
                    s.push_str(&[p[byte]].to_hex());
                    if byte!= end {
                        s.push_str(":");
                    }
                }
        });
        s
    }

    fn to_u16(p: &Packet, start: usize) -> u16 {
        let param1: u16 = p[start] as u16 * 256;
        let param2 = p[start + 1] as u16;
        param1 + param2
    }

    fn to_u4(hlen: u8) -> u8 {
        hlen & 15
    }

    fn to_level_four_protocol(prot_num: u8) -> String {
        match prot_num {
            1 => "ICMP".to_string(),
            2 => "IGMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            58 => "ICMPv6".to_string(),
            _ => prot_num.to_string()
        }
    }

    fn to_level_three_protocol(prot_num: u16)-> String{
        match prot_num{
            2048 => "IPv4".to_string(), // 0x0800
            2054 => "ARP".to_string(), // 0x0806
            33024 => "IEEE 802.1Q".to_string(), // 0x8100
            35041 => "HomePlug AV".to_string(), // 0x88e1
            34525 => "IPv6".to_string(), // 0x86dd
            _ => "Unknown".to_string()
        }
    }


    impl NAPacket {
        fn new(pcap_packet: Packet) -> Self {
            let mut eth_type = to_u16(&pcap_packet,12);
            NAPacket {
                destination_mac_address: to_mac_address(&pcap_packet, 0, 5),
                source_mac_address: to_mac_address(&pcap_packet, 6, 11),

                level_three_type: to_level_three_protocol(to_u16(&pcap_packet,12)),

                other: match eth_type {
                    2054 => if pcap_packet[21] ==1 {"ARP Request".to_string()}else{"ARP Reply".to_string()}, // ARP, OpCode byte 21 = 1 Request, 2 Reply
                    _ => " ".to_string()
                },

                source_address: match eth_type {
                    2048 => to_ip_address(&pcap_packet, 26, 29) , //IPv4
                    2054 => to_ip_address(&pcap_packet, 28, 31), // ARP Sender IP
                    34525 => to_ipv6_address(&pcap_packet, 22, 37), //IPv6
                    _ => " ".to_string()
                } ,

                destination_address: match eth_type {
                    2048 => to_ip_address(&pcap_packet, 30, 33), //IPv4
                    2054 => to_ip_address(&pcap_packet, 38, 41), // ARP Target IP
                    34525 => to_ipv6_address(&pcap_packet, 38, 53), //IPv6
                    _ => " ".to_string()
                } ,

                total_length: pcap_packet.header.len,

                level_four_protocol: match eth_type{
                    2048 => to_level_four_protocol(pcap_packet[23]), //IPv4
                    34525 => match pcap_packet[20]{ //IPv6 byte 20 is Next Header
                        6 | 17 | 58 => to_level_four_protocol(pcap_packet[20]) , //IPv6 + TCP or IPv6 + UDP IPv6 + ICMPv6
                        _ => "".to_string()
                    } ,
                    _ => "".to_string()
                } ,

                source_port: match eth_type{
                    2048 => match pcap_packet[23] { //IPV4
                        6 | 17 => to_u16(&pcap_packet, 34), //IPV4 + TCP o IPV4+ UDP
                        _ => 0 as u16 // 0 for IGMP, ICMP
                    },
                    34525 => match pcap_packet[20]{ // IPv6
                        6 | 17  => to_u16(&pcap_packet, 54), //IPV6 + TCP o UDP
                        _ => 0 as u16
                    }
                    _ => 0 as u16
                }
                ,
                destination_port:  match eth_type{
                    2048 => match pcap_packet[23] { //IPV4
                        6 | 17 => to_u16(&pcap_packet, 36), //IPV4 + TCP o UDP
                        _ => 0 as u16 // 0 for IGMP, ICMP
                    },
                    34525 => match pcap_packet[20]{ // IPv6
                        6 | 17 => to_u16(&pcap_packet, 56), //IPV6 + TCP o UDP
                        _ => 0 as u16
                    }
                    _ => 0 as u16
                },

                timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),

            }}

        fn to_string_mac(&self) -> String {
            let mut s = String::new();
            s.push_str(
                &*("MAC_s: ".to_owned() + &self.source_mac_address
                    + &*" MAC_d: ".to_owned() + &self.destination_mac_address));
            s
        }

        fn to_string_source_socket(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("IP_s: ".to_owned() + &self.source_address
                + &*" Port_s: ".to_owned() + &self.source_port.to_string()));
            s
        }

        fn to_string_dest_socket(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("IP_d: ".to_owned() + &self.destination_address
                + &*" Port_d: ".to_owned() + &self.destination_port.to_string()));
            s
        }

        fn info(&self) -> String {
            let mut s = String::new();
            s.push_str(&*("L3_type: ".to_owned() + &self.level_three_type.to_string()
                + &*" Len: ".to_owned() + &self.total_length.to_string()
                + &*" L4_Prot: ".to_owned() + &self.level_four_protocol
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
    pub struct Stats {
        ip_address: String,
        port: u16,
        transported_protocols: Vec<String>,
        bytes_number: u128,
        first_timestamp: u128,
        last_timestamp: u128,
    }

    impl Stats {
        pub fn new(ip_address: String) -> Self {
            Stats {
                ip_address,
                port: 0,
                transported_protocols: Vec::new(),
                bytes_number: 0,
                first_timestamp: 0,
                last_timestamp: 0,
            }
        }
    }

    fn produce_report(file_name: String, device: Device, packets: Vec<NAPacket>, old_stats: [Vec<Stats>; 4]) -> [Vec<Stats>; 4] {
        fn produce_stats(old_stats: [Vec<Stats>; 4], device: Device, packets: Vec<NAPacket>) -> [Vec<Stats>; 4] {
            fn update_stats(vec: &mut Vec<Stats>, packet: &NAPacket, packet_port: u16, device_address: String) {
                let mut iter = vec.iter_mut();
                loop {
                    let item = iter.next();
                    match item {
                        // se è la prima volta che riempio il vettore
                        Some(stats) if stats.port == 0 => {
                            // aggiorna la porta
                            stats.port = packet_port;
                            // aggiungi il protocollo di livello 4
                            stats.transported_protocols.push(packet.level_four_protocol.clone());
                            // aggiorna il numero totale di bytes
                            stats.bytes_number = packet.total_length as u128;
                            // aggiorna il first timestamp
                            stats.first_timestamp = packet.timestamp;
                            // aggiorna il last timestamp
                            stats.last_timestamp = packet.timestamp;
                            break;
                        }
                        // se il vettore è già stato usato
                        Some(stats) => {
                            // controlla se la porta coincide
                            if stats.port == packet_port {
                                // queste sono le statistiche, aggiorna!
                                // aggiungi il protocollo di livello 4, se non c'è
                                if !stats.transported_protocols.contains(&packet.level_four_protocol) {
                                    stats.transported_protocols.push(packet.level_four_protocol.clone());
                                }
                                // aggiorna il numero totale di bytes
                                stats.bytes_number += packet.total_length as u128;
                                // aggiorna il last timestamp
                                stats.last_timestamp = packet.timestamp;
                                break;
                            } else {
                                // statistiche non ancora trovate, continua a cercare!
                                continue;
                            }
                        }
                        // se la statistica non c'è
                        None => {
                            // aggiungi una stats
                            let mut stats = Stats::new(device_address);
                            // aggiorna la porta
                            stats.port = packet_port;
                            // aggiungi il protocollo di livello 4
                            stats.transported_protocols.push(packet.level_four_protocol.clone());
                            // aggiorna il numero totale di bytes
                            stats.bytes_number = packet.total_length as u128;
                            // aggiorna il first timestamp
                            stats.first_timestamp = packet.timestamp;
                            // aggiorna il last timestamp
                            stats.last_timestamp = packet.timestamp;
                            // aggiungi stats a vettore
                            vec.push(stats);
                            break;
                        }
                    }
                }
            }

            // network address/port pair
            // protocols transported
            // cumulated number of bytes transmitted
            // timestamp of the first and last occurrence of information exchanged
            // indirizzi del device
            let device_ipv4_address = device.addresses[0].addr.to_string();
            let device_ipv6_address = device.addresses[1].addr.to_string();

            let mut incoming_ipv4_stats = old_stats[0].clone();
            let mut incoming_ipv6_stats = old_stats[1].clone();
            let mut outgoing_ipv4_stats = old_stats[2].clone();
            let mut outgoing_ipv6_stats = old_stats[3].clone();

            for packet in packets {
                // controlla il source address del pacchetto, poi il destination
                match (&packet.source_address, &packet.destination_address) {
                    // outgoing packet
                    (it, _) if *it == device_ipv4_address => {
                        // se è un outgoing ipv4 packet
                        update_stats(&mut outgoing_ipv4_stats, &packet, packet.source_port, device_ipv4_address.clone());
                    }
                    (it, _) if *it == device_ipv6_address => {
                        // se è un outgoing ipv6 packet
                        update_stats(&mut outgoing_ipv6_stats, &packet, packet.source_port, device_ipv6_address.clone());
                    }
                    // incoming packet
                    (_, it) if *it == device_ipv4_address => {
                        // se è un incoming ipv4 packet
                        update_stats(&mut incoming_ipv4_stats, &packet, packet.destination_port, device_ipv4_address.clone());
                    }
                    (_, it) if *it == device_ipv6_address => {
                        // se è un incoming ipv6 packet
                        update_stats(&mut incoming_ipv6_stats, &packet, packet.destination_port, device_ipv6_address.clone());
                    }
                    _ => {
                        //println!("Ignored packet! Protocol: {:?}, Source: {:?}, Destination: {:?}", packet.level_three_type, packet.source_address, packet.destination_address);
                        // panic!("Should not be possible!");
                        continue;
                    }
                }
            }
            [incoming_ipv4_stats, incoming_ipv6_stats, outgoing_ipv4_stats, outgoing_ipv6_stats]
        }
        // define the path
        let vec = produce_stats(old_stats, device, packets);
        // crea il file o tronca al byte 0 se il file esiste già
        let mut report = File::create(file_name.clone()).unwrap(); // returns a Result
        // scrivi le stringhe nel report
        writeln!(report, "Sniffer report")
            .expect("Unable to write the report file!");
        writeln!(report).expect("Unable to write the report file!");
        for (i, stats_group) in vec.clone().iter().enumerate() {
            writeln!(report, "========================================================================")
                .expect("Unable to write the report file!");
            writeln!(report).expect("Unable to write the report file!");
            match i {
                0 => writeln!(report, "Incoming IPv4 Stats"),
                1 => writeln!(report, "Incoming IPv6 Stats"),
                2 => writeln!(report, "Outgoing IPv4 Stats"),
                3 => writeln!(report, "Outgoing IPv6 Stats"),
                _ => panic!("Should not be possible!")
            }.expect("Unable to write the report file!");
            writeln!(report).expect("Unable to write the report file!");
            // for each stats_group write the stats
            'inner: for stats in stats_group {
                // se port == 0, ignora
                if stats.port == 0 {
                    writeln!(report, "There is no traffic!")
                        .expect("Unable to write the report file!");
                    writeln!(report).expect("Unable to write the report file!");
                    break 'inner;
                }
                // write the ip address
                writeln!(report, "Ip address: {}", stats.ip_address)
                    .expect("Unable to write the report file!");
                // write the port
                writeln!(report, "Port: {}", stats.port)
                    .expect("Unable to write the report file!");
                // write the list of transported protocols
                writeln!(report, "Transported protocols: {}", stats.transported_protocols.iter().fold(
                    String::new(), |mut acc, prot| {
                        acc.push_str(prot.as_str());
                        acc.push_str(", ");
                        acc
                    })
                ).expect("Unable to write the report file!");
                // write the total number of bytes
                writeln!(report, "Cumulated number of bytes transmitted: {}", stats.bytes_number)
                    .expect("Unable to write the report file!");
                // write the first timestamp
                writeln!(report, "Timestamp of the first occurrence of information exchanged: {}", stats.first_timestamp)
                    .expect("Unable to write the report file!");
                // write the last timestamp
                writeln!(report, "Timestamp of the last occurrence of information exchanged: {}", stats.last_timestamp)
                    .expect("Unable to write the report file!");
                writeln!(report).expect("Unable to write the report file!");
            }
        }
        println!("Report produced!");
        vec
    }

    mod format {
        pub fn get_file_name(mut string: String) -> String {
            string = string.trim().to_string();
            if !string.ends_with(".txt") {
                string.push_str(".txt");
            }
            string
        }
    }
}
