use std::fs::File;
use pcap::Device;

pub mod sniffer {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use std::fs::File;
    use std::io::Write;
    use pcap::{Capture, Device, Packet};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{JoinHandle, sleep, spawn};
    use std::time::{Duration, SystemTime};
    use cursive::backends::curses::pan::pancurses::{newwin, Window};
    use rustc_serialize::hex::ToHex;
    use crate::sniffer::NAState::{PAUSED, RESUMED, STOPPED};

    #[derive(Debug)]
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
        report_file_name: String
    }

    impl Sniffer {
        pub fn new(adapter: String, output: String, timeout: i32, filter: String) -> Result<Self, NAError> {

            //Solo per debug: stampo i vari devices
            let d = Device::list().unwrap();
            for (i, device) in d.iter().enumerate() {
                print!("Device {} | ", i);
                for addr in &device.addresses {
                    print!("{:?} | ", addr.addr);
                }
                println!()
            }

            let device = match d.into_iter().find(|d| d.name == adapter) {
                Some(dev) => dev,
                None => return Err(NAError::new("Device not found")),
            };

            let mut cap = Capture::from_device(device.clone())
                .unwrap()
                .timeout(10000)
                .promisc(true)
                .open()
                .unwrap();

            let vec = Vec::new();

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

            let m = Arc::new(Mutex::new((RESUMED, vec, stats)));
            let m_cl = m.clone();
            let m_cl_2 = m.clone();
            let cv = Arc::new(Condvar::new());
            let cv_cl = cv.clone();
            let cv_cl_2 = cv.clone();

            let device_cl = device.clone();
            let output_cl = output.clone();
            let device_cl_2 = device.clone();
            let output_cl_2 = output.clone();
            // timeout thread
            spawn(move || {
                loop {
                    sleep(Duration::from_millis(timeout as u64));
                    let mg_res = m_cl_2.lock();
                    match mg_res {
                        Ok(mut mg) if mg.0.is_resumed() => {
                            mg.2 = produce_report(output_cl_2.clone(), device_cl_2.clone(), mg.1.clone(), mg.2.clone());
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

                let sub3 = newwin(33, 78, 5, 1);
                sub3.draw_box(0,0);
                sub3.refresh();
                let sub4 = newwin(31, 76, 6, 2);
                sub4.scrollok(true);
                sub4.setscrreg(6, 30);

                println!("****** SNIFFING STARTED ******");
                loop {
                    let mut mg = m_cl.lock().unwrap();
                    if mg.0.is_resumed() {
                        // rilascia il lock prima di next_packet() (bloccante)
                        drop(mg);
                        match cap.next_packet() {
                            Ok(packet) => {
                                mg = m_cl.lock().unwrap();
                                if mg.0.is_paused() {
                                    continue;
                                } else if mg.0.is_stopped() {
                                    break;
                                }

                                let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
                                let p = NAPacket::new(packet.clone(), timestamp);
                                println!("{:?}", p);
                                sub4.printw(&p.to_string_mac());
                                sub4.printw("\n");
                                sub4.printw(&p.to_string_source_socket());
                                sub4.printw("\n");
                                sub4.printw(&p.to_string_dest_socket());
                                sub4.printw("\n");
                                sub4.printw(&p.info());
                                sub4.printw("\n");
                                sub4.printw("\n");
                                sub4.refresh();
                                mg.1.push(p);
                            }
                            Err(e) => {
                                println!("ERROR: {}", e);
                                break;
                            }
                        }
                    } else if mg.0.is_paused() {
                        mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                    } else {
                        break
                    }
                }

                let mut mg = m_cl.lock().unwrap();
                mg.2 = produce_report(output_cl.clone(), device_cl.clone(), mg.1.clone(), mg.2.clone());

                // change the mutex, just in case
                mg.0 = STOPPED;
                cv_cl.notify_all();

                println!("****** SNIFFING TERMINATED ******");
            });

            Ok(Sniffer { m, jh, cv, device, report_file_name: output })
        }

        pub fn pause(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = PAUSED;

            println!("****** SNIFFING PAUSED ******");

            mg.2 = produce_report(self.report_file_name.clone(), self.device.clone(), mg.1.clone(), mg.2.clone());
            mg.1 = Vec::new();
        }

        pub fn resume(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = RESUMED;
            self.cv.notify_all();
            println!("****** SNIFFING RESUMED ******");
        }

        pub fn stop(&self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = STOPPED;
            self.cv.notify_all();
        }
    }

    #[derive(Debug, Clone)]
    struct NAPacket {
        //level 2 header
        destination_mac_address: String, // 0 - 5
        source_mac_address: String, // 6 - 11
        //level 3 header
        level_three_type: u8, // 12 - 13
        header_length: u8, // 14
        explicit_congestion_notification: u8, // 15
        total_length: u16, // 16 - 17
        identification: u16, // 18 - 19
        fragment_offset: u16, // 20 - 21
        ttl: u8, // 22
        level_four_protocol: String, // 23
        header_checksum: u16, // 24 - 25
        source_address: String, // 26 - 29
        destination_address: String, // 30 - 33
        source_port: u16, // 34 - 35
        destination_port: u16, // 36 - 37
        other_data: Vec<u8>,
        timestamp: u128
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
            _ => prot_num.to_string()
        }
    }


    impl NAPacket {
        fn new(pcap_packet: Packet, timestamp: u128) -> Self {
            NAPacket {
                destination_mac_address: to_mac_address(&pcap_packet, 0, 5),
                source_mac_address: to_mac_address(&pcap_packet, 6, 11),
                level_three_type: if to_u16(&pcap_packet, 12) == 2048 { 4 } else { 6 },
                header_length: pcap_packet[14],
                explicit_congestion_notification: pcap_packet[15],
                total_length: to_u16(&pcap_packet, 16),
                identification: to_u16(&pcap_packet, 18),
                fragment_offset: to_u16(&pcap_packet, 20),
                ttl: pcap_packet[22],
                level_four_protocol: to_level_four_protocol(pcap_packet[23]),
                header_checksum: to_u16(&pcap_packet, 24),
                source_address: to_ip_address(&pcap_packet, 26, 29),
                destination_address: to_ip_address(&pcap_packet, 30, 33),
                source_port: to_u16(&pcap_packet, 34),
                destination_port: to_u16(&pcap_packet, 36),
                other_data: vec![],
                timestamp
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
                + &*" L4_Prot ".to_owned() + &self.level_four_protocol
                + &*" TS: ".to_owned() + &self.timestamp.to_string()));
            s
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


    //pub fn na_config(){
       // let mut adapter_name = String::new();
       // let mut report_file_name = String::new();

       // println!("Select the adapter to sniff: ");
       // println!("{}", list_adapters().unwrap());
       // stdout().flush().unwrap();
       // stdin().read_line(&mut adapter_name).unwrap();

        // println!("Define .txt report file path and name: ");
        // stdout().flush().unwrap();
        // stdin().read_line(&mut report_file_name).unwrap();

    //}


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
                        println!("Ignored packet! Protocol: {:?}, Source: {:?}, Destination: {:?}", packet.level_three_type, packet.source_address, packet.destination_address);
                        // panic!("Should not be possible!");
                        continue;
                    }
                }
            }
            [incoming_ipv4_stats, incoming_ipv6_stats, outgoing_ipv4_stats, outgoing_ipv6_stats]
        }
        // define the path
        let vec = produce_stats(old_stats, device, packets);
        let mut path = file_name.clone();
        path.push_str(".txt");
        // crea il file o tronca al byte 0 se il file esiste già
        let mut report = File::create(path).unwrap(); // returns a Result
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
}
