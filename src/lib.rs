pub mod sniffer {
    use std::fs::File;
    use std::io::Write;
    use pcap::Device;

    pub struct Sniffer {}
    pub struct Packet {
        destination_mac_address: String, // 0 - 5
        source_mac_address: String, // 6 - 11
        level_three_type: u16, // 12 - 13
        header_length: u8, // 14
        explicit_congestion_notification: u8, // 15
        total_length: u16, // 16 - 17
        identification: u16, // 18 - 19
        fragment_offset: u16, // 20 - 21
        ttl: u8, // 22
        level_four_protocol: u8, // 23
        header_checksum: u16, // 24 - 25
        source_address: String, // 26 - 29
        destination_address: String, // 30 - 33
        source_port: u16, // 34 - 35
        destination_port: u16, // 36 - 37
        other_data: Vec<u8>
    }

    impl Packet {
        pub fn new(total_length: u16,
                   level_four_protocol: u8,
                   source_address: String,
                   destination_address: String,
                   source_port: u16,
                   destination_port: u16
        ) -> Self {
            Packet {
                destination_mac_address: String::new(),
                source_mac_address: String::new(),
                level_three_type: 0,
                header_length : 0,
                explicit_congestion_notification: 0,
                total_length,
                identification: 0,
                fragment_offset: 0,
                ttl: 0,
                level_four_protocol,
                header_checksum: 0,
                source_address,
                destination_address,
                source_port,
                destination_port,
                other_data: vec![],
            }
        }
    }

    #[derive(Debug)]
    pub struct Stats {
        ip_address: String,
        port: u16,
        transported_protocols: Vec<u8>,
        bytes_number: u16,
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

    pub fn produce_stats(device: Device, packets: Vec<&Packet>) -> [Vec<Stats>; 4] {
        fn update_stats(vec: &mut Vec<Stats>, packet: &Packet, packet_port: u16, device_address: String) {
            let mut iter = vec.iter_mut();
            loop {
                let item = iter.next();
                match item {
                    // se è la prima volta che riempio il vettore
                    Some(stats) if stats.port == 0 => {
                        // aggiorna la porta
                        stats.port = packet_port;
                        // aggiungi il protocollo di livello 4
                        stats.transported_protocols.push(packet.level_four_protocol);
                        // aggiorna il numero totale di bytes
                        stats.bytes_number = packet.total_length;
                        // aggiorna il first timestamp
                        // stats.first_timestamp = something;
                        // aggiorna il last timestamp
                        // stats.last_timestamp = something;
                        break;
                    }
                    // se il vettore è già stato usato
                    Some(stats) => {
                        // controlla se la porta coincide
                        if stats.port == packet_port {
                            // queste sono le statistiche, aggiorna!
                            // aggiungi il protocollo di livello 4, se non c'è
                            if !stats.transported_protocols.contains(&packet.level_four_protocol) {
                                stats.transported_protocols.push(packet.level_four_protocol);
                            }
                            // aggiorna il numero totale di bytes
                            stats.bytes_number += packet.total_length;
                            // aggiorna il last timestamp
                            // stats.last_timestamp = something;
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
                        stats.transported_protocols.push(packet.level_four_protocol);
                        // aggiorna il numero totale di bytes
                        stats.bytes_number = packet.total_length;
                        // aggiorna il first timestamp
                        // stats.first_timestamp = something;
                        // aggiorna il last timestamp
                        // stats.last_timestamp = something;
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
        //
        let mut incoming_ipv4_stats = vec![
            Stats::new(device_ipv4_address.clone()),
        ];
        let mut incoming_ipv6_stats = vec![
            Stats::new(device_ipv6_address.clone()),
        ];
        let mut outgoing_ipv4_stats = vec![
            Stats::new(device_ipv4_address.clone()),
        ];
        let mut outgoing_ipv6_stats = vec![
            Stats::new(device_ipv6_address.clone()),
        ];
        for packet in packets {
            // controlla il source address del pacchetto, poi il destination
            match (&packet.source_address, &packet.destination_address) {
                // outgoing packet
                (it, _) if *it == device_ipv4_address => {
                    // se è un outgoing ipv4 packet
                    update_stats(&mut outgoing_ipv4_stats, packet, packet.source_port, device_ipv4_address.clone());
                }
                (it, _) if *it == device_ipv6_address => {
                    // se è un outgoing ipv6 packet
                    update_stats(&mut outgoing_ipv6_stats, packet, packet.source_port, device_ipv6_address.clone());
                }
                // incoming packet
                (_, it) if *it == device_ipv4_address => {
                    // se è un incoming ipv4 packet
                    update_stats(&mut incoming_ipv4_stats, packet, packet.destination_port, device_ipv4_address.clone());
                }
                (_, it) if *it == device_ipv6_address => {
                    // se è un incoming ipv6 packet
                    update_stats(&mut incoming_ipv6_stats, packet, packet.destination_port, device_ipv6_address.clone());
                }
                _ => panic!("Should not be possible!")
            }
        }
        [incoming_ipv4_stats, incoming_ipv6_stats, outgoing_ipv4_stats, outgoing_ipv6_stats]
    }

    pub fn produce_report(vec: [Vec<Stats>; 4]) {
        // define the path
        let path = "report.txt";
        // crea il file o tronca al byte 0 se il file esiste già
        let mut report = File::create(path).unwrap(); // returns a Result
        // scrivi le stringhe nel report
        writeln!(report, "Sniffer report")
            .expect("Unable to write the report file!");
        writeln!(report).expect("Unable to write the report file!");
        for (i, stats_group) in vec.iter().enumerate() {
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
                    String::new(), |acc, &num| acc + &num.to_string() + ", ")
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
    }
}