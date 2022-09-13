pub mod sniffer {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use std::io::{stdin, stdout, Write};
    use pcap::{Device, Packet};
    use std::str::from_utf8;
    use rustc_serialize::hex::ToHex;

    pub struct Sniffer {}

    #[derive(Debug)]
    pub struct NAPacket {
        level_three_type: u8, // 12 - 13
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

    pub fn to_mac_address(p: &Packet, start: usize, end:usize)-> String{
        let mut s = String::new();
        (start..=end).for_each(|byte| {
            let v = vec![p[byte]];
            s.push_str(&v[..].to_hex());
            if byte!=end{
                s.push_str(":");
            }
        });
        s
    }

    pub fn to_ip_address(p: &Packet,start: usize, end: usize)->String{
        let mut s = String::new();
        (start..=end).for_each(|byte| {
            let v = vec![p[byte]];
            s.push_str(&p[byte].to_string());
            if byte!=end{
                s.push_str(".");
            }
        });
        s
    }

    pub fn to_u16(p: &Packet, start: usize) -> u16 {
        let param1 : u16 = p[start] as u16 * 256;
        let param2 = p[start+1] as u16;
        param1 + param2
    }


    impl NAPacket{
        pub fn new(pcap_packet: Packet)-> Self {
            NAPacket{
                level_three_type: if (pcap_packet[12] == 8){4} else {6},
                header_length: pcap_packet[14],
                explicit_congestion_notification: pcap_packet[15],
                total_length: to_u16(&pcap_packet, 16),
                identification: to_u16(&pcap_packet, 18),
                fragment_offset: to_u16(&pcap_packet, 20),
                ttl: pcap_packet[22],
                level_four_protocol: pcap_packet[23],
                header_checksum: to_u16(&pcap_packet, 24),
                source_address: to_ip_address(&pcap_packet, 26, 29),
                destination_address: to_ip_address(&pcap_packet, 30, 33),
                source_port: to_u16(&pcap_packet, 34),
                destination_port: to_u16(&pcap_packet, 36),
                other_data: vec![]
            }}
    }



    #[derive(Debug)]
    pub struct NAError{
        message: String,
    }

    impl NAError{
        fn new(msg: &str)-> Self{NAError{message: msg.to_string()}}
    }

    impl Display for NAError{
        fn fmt(&self, f:&mut Formatter<'_>)-> std::fmt::Result{
            write!(f,"NAError: {}",self.message)
        }
    }

    impl Error for NAError{}


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


    pub fn na_config(){
        let mut adapter_name = String::new();
        let mut report_file_name = String::new();

        println!("Select the adapter to sniff: ");
        println!("{}", list_adapters().unwrap());
        stdout().flush().unwrap();
        stdin().read_line(&mut adapter_name).unwrap();

        println!("Define .txt report file path and name: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut report_file_name).unwrap();

    }


}