pub mod sniffer {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use pcap::Packet;

    pub struct Sniffer {}
    pub struct NAPacket {
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


}