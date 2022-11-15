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
        writeln!(report_md, "No traffic detected!")
            .expect("Unable to write the report file!");
        writeln!(report_xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            .expect("Unable to write the report file!");
        writeln!(report_xml, "<report>No traffic detected!</report>")
            .expect("Unable to write the report file!");
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
    writeln!(report_xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
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
