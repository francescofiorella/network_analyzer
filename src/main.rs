use clap::Parser;
use pcap::Device;
use network_analyzer::sniffer::{Sniffer};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    adapter: String,
    #[clap(short, long, value_parser, default_value = "report")]
    output: String,
    #[clap(short, long, value_parser, default_value = "10000")]
    update_time: u64,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
    #[clap(short, long, value_parser, default_value = "false")]
    tui: bool,
    #[clap(short, long, value_parser, default_value = "false")]
    list_adapters: bool,
}

fn main() {
    let args = Args::parse();

    if args.list_adapters {
        let adapter_list = Device::list().unwrap();
        println!("------------------------ ADAPTER LIST ------------------------");
        for (index , device) in adapter_list.into_iter().enumerate() {
            let format = (index+1).to_string().as_str().to_owned() + ") Adapter name: " + device.name.as_str();
            println!("{}", format);
        }
        println!("--------------------------------------------------------------")
    } else {
        //Application state
        let s = Sniffer::new(args.adapter, args.output, args.update_time, args.filter, args.tui).unwrap();
        //event handler
        //Main thread in loop qui dentro
        s.enable_commands();
        //Main thread attende qui la terminazione di jh, dopo la quale termina il processo
        //DA TOGLIERE DA QUI, BISOGNERA' GESTIRLA CON IL DISTRUTTORE...
        s.jh.join().unwrap();
    }




}


