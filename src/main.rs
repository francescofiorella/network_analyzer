use std::io::stdin;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use clap::Parser;
use pcap::{Capture, Device};
use network_analyzer::sniffer::{Sniffer};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    adapter: String,
    #[clap(short, long, value_parser, default_value = "result.txt")]
    output: String,
    #[clap(short, long, value_parser, default_value = "0")]
    timeout: i32,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
}

fn main() {
    let args = Args::parse();
    println!("{}", args.adapter);
    println!("{}", args.output);
    println!("{}", args.timeout);
    println!("{}", args.filter);

    println!("****** COMMANDS ******");
    println!("Press \"P\" to pause");
    println!("Press \"R\" to resume");
    println!("**********************");
    sleep(Duration::from_secs(5));

    //Application state
    let s = Sniffer::new(args.adapter, args.output, args.timeout, args.filter).unwrap();

    //Event loop
    while !s.jh.is_finished() {
        let mut command = String::new();
        stdin().read_line(&mut command).unwrap();
        if command.chars().nth(0).unwrap() == 'P' {
            s.pause();
        } else if command.chars().nth(0).unwrap() == 'R' {
            s.resume();
        } else {
            println!("Unavailable command");
        }
    }

    //Process closing
    s.jh.join().unwrap();

    //let stats = produce_stats(device, vec);
    //produce_report(stats);
}


