use std::io::stdin;
use std::thread::sleep;
use std::time::Duration;
use clap::Parser;
use network_analyzer::sniffer::{Sniffer};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    adapter: String,
    #[clap(short, long, value_parser, default_value = "report")]
    output: String,
    #[clap(short, long, value_parser, default_value = "10000")]
    timeout: i32,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
}

fn print_commands() {
    println!("****** COMMANDS ******");
    println!("Press \"P\" to pause");
    println!("Press \"R\" to resume");
    println!("Press \"S\" to stop");
    println!("**********************");
}

fn main() {
    let args = Args::parse();
    println!("{}", args.adapter);
    println!("{}", args.output);
    println!("{}", args.timeout);
    println!("{}", args.filter);

    print_commands();
    sleep(Duration::from_secs(5));

    //Application state
    let s = Sniffer::new(args.adapter, args.output, args.timeout, args.filter);
    match s {
        Ok(sniffer) => {
            //Event loop
            while !sniffer.jh.is_finished() {
                let mut command = String::new();
                stdin().read_line(&mut command).unwrap();
                if command.chars().nth(0).unwrap() == 'P' {
                    sniffer.pause();
                    print_commands();
                } else if command.chars().nth(0).unwrap() == 'R' {
                    sniffer.resume();
                    print_commands();
                } else if command.chars().nth(0).unwrap() == 'S' {
                    sniffer.stop();
                } else {
                    println!("Unavailable command");
                }
            }

            //Process closing
            sniffer.jh.join().unwrap();
        }
        Err(why) => println!("{}", why)
    }
}


