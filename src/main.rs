use std::io::{Read, stdin, stdout, Write};
use clap::Parser;
use network_analyzer::sniffer::{list_adapters, na_config};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    network_adapter: String,
}


fn main() {
    //let args = Args::parse();
    na_config();


}
