use std::io::stdin;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use clap::Parser;
use cursive::backends::curses::pan::pancurses::{ALL_MOUSE_EVENTS, A_BLINK, A_BOLD, A_NORMAL, cbreak, curs_set, endwin, getmouse, initscr, Input, mousemask, newwin, noecho, resize_term, A_REVERSE, start_color, init_pair, COLOR_GREEN, COLOR_BLACK, COLOR_PAIR};
use cursive::{Cursive, CursiveExt, pancurses};
use cursive::theme::PaletteColor::Highlight;
use cursive::views::{Dialog, TextView};
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
    update_time: i32,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
    #[clap(short, long, value_parser, default_value = "true")]
    tui: bool,
}

fn main() {
    let args = Args::parse();

    //Application state
    let s = Sniffer::new(args.adapter, args.output, args.update_time, args.filter, args.tui).unwrap();
    if args.tui {
        s.event_handler();
    }
    //Process closing
    s.jh.join().unwrap();

}


