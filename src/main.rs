use std::io::stdin;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use clap::Parser;
use cursive::backends::curses::pan::pancurses::{ALL_MOUSE_EVENTS, A_BLINK, A_BOLD, A_NORMAL, cbreak, curs_set, endwin, getmouse, initscr, Input, mousemask, newwin, noecho, resize_term, A_REVERSE, start_color, init_pair, COLOR_GREEN, COLOR_BLACK, COLOR_PAIR, COLOR_WHITE};
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
    #[clap(short, long, value_parser, default_value = "result")]
    output: String,
    #[clap(short, long, value_parser, default_value = "10000")]
    timeout: u64,
    #[clap(short, long, value_parser, default_value = "None")]
    filter: String,
}

fn main() {
    let args = Args::parse();

    let commands = vec![
        "PAUSE",
        "RESUME",
    ];

    //screen initialization
    let mut window = initscr();

    //Color inizialization
    start_color();
    init_pair(1,COLOR_WHITE,COLOR_BLACK);
    window.attron(COLOR_PAIR(1));

    resize_term(38, 80);
    noecho();
    curs_set(0);
    //refresh the screen to match whats in memory
    window.refresh();
    window.keypad(true);
    mousemask(ALL_MOUSE_EVENTS, None);

    let sub1 = window.subwin(5, 11, 0, 1).unwrap();
    sub1.draw_box(0,0);
    sub1.mvprintw(1,2, "Command");
    sub1.keypad(true);
    sub1.refresh();

    let sub2 = window.subwin(5, 67, 0, 12).unwrap();
    sub2.draw_box(0,0);
    sub2.mvprintw(1, 1, "Adapter: ");
    sub2.mvprintw(1, 9, &args.adapter);
    sub2.mvprintw(2, 1, "Filter: ");
    sub2.mvprintw(2, 9, &args.filter);
    sub2.mvprintw(3, 1, "Output file: ");
    sub2.mvprintw(3, 14, &args.output);
    sub2.refresh();

    //Application state
    let s = Sniffer::new(args.adapter, args.output, args.timeout, args.filter).unwrap();

    //Event loop
    let mut menu = 0;
    let mut running = true;

    while !s.jh.is_finished() {
        for (index, command) in commands.iter().enumerate() {
            if menu == index {
                sub1.attron(A_BLINK);
            }
            else {
                sub1.attroff(A_BLINK);
            }
            if index == 0 {
                sub1.mvprintw(2, 2, command);
            } else {
                sub1.mvprintw(3, 2, command);
            }

        }
        match sub1.getch(){ //getch waits for user key input -> returns Input value assoc. to the key
            Some(Input::KeyMouse)=>{
                if let Ok(mouse_event)= getmouse(){
                    if(mouse_event.y==2){
                        if(mouse_event.x>=2 && mouse_event.x<8){
                            running = false;
                        }
                    }

                    if(mouse_event.y==3){
                        if(mouse_event.x>=3 && mouse_event.x<9){
                            running = true
                        }
                    }
                }
            }
            Some(Input::KeyUp) => {
                if menu != 0 {
                    menu -= 1;
                    continue;
                }
            },
            Some(Input::KeyDown) =>
                {
                    if menu != 1 {
                        menu += 1;
                        continue;
                    }
                },

            Some(Input::KeyRight) => {
                running = if menu == 0 {false} else {true}
            },

            Some(_) => continue,

            None => (),
        }

        if running {
            s.resume();
        } else {
            s.pause();
        }

    }

    //Process closing
    s.jh.join().unwrap();
    window.attroff(COLOR_PAIR(1));
    endwin(); //screen deallocation

}


