use std::io::stdin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use clap::Parser;
use cursive::backends::curses::pan::pancurses::{A_BOLD, A_REVERSE, COLOR_BLACK, COLOR_CYAN, COLOR_GREEN, COLOR_MAGENTA, COLOR_PAIR, COLOR_WHITE, COLOR_YELLOW, curs_set, init_pair, initscr, Input, newwin, noecho, resize_term, start_color, Window};
use pcap::Device;
use network_analyzer::sniffer::{get_adapter, Sniffer};
use network_analyzer::sniffer::channel::Message;
use network_analyzer::sniffer::filter::{Filter, get_filter};
use network_analyzer::sniffer::na_error::NAError;
use network_analyzer::sniffer::na_packet::NAPacket;
use network_analyzer::sniffer::na_state::NAState;
use network_analyzer::sniffer::na_state::NAState::{PAUSED, RESUMED, STOPPED};


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value = "1")]
    adapter: u8,
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

const RUN: &str = "****** SNIFFING PACKETS... ******";
const PAUSE: &str = "****** SNIFFING PAUSED ******";
const QUIT: &str = "****** SNIFFING CLOSING... ******";

fn notui_show_commands() {
    let commands = "\
        ****** Commands ******\n\
        Press \"P + Enter\" to pause\n\
        Press \"R + Enter\" to resume\n\
        Press \"Q + Enter\" to quit \n\
        **********************\n\
        Starting sniffing...";

    println!("{}", commands);
    sleep(Duration::from_secs(3));
    println!("{}", RUN);
}

fn tui_init(adapter: &str, filter: &Filter, output: &str, update_time: u64) -> Window {
    //screen initialization
    if cfg!(target_os = "macos") {
        Command::new("/usr/X11/bin/resize").arg("-s").arg("43").arg("80").output().expect("Error while calling resize command");
    } else if cfg!(target_os="linux") {
        Command::new("resize").arg("-s").arg("43").arg("80").output().expect("Error while calling resize command");
    }
    let window = initscr();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(2, COLOR_YELLOW, COLOR_BLACK);
    init_pair(3, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(4, COLOR_GREEN, COLOR_BLACK);
    init_pair(5, COLOR_CYAN, COLOR_BLACK);

    //screen settings
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        resize_term(0, 0);
    } else {
        resize_term(42, 80);
    }
    noecho();
    curs_set(0);
    window.keypad(true);
    window.refresh();

    //subwindow 2
    let sub2 = window.subwin(6, 67, 0, 12).unwrap();
    sub2.draw_box(0, 0);
    sub2.attron(COLOR_PAIR(4));
    sub2.attron(A_BOLD);
    sub2.mvprintw(1, 1, "Adapter: ");
    sub2.attroff(A_BOLD);
    sub2.mvprintw(1, 10, adapter);
    sub2.attron(A_BOLD);
    sub2.mvprintw(2, 1, "Filter: ");
    sub2.attroff(A_BOLD);
    sub2.mvprintw(2, 9, filter.to_string());
    sub2.attron(A_BOLD);
    sub2.mvprintw(3, 1, "Output file: ");
    sub2.attroff(A_BOLD);
    sub2.mvprintw(3, 14, output);
    sub2.attron(A_BOLD);
    sub2.mvprintw(4, 1, "Output upd. time (ms): ");
    sub2.attroff(A_BOLD);
    sub2.mvprintw(4, 24, update_time.to_string().as_str());
    sub2.attroff(COLOR_PAIR(4));
    sub2.refresh();

    //subwindow 3
    let sub3 = newwin(33, 78, 9, 1);
    sub3.draw_box(0, 0);
    sub3.refresh();
    window
}

fn state_win_init() -> Window {
    let state_window = newwin(3, 78, 6, 1);
    state_window.draw_box(0, 0);
    state_window.mvprintw(1, 22, RUN);
    state_window.refresh();
    state_window
}

pub fn print_packet(p: NAPacket, tui_window: Option<&Window>, tui_mutex: Arc<Mutex<()>>) {
    if tui_window.is_some() {
        let _mg = tui_mutex.lock().unwrap(); //drop at the end of the block
        tui_window.as_ref().unwrap().attron(A_BOLD);
        tui_window.as_ref().unwrap().attron(COLOR_PAIR(2));
        tui_window.as_ref().unwrap().printw(p.to_string_mac());
        tui_window.as_ref().unwrap().printw("\n");
        tui_window.as_ref().unwrap().attroff(COLOR_PAIR(2));
        tui_window.as_ref().unwrap().attron(COLOR_PAIR(3));
        tui_window.as_ref().unwrap().printw(p.to_string_endpoints());
        tui_window.as_ref().unwrap().printw("\n");
        tui_window.as_ref().unwrap().printw(p.to_string_ports());
        tui_window.as_ref().unwrap().printw("\n");
        tui_window.as_ref().unwrap().attroff(COLOR_PAIR(3));
        tui_window.as_ref().unwrap().attron(COLOR_PAIR(5));
        tui_window.as_ref().unwrap().printw(p.info());
        tui_window.as_ref().unwrap().attroff(COLOR_PAIR(5));
        tui_window.as_ref().unwrap().printw("\n");
        tui_window.as_ref().unwrap().printw("\n");
        tui_window.as_ref().unwrap().attroff(A_BOLD);
        tui_window.as_ref().unwrap().refresh();
    } else {
        println!("{}", p);
    }
}

fn print_state(state_window: Option<&Window>, state: &NAState, tui_mutex: Arc<Mutex<()>>) {
    let msg = match state {
        PAUSED => PAUSE,
        STOPPED => QUIT,
        RESUMED => RUN,
    };

    match state_window {
        Some(sw) => {
            let _mg = tui_mutex.lock().unwrap(); //release at end of the block
            sw.clear();
            sw.draw_box(0, 0);
            sw.mvprintw(1, 22, msg);
            sw.refresh();
        }

        None => println!("{}", msg),
    }
}

fn print_error(sub4: Option<&Window>, error: NAError, tui_enabled: bool, tui_mutex: Arc<Mutex<()>>) {
    if tui_enabled {
        let _mg = tui_mutex.lock().unwrap(); //drop at the end of the block
        sub4.as_ref().unwrap().clear();
        sub4.as_ref().unwrap().printw(error.to_string().as_str());
        sub4.as_ref().unwrap().printw("\n");
        sub4.as_ref().unwrap().printw("Press any key to quit");
        sub4.as_ref().unwrap().refresh();
    } else {
        println ! ("ERROR: {}", error);
        println !("Press any key + \"Enter\" to quit")
    }
}


fn enable_commands(sniffer: &mut Sniffer, main_window: Option<Window>, state_window: Option<Window>, tui: bool, tui_mutex: Arc<Mutex<()>>) {
    if tui {
        tui_event_handler(sniffer, main_window, state_window, tui_mutex); // blocking function until stop
    } else {
        notui_event_handler(sniffer); // blocking function until stop
        println!("Closing event handler loop");
    }
}

fn tui_event_handler(sniffer: &mut Sniffer, main_window: Option<Window>, state_window: Option<Window>, tui_mutex: Arc<Mutex<()>>) {
    //commands definition
    let commands = vec![
        "PAUSE",
        "RESUME",
        "QUIT",
    ];


    //drawing subwindow 1
    let sub1 = main_window.as_ref().unwrap().subwin(6, 11, 0, 1).unwrap();
    sub1.draw_box(0, 0);
    sub1.mvprintw(1, 2, "Command");
    sub1.keypad(true);
    sub1.refresh();

    //Event loop
    let mut menu = 0u8;
    let mut running = 0u8;

    loop {
        if sniffer.get_state().is_stopped() {
            break;
        }

        let mg = tui_mutex.lock().unwrap();

        for (mut index, command) in commands.iter().enumerate() {
            if menu == index as u8 {
                sub1.attron(A_REVERSE);
            } else {
                sub1.attroff(A_REVERSE);
            }
            let y = {
                index += 2;
                index as i32
            };

            sub1.mvprintw(y, 2, command);
        }

        sub1.refresh();
        drop(mg);

        match sub1.getch() { //getch waits for user key input -> returns Input value assoc. to the key
            Some(Input::KeyUp) => {
                if menu != 0 {
                    menu -= 1;
                }
                continue;
            }

            Some(Input::KeyDown) => {
                if menu != 2 {
                    menu += 1;
                }
                continue;
            }

            Some(Input::Character('\n')) => {
                running = menu
            }

            Some(_) => continue,

            None => (),
        }

        match running {
            0 => {
                sniffer.pause();
                print_state(state_window.as_ref(), &PAUSED, tui_mutex.clone());
            }
            1 => {
                sniffer.resume();
                print_state(state_window.as_ref(), &RESUMED, tui_mutex.clone());
            }
            _ => {
                sniffer.stop();
                print_state(state_window.as_ref(), &STOPPED, tui_mutex.clone());
            }
        }
    }
}

fn notui_event_handler(sniffer: &mut Sniffer) {
    //event loop
    loop {
        if sniffer.get_state().is_stopped() {
            break;
        }

        let mut cmd = String::new();
        stdin().read_line(&mut cmd).unwrap();

        if sniffer.get_state().is_stopped() {
            break;
        }

        match cmd.chars().nth(0).unwrap().to_ascii_lowercase() {
            'p' => sniffer.pause(),
            'r' => sniffer.resume(),
            'q' => {
                sniffer.stop();
                break;
            }
            _ => {
                println!("Undefined command!");
                continue;
            }
        }
    }
}

fn print_closing(window: &Window, tui_mutex: Arc<Mutex<()>>) {
    let _mg = tui_mutex.lock().unwrap();
    window.clear();

    if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        window.attron(A_BOLD);
    }

    window.attron(COLOR_PAIR(2));
    window.mvprintw(5, 25, "    ______ _____ _____");
    window.mvprintw(6, 25, "   / ____/ ____/ ____/");
    window.mvprintw(7, 25, "  / /_  / /   / /");
    window.mvprintw(8, 25, " / __/ / /___/ /___");
    window.mvprintw(9, 25, "/_/    \\____/\\____/");
    window.attroff(COLOR_PAIR(2));
    window.attron(COLOR_PAIR(3));
    window.mvprintw(9, 55, "__");
    window.mvprintw(10, 15, "   ____  ___  / /__      ______  _____/ /__");
    window.mvprintw(11, 15, "  / __ \\/ _ \\/ __/ | /| / / __ \\/ ___/ //_/");
    window.mvprintw(12, 15, " / / / /  __/ /_ | |/ |/ / /_/ / /  / , |");
    window.mvprintw(13, 15, "/_/ /_/\\___/\\__/ |__/|__/\\____/_/  /_/|_|");
    window.attroff(COLOR_PAIR(3));
    window.attron(COLOR_PAIR(5));
    window.mvprintw(14, 15, "   ____ _____  ____ _/ /_  ______ ___  _____");
    window.mvprintw(15, 15, "  / __ `/ __ \\/ __ `/ / / / /_  // _ \\/ ___/");
    window.mvprintw(16, 15, " / /_/ / / / / /_/ / / /_/ / / //  __/ /    ");
    window.mvprintw(17, 15, " \\__,_/_/ /_/\\__,_/_/\\__, / /___|___/_/");
    window.mvprintw(18, 15, "                    /____/");

    if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        window.attroff(A_BOLD);
    }

    window.attroff(COLOR_PAIR(5));
    window.refresh();
}

fn main() {
    let args = Args::parse();

    if args.list_adapters {
        let adapter_list = Device::list().unwrap();
        println!("------------------------ ADAPTER LIST ------------------------");
        for (index, device) in adapter_list.into_iter().enumerate() {
            let format = (index + 1).to_string().as_str().to_owned() + ") Adapter name: " + device.name.as_str();
            println!("{}", format);
        }
        println!("--------------------------------------------------------------")
    } else {
        let tui_enabled: bool = args.tui;

        //Application state
        let mut s = Sniffer::new(args.adapter, args.output.clone(), args.update_time, args.filter.clone()).unwrap();

        //Main-window initialization | Showing commands :
        let mut main_window = None;
        let mut state_window: Option<Window> = None;

        if tui_enabled {
            let device_name = get_adapter(args.adapter).unwrap().name;
            let filter = get_filter(&args.filter.to_ascii_lowercase()).unwrap();
            main_window = Some(tui_init(&device_name, &filter, &args.output, args.update_time));
            let s_w = state_win_init();
            state_window = Some(s_w);
        } else {
            notui_show_commands();
        }

        let receiver = s.subscribe();

        let tui_mutex = Arc::new(Mutex::new(()));
        let tui_mutex_cl = tui_mutex.clone();

        // observe the sniffer, print packets and state
        let observer_thread = thread::spawn(move || {
            let mut sub4: Option<Window> = None;

            if tui_enabled {
                let s4 = newwin(31, 76, 10, 2);
                s4.scrollok(true);
                s4.setscrreg(0, 30);
                sub4 = Some(s4);
            }

            loop {
                match receiver.recv() {
                    Ok(Message::Error(err)) => {
                        print_error(sub4.as_ref(), err, tui_enabled, tui_mutex_cl.clone());
                        break;
                    }
                    Ok(Message::State(state)) => {
                        if state.is_stopped() {
                            print_closing(sub4.as_ref().unwrap(), tui_mutex_cl.clone());
                            break;
                        }
                    }
                    Ok(Message::Packet(packet)) => print_packet(packet, sub4.as_ref(), tui_mutex_cl.clone()),
                    Err(_) => break
                }
            }
            if !tui_enabled {
                println!("Observer thread exiting");
            }
        });

        // Event Handler
        // Main thread in loop qui dentro
        enable_commands(&mut s, main_window, state_window, tui_enabled, tui_mutex);

        observer_thread.join().unwrap();
    }
}
