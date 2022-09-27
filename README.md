# DOCs

## Application

### Pictures of FCC Network Analyzer v1.0, in tui mode

<img src="./screenshots/screenshot_1.png" alt="screenshot" width="500"/>
<img src="./screenshots/screenshot_2.png" alt="screenshot" width="500"/>

### CLI Arguments:
* `--adapter (-a):` u8 number (default 1) associated to an adapter according to a list that can be shown passing `-l` or `--list-adapters` as argument
* `--output (-o)`: String (default "report") defining the name of the output file (.md / .xml where the report is written)
* `--update-time (-u)`: u64 number (default 10000) defining the output file update time (in milliseconds)
* `--filter (-f)`: String (default "None") defining a packet filter
* `--tui (-t)`: bool (default "false") enabling the `tui mode`
* `--list-adapters (-l)`: bool (default "false") showing the list of available network adapters to be sniffed, together with the associated index.

### Functions explanation

```rust
fn notui_show_commands()
```

Prints on the terminal the list of commands.

These commands can be used to control the sniffing process and are:
* P to Pause
* R to Resume
* Q to Quit

This function uses the println! macro and waits for 3 seconds before returning.<br>
In this way, the user can correctly visualize the list, independently of the following
operations.<br>
At the end, a "sniffing start" message is shown.

```rust
pub fn print_packet(p: NAPacket, tui_window: Option<&Window>, tui_mutex: Arc<Mutex<()>>)
```
Prints a received `NAPacket`:
 * on a given `pancurses::Window` according to a proper format if the application is run in `--tui` mode
 * to the stdout (by means of the `Display` trait implemented by the struct `NAPacket`) in the other cases
The passed parameters are:
1) `NAPacket` to print
2) Optional `pancurses::Window` if the application is run in `--tui` mode (None otherwise)
3) `Arc<Mutex<()>>` to synchronize the writing operations on the tui (in case of `--tui` mode)

```rust
fn print_state(state_window: Option<&Window>, state: &NAState, tui_mutex: Arc<Mutex<()>>)
```
Refreshes the state window with the current `Sniffer`'s state
Everytime a 'state change message' is sent from the Sniffer object, the tui's state window is refreshed

```rust
fn enable_commands(sniffer: &mut Sniffer, main_window: Option<Window>, state_window: Option<Window>, tui: bool, tui_mutex: Arc<Mutex<()>>)
```

Calls `tui_event_handler(...)` or `notui_event_handler(...)` depending on the tui boolean
argument received.

This function starts the main loop that listen to the tui or to the terminal stdin.<br>
It accept as parameters a `sniffer` reference and a `tui` boolean.<br>
The other parameters are "optional" and are used only in case of a tui based call.<br>
These are the `main_window` and the `state_window` which are of type `Option<Window>` and a
`tui_mutex`, used to synchronize the tui updates.

```rust
fn tui_event_handler(sniffer: &mut Sniffer, main_window: Option<Window>, state_window: Option<Window>, tui_mutex: Arc<Mutex<()>>)
```
1) Defines the commands to be shown in the tui's command window
2) Prints the command window and enables the arrow keys
3) Waits in loop (through a blocking getch) for user user commands (arrow key pressure / enter)
4) Calls the function associated to the selected command

```rust
fn print_closing(window: &Window, tui_mutex: Arc<Mutex<()>>)
```
Prints the application logo on a given `pancurses::Window`

### main

The first action performed by the main is the parsing of the main arguments (via `Parser` derived by `clap` library).

In `--list-adapters (-l)` mode, only the list of available network adapters (together with the associated index) is shown.

 Otherwise, the main:
1) checks if the `--tui (-t)` mode has been activated
2) creates a `network_adapter::sniffer::Sniffer` object, properly configured by passing the main arguments as parameters to the constructor
3) if the `tui mode` is enabled, properly initializes the tui layout and content on the terminal
4) subscribes to the `SnifferChannel` associated to the `Sniffer` object, in order to listen for packets, state change messages or errors (`network_analyzer::sniffer::Message`).

## Network Analyzer Library

### network_analyzer::sniffer

```rust
pub fn get_adapter(adapter: u8) -> Result<Device, NAError>
```

Returns the nth `Device` of the device list, or an error if it doesn't exist.

This function takes an u8 representing the index associated to a device within the network device list and returns a Result, containing either a proper pcap `Device` object, or a `NAError`

### network_analyzer::sniffer::Sniffer

The struct `Sniffer` initializes the sniffing and reporting process, by
* Finding the `pcap::Device` associated to the given `adapter`
* Properly setting up (in promisc mode) and activating a `pcap::Capture` on the given `adapter`.
* Associating (if possible) the given `filter` string to a `network_analyzer::Filter` tag
* Creating a `network_analyzer::channel::SnifferChannel` to transfer informations from the
internal threads to the subscribed one (where the Sniffer is created).
Moreover, the struct `Sniffer` is responsible for the initialization of two threads:
 1) <i>timer_thread</i>: while the sniffer isn't paused/stopped, every `update_time` milliseconds, updates the sniffing report contained in a `output` (.xml and .md) file
 2) <i>sniffing_thread</i>: while the sniffer isn't paused/stopped, waits for the capturing of a packet, takes the captured `pcap::Packet`, transforms it in a readable `NAPacket`, filters it (following the given `filter`) and eventually transfers it to the subscribed thread(s) via `SnifferChannel`.
 The `Sniffer` also implements the `Drop` trait, so that the `drop(&mut self)` function waits for the proper termination
 of the two threads initialized by the struct.
 
```rust
pub fn new(adapter: u8, output: String, update_time: u64, filter: String) -> Result<Self, NAError>
```
Creates a new `Sniffer` object given four parameters (network adapter to sniff (u8), output filename (String), output file update time (u64), filter (String)) or returns an `NAError`.

```rust
pub fn pause(&mut self)
```
Pauses both sniffing and reporting threads within the `Sniffer` struct
This function performs different tasks in order to correctly pause the sniffing process:
 * Sets the sniffer's `NAState` field to `NAState::PAUSED`
 * Sends a 'state change message' onto the `SnifferChannel`
 * Forces the writing of a report before the pause
 
 ```rust
pub fn resume(&mut self)
```
 Resumes both sniffing and reporting threads within the `Sniffer` struct
 This function performs different tasks in order to correctly resume the sniffing process:
 * Sets the sniffer's `NAState` field to `NAState::RESUMED`
 * Sends a 'state change message' onto the `SnifferChannel`
 * Notifies both sniffing and reporting threads in wait on the `Sniffer`'s condition variable
 
```rust
pub fn stop(&mut self)
```
Forces the exiting of both sniffing and reporting threads within the `Sniffer` struct
 This function performs different tasks in order to terminate of the sniffing process:
 * Sets the sniffer's `NAState` field to `NAState::STOPPED`
 * Sends a 'state change message' onto the `SnifferChannel`
 * Notifies both sniffing and reporting threads (if paused, otherwise the notification is lost)

```rust
pub fn subscribe(&mut self) -> Receiver<Message>
```

Returns a `Receiver<Message>`.<br>
It can be used to receive all the updates from the `Sniffer`.

This method tries to acquire the inner Mutex, so it blocks until it is free.
Then it calls the `subscribe()` function of the `SnifferChannel` and returns
the new receiver.

```rust
pub fn get_state(&self) -> NAState
```
Returns the current state of the sniffer.

This method tries to acquire the inner Mutex, so it blocks until it is free.
Then the NAState is cloned and returned.

 ### network_analyzer::sniffer::NAPacket
 
```rust
pub fn filter(&self, filter: Filter) -> bool
```

* Returns `true` if the given `NAPacket` passes the given filter
* Returns `false` if the given `NAPacket` doesn't pass the given filter
 This function receives a `Filter` tag and checks if the receiver (`NAPacket`)
 passes or not the filter.
<br></br>
<i>Example:</i>
- The filter is `Filter::IP(192.168.1.1)` => if a 192.168.1.1 ip address is found
 to be either the level 3 source or destination of the packet, `true` is returned.
- The filter is `Filter::ARP` => if the level three type of the packet is found to be
"ARP", `true` is returned.
- The filter is `Filter::None` => `true` is returned whatever packet is inspected

### network_analyzer::sniffer::na_packet::protocols

```rust
pub(crate) fn get_ipv6_transported_protocol(p: &[u8], (next_header_index, remaining_size): (usize, usize)) -> (String, usize)
```

Slides the IPv6 headers until it finds another protocol, so it returns a pair
composed by the transported protocol's name and the index of the first byte
of its header.

This function gets two arguments:
* The packet to be processed as an array of u8.
* A pair composed by the "next header index" which refers to the first byte
of the next header to be processed and by the "remaining size" which is the
remaining dimension (in bytes) of the header.

The function slides the IPv6 header until it finds the "Next Header" field,
if it indicates an IPv6 Extension Header, it calculates the remaining length
of the first header and then calls again the function (in a recursive call),
otherwise it calls `to_transported_protocol(prot_num)` and returns.

It panics if the index exceed the array length.

### network_analyzer::sniffer::Filter

Enumerates the different filtering categories offered by the network_analyzer library.
It also implements the `ToString` trait, allowing a correct transformation of `Filter`'s
tag (and possible detail) into a proper string representation.
<br></br>
<i> Example </i>
* `Filter::IP(192.168.1.1)` is converted into "IP 192.168.1.1"
* `Filter::Port(443)` is converted into "port 443"

```rust
pub fn get_filter(filter: &String) -> Result<Filter, NAError>
```

Associates a received string to a `Filter` (if possible), or returns an `NAError`.
This function associates a string to a filter, by analyzing the correctness of the passed parameter.
 <br></br>
<i>Example</i>:
* "ipv4" can be associated to a `Filter::IPv4` filter
* "192.168.1.1" can be associated to  `Filter::IP(String)`
* "2001:db8::2:1" can be associated to a `Filter::IP(String)`
* "foo.192 foo" cannot be associated to any filter

### network_analyzer::sniffer::stats::Stats

The `Stats` type.

It is used to store information about the (ISO/OSI) level four packet flow,
needed to produce the sniffer report.<br>
This type implements the `Debug` and `Clone` traits.

It contains:
* The pair of socket
* The level three protocol's name
* The transported protocol's name
* The flow's total number of bytes
* The timestamp of the first packet received
* The timestamp of the last packet received

```rust
pub(crate) fn new(packet: NAPacket) -> Self
```

Creates a new `Stats` from a `NAPacket`.

This method extracts the needed field from the packet and populate
the new object, by using the timestamp twice, both for the first
and last packet fields.

It is typically used by passing as argument the first packet of a flow.

```rust
pub(crate) fn produce_report(file_name_md: String, file_name_xml: String, packets: Vec<NAPacket>, stats: Vec<Stats>) -> Vec<Stats>
```

Produces two report files (<i>.xml</i> and <i>.md</i>) and returns the updated
vector of `Stats`.

The function takes as argument two file name (one for each format), a vector of
packets and a vector of (old) stats; these are used to produce an updated version
of the stats by calling the function `produce_stats(stats, packets)`.<br>
Then, it creates the files and writes them by using the `writeln!` macro.<br>
At the end, it returns the updated stats.

It panics if it is unable to write correctly the files and show the message
`"Unable to write the report file!"`.

```rust
fn produce_stats(mut stats: Vec<Stats>, packets: Vec<NAPacket>) -> Vec<Stats>
```

Produces an updated version of the stats and returns a vector of `Stats` objects.

This function takes as argument a vector of old stats and a vector of packets
to be processed and added.

It slides the packets, checks if its pair of socket is already recorded
in the stats, then it updates the relative `Stats` object by adding the
number of bytes and replacing the last packet timestamp.<br>
Otherwise, it creates a new object by calling the `new(packet)` static
function of `Stats`.

At the end, it returns the updated vector of stats.

### network_analyzer::sniffer::channel::SnifferChannel

The `SnifferChannel` type.

It is used to let the sniffer communicate with its subscribers by sending messages.<br>
It contains a vector of `Sender<Message>`, one for each subscriber.

```rust
pub(crate) fn new() -> Self
```

Creates a new `SnifferChannel` object and populate it with an empty array of senders.

```rust
pub(crate) fn subscribe(&mut self) -> Receiver<Message>
```

Creates a new communication channel and returns the receiver.

This method use the `std::sync::mpsc::channel()` function to create
a `Sender`, which will be added to the `SnifferChannel` and a `Receiver`,
which will be returned to the subscriber.

```rust
pub(crate) fn send(&mut self, message: Message)
```

Sends a `Message` to all the subscribers.

The method slides the senders vector and checks if each of them is still valid.<br>
It calls the `send(message)` method of the `Sender` that attempts to send the
message and returns an error if the `Receiver` has been already deallocated.<br>
In this case, the sender is removed from the vector.

### network_analyzer::sniffer::channel::Message

The `Message` type.

It is an enumeration that contains the message sent in the `SnifferChannel`,
that can be either a `NAError`, a `NAState` or a `NAPacket`.<br>
This type implements the `Clone` trait.
