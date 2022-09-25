# DOCs

## Application

## Library

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
