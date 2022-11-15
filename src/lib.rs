pub mod sniffer {
    pub mod na_packet;
    pub mod na_state;
    pub mod na_error;
    pub mod filter;
    mod stats;
    mod format;
    pub mod channel;

    use pcap::{Capture, Device};
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::mpsc::Receiver;
    use std::thread::{JoinHandle, sleep, spawn};
    use std::time::Duration;
    use pcap::Error::TimeoutExpired;
    use crate::sniffer::channel::{Message, SnifferChannel};
    use crate::sniffer::filter::get_filter;
    use crate::sniffer::format::get_file_name;
    use crate::sniffer::na_error::NAError;
    use crate::sniffer::na_packet::NAPacket;
    use crate::sniffer::na_state::NAState;
    use crate::sniffer::na_state::NAState::{PAUSED, RESUMED, STOPPED};
    use crate::sniffer::stats::{produce_report, Stats};

    ///Returns the nth `Device` of the device list, or an error if it doesn't exist
    ///
    ///This function takes an u8 representing the index associated to a device within
    ///the network device list and returns a Result, containing either a proper pcap
    /// `Device` object, or a `NAError`.
    ///
    ///  Can raise errors:
    /// - ⚠ **Device not found**: when the adapter defined does not match with any device number.

    pub fn get_adapter(adapter: u8) -> Result<Device, NAError> {
        let device_list = Device::list().unwrap();
        let mut couple = Vec::<(u8, Device)>::new();
        for (index, device) in device_list.into_iter().enumerate() {
            couple.push((index as u8 + 1, device));
        }
        let device = match couple.into_iter().find(|c| c.0 == adapter) {
            Some((_, dev)) => dev,
            None => return Err(NAError::new("Device not found")),
        };

        Ok(device)
    }

    ///The struct `Sniffer` initializes the sniffing and reporting process, by
    ///* Finding the `pcap::Device` associated to the given `adapter`
    ///* Properly setting up (in promisc mode) and activating a `pcap::Capture` on the given `adapter`.
    ///* Associating (if possible) the given `filter` string to a `network_analyzer::Filter` tag
    ///* Creating a `network_analyzer::channel::SnifferChannel` to transfer informations from the
    ///internal threads to the subscribed one (where the Sniffer is created).
    ///
    ///
    ///Moreover, the struct `Sniffer` is responsible for the initialization of two threads:
    /// 1) <i>timer_thread</i>: while the sniffer isn't paused/stopped, every `update_time` milliseconds, updates the sniffing report contained in a `output` (.xml and .md) file
    /// 2) <i>sniffing_thread</i>: while the sniffer isn't paused/stopped, waits for the capturing of a packet, takes the captured `pcap::Packet`, transforms it in a readable `NAPacket`, filters it (following the given `filter`) and eventually transfers it to the subscribed thread(s) via `SnifferChannel`.
    ///
    /// The `Sniffer` also implements the `Drop` trait, so that the `drop(&mut self)` function waits for the proper termination
    /// of the two threads initialized by the struct.
    pub struct Sniffer {
        m: Arc<Mutex<(NAState, Vec<NAPacket>, Vec<Stats>, SnifferChannel)>>,
        jh: Option<(JoinHandle<()>, JoinHandle<()>)>,
        cv: Arc<Condvar>,
        report_file_name: (String, String),
    }

    impl Sniffer {

        ///Creates a new `Sniffer` object given four parameters (network adapter to sniff (u8), output filename (String),
        /// output file update time (u64), filter (String)) or returns an `NAError`.
        ///
        /// Can raise errors:
        /// - ⚠ **`Cap` Errors**: contains errors issued by `next_packet` method of `Cap` library

        pub fn new(adapter: u8, output: String, update_time: u64, filter: String) -> Result<Self, NAError> {
            let report_file_name = get_file_name(output.clone());
            let report_file_name_cl = report_file_name.clone();
            let report_file_name_cl_2 = report_file_name.clone();

            let device = get_adapter(adapter)?;
            let enum_filter = get_filter(&filter.trim().to_ascii_lowercase())?;

            let sniffer_channel = SnifferChannel::new();

            let stats_vec = Vec::<Stats>::new();
            let vec = Vec::<NAPacket>::new();

            let m = Arc::new(Mutex::new((RESUMED, vec, stats_vec, sniffer_channel)));
            let m_cl = m.clone();
            let m_cl_2 = m.clone();
            let cv = Arc::new(Condvar::new());
            let cv_cl = cv.clone();
            let cv_cl_2 = cv.clone();

            // report update thread (timer)
            let timer_thread = spawn(move || {
                loop {
                    sleep(Duration::from_millis(update_time));
                    let mg_res = m_cl_2.lock();
                    match mg_res {
                        Ok(mut mg) if mg.0.is_resumed() => {
                            mg.2 = produce_report(report_file_name_cl_2.0.clone(), report_file_name_cl_2.1.clone(), mg.1.clone(), mg.2.clone());
                            mg.1 = Vec::new();
                        }
                        Ok(mut mg) if mg.0.is_paused() => {
                            mg = cv_cl_2.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                            drop(mg);
                            continue;
                        }
                        _ => break
                    }
                }
                //println!("Timer thread exiting")
            });

            let sniffing_thread = spawn(move || {
                let mut cap = Capture::from_device(device.clone())
                    .unwrap()
                    .timeout(5000)
                    .promisc(true)
                    .open()
                    .unwrap();

                loop {
                    let mut mg = m_cl.lock().unwrap();
                    if mg.0.is_resumed() {
                        // rilascia il lock prima di next_packet() (bloccante)
                        drop(mg);
                        match cap.next_packet() {

                            Ok(packet) => {
                                mg = m_cl.lock().unwrap();
                                if mg.0.is_paused() {
                                    drop(cap);
                                    mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                                    cap = Capture::from_device(device.clone())
                                        .unwrap()
                                        .timeout(5000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    drop(mg);
                                    continue;

                                } else if mg.0.is_stopped() {
                                    break;
                                }

                                let p = NAPacket::new(packet.clone());

                                if p.filter(enum_filter.clone()) {
                                    mg.3.send(Message::Packet(p.clone()));
                                    mg.1.push(p);
                                }
                            }

                            Err(e) => {
                                if e == TimeoutExpired {
                                    cap = Capture::from_device(device.clone())
                                        .unwrap()
                                        .timeout(5000)
                                        .promisc(true)
                                        .open()
                                        .unwrap();
                                    continue;
                                }

                                // send the error to the ui
                                let mut mg = m_cl.lock().unwrap();
                                mg.3.send(Message::Error(NAError::new(&e.to_string())));
                                break;
                            }
                        }

                    } else if mg.0.is_paused() {
                        drop(cap);
                        mg = cv_cl.wait_while(mg, |mg| mg.0.is_paused()).unwrap();
                        cap = Capture::from_device(device.clone())
                            .unwrap()
                            .timeout(5000)
                            .promisc(true)
                            .open()
                            .unwrap();

                    } else {
                        break;
                    }

                    drop(mg);
                }

                let mut mg = m_cl.lock().unwrap();
                mg.0 = STOPPED;
                mg.2 = produce_report(report_file_name_cl.0.clone(), report_file_name_cl.1.clone(), mg.1.clone(), mg.2.clone());

                cv_cl.notify_all();

                //println!("Sniffing thread exiting");
            });

            Ok(Sniffer { m, jh: Some((sniffing_thread, timer_thread)), cv, report_file_name })
        }

        ///Pauses both sniffing and reporting threads within the `Sniffer` struct
        ///
        ///This function performs different tasks in order to correctly pause the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::PAUSED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Forces the writing of a report before the pause
        pub fn pause(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = PAUSED;
            mg.3.send(Message::State(PAUSED));
            mg.2 = produce_report(self.report_file_name.0.clone(), self.report_file_name.1.clone(), mg.1.clone(), mg.2.clone());
            mg.1 = Vec::new();
        }

        ///Resumes both sniffing and reporting threads within the `Sniffer` struct
        ///
        /// This function performs different tasks in order to correctly resume the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::RESUMED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Notifies both sniffing and reporting threads in wait on the `Sniffer`'s condition variable
        pub fn resume(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = RESUMED;
            mg.3.send(Message::State(RESUMED));
            self.cv.notify_all();
        }

        ///Forces the exiting of both sniffing and reporting threads within the `Sniffer` struct
        ///
        /// This function performs different tasks in order to terminate of the sniffing process:
        /// * Sets the sniffer's `NAState` field to `NAState::STOPPED`
        /// * Sends a 'state change message' onto the `SnifferChannel`
        /// * Notifies both sniffing and reporting threads (if paused, otherwise the notification is lost)
        pub fn stop(&mut self) {
            let mut mg = self.m.lock().unwrap();
            mg.0 = STOPPED;
            mg.3.send(Message::State(STOPPED));
            self.cv.notify_all();
        }

        /// Returns a `Receiver<Message>`.<br>
        /// It can be used to receive all the updates from the `Sniffer`.
        ///
        /// This method tries to acquire the inner Mutex, so it blocks until it is free.
        /// Then it calls the `subscribe()` function of the `SnifferChannel` and returns
        /// the new receiver.
        pub fn subscribe(&mut self) -> Receiver<Message> {
            let mut mg = self.m.lock().unwrap();
            mg.3.subscribe()
        }

        /// Returns the current state of the sniffer.
        ///
        /// This method tries to acquire the inner Mutex, so it blocks until it is free.
        /// Then the NAState is cloned and returned.
        pub fn get_state(&self) -> NAState {
            self.m.lock().unwrap().0.clone()
        }
    }

    impl Drop for Sniffer {
        fn drop(&mut self) {
            let (t1, t2) = std::mem::replace(&mut self.jh, None).unwrap();
            t1.join().unwrap();
            t2.join().unwrap();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[should_panic(expected = "Device not found")]
        fn test_not_existing_adapter() {
            let device_list = Device::list().unwrap();
            let mut couple = Vec::<(u8, Device)>::new();
            for (index, device) in device_list.into_iter().enumerate() {
                couple.push((index as u8 + 1, device));
            }
            let last_dev_index = couple.pop().unwrap().0;
            get_adapter(last_dev_index+1).unwrap();
        }
    }
}
