use std::sync::mpsc::{channel, Receiver, Sender};
use crate::sniffer::na_error::NAError;
use crate::sniffer::na_packet::NAPacket;
use crate::sniffer::na_state::NAState;

/// The `SnifferChannel` type.
///
/// It is used to let the sniffer communicate with its subscribers by sending messages.<br>
/// It contains a vector of `Sender<Message>`, one for each subscriber.
pub(crate) struct SnifferChannel {
    senders: Vec<Sender<Message>>,
}

impl SnifferChannel {
    /// Creates a new `SnifferChannel` object and populate it with an empty array
    /// of senders.
    pub(crate) fn new() -> Self {
        SnifferChannel { senders: Vec::new() }
    }

    /// Creates a new communication channel and returns the receiver.
    ///
    /// This method use the `std::sync::mpsc::channel()` function to create
    /// a `Sender`, which will be added to the `SnifferChannel` and a `Receiver`,
    /// which will be returned to the subscriber.
    pub(crate) fn subscribe(&mut self) -> Receiver<Message> {
        let (sx, rx) = channel::<Message>();
        self.senders.push(sx);
        rx
    }

    /// Sends a `Message` to all the subscribers.
    ///
    /// The method slides the senders vector and checks if each of them is still valid.<br>
    /// It calls the `send(message)` method of the `Sender` that attempts to send the
    /// message and returns an error if the `Receiver` has been already deallocated.<br>
    /// In this case, the sender is removed from the vector.
    pub(crate) fn send(&mut self, message: Message) {
        let mut i = 0;
        loop {
            if i < self.senders.len() {
                match self.senders[i].send(message.clone()) {
                    Err(_) => drop(self.senders.remove(i)),
                    _ => i += 1
                }
            } else {
                break;
            }
        }
    }
}

/// The `Message` type.
///
/// It is an enumeration that contains the message sent in the `SnifferChannel`,
/// that can be either a `NAError`, a `NAState` or a `NAPacket`.<br>
/// This type implements the `Clone` trait.
#[derive(Clone)]
pub enum Message {
    Error(NAError),
    State(NAState),
    Packet(NAPacket),
}

#[cfg(test)]
mod test {
    use super::*;

    fn create_sample_na_packet() -> NAPacket {
        NAPacket {
            destination_mac_address: "".to_string(),
            source_mac_address: "".to_string(),
            //level 3 header
            level_three_type: "".to_string(),
            total_length: 0,
            source_address: None,
            destination_address: None,

            //level 4 header
            transported_protocol: None,
            source_port: None,
            destination_port: None,

            timestamp: 0,
        }
    }

    #[test]
    fn test_send_a_state_to_channel() {
        let mut channel = SnifferChannel::new();
        let sub = channel.subscribe();
        let message = Message::State(NAState::RESUMED);
        channel.send(message);
        assert!(sub.recv().is_ok());
    }

    #[test]
    fn test_send_an_error_to_channel() {
        let mut channel = SnifferChannel::new();
        let sub = channel.subscribe();
        let message = Message::Error(NAError::new("Error"));
        channel.send(message);
        assert!(sub.recv().is_ok());
    }

    #[test]
    fn test_send_a_packet_to_channel() {
        let mut channel = SnifferChannel::new();
        let sub = channel.subscribe();
        let na_packet = create_sample_na_packet();
        let message = Message::Packet(na_packet);
        channel.send(message);
        assert!(sub.recv().is_ok());
    }

    #[test]
    fn test_channel_dropped_before_sub() {
        let mut channel = SnifferChannel::new();
        let sub = channel.subscribe();
        let na_packet = create_sample_na_packet();
        let message = Message::Packet(na_packet);
        channel.send(message);
        drop(channel);
        assert!(sub.recv().is_ok());
        assert!(sub.recv().is_err());
    }
}
