use crate::{parser, Rule};
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::Packet;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

/// A unique identifier for a TCP stream (source IP, source port, dest IP, dest port).
pub type StreamId = (IpAddr, u16, IpAddr, u16);

/// Represents a single, unidirectional TCP stream being reassembled.
#[derive(Default)]
pub struct Stream {
    segments: BTreeMap<u32, Vec<u8>>,
    next_seq: u32,
    syn_seen: bool,
    /// A buffer for the contiguous, reassembled Layer 7 data.
    l7_buffer: Vec<u8>,
}

impl Stream {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_segment(&mut self, seq: u32, payload: &[u8]) {
        if !payload.is_empty() {
            self.segments.insert(seq, payload.to_vec());
        }
    }

    /// Tries to reassemble contiguous data, appending it to the L7 buffer.
    pub fn reassemble(&mut self) {
        while let Some(payload) = self.segments.remove(&self.next_seq) {
            self.l7_buffer.extend_from_slice(&payload);
            let payload_len = payload.len() as u32;
            self.next_seq = self.next_seq.wrapping_add(payload_len);
        }
    }
}

/// Manages the reassembly of multiple TCP streams and triggers L7 analysis.
pub struct TcpReassembler {
    streams: HashMap<StreamId, Stream>,
    rules: Arc<Vec<Rule>>,
}

impl TcpReassembler {
    pub fn new(rules: Arc<Vec<Rule>>) -> Self {
        TcpReassembler {
            streams: HashMap::new(),
            rules,
        }
    }

    /// Processes a single TCP packet, reassembles the stream, and returns any alerts.
    pub fn process_tcp_packet(
        &mut self,
        source_ip: IpAddr,
        dest_ip: IpAddr,
        tcp_packet: &TcpPacket,
    ) -> Vec<String> {
        let stream_id = (source_ip, tcp_packet.get_source(), dest_ip, tcp_packet.get_destination());
        let payload = tcp_packet.payload();
        let seq = tcp_packet.get_sequence();
        let flags = tcp_packet.get_flags();

        let stream = self.streams.entry(stream_id).or_insert_with(Stream::new);

        if (flags & TcpFlags::SYN) != 0 && !stream.syn_seen {
            stream.syn_seen = true;
            stream.next_seq = seq.wrapping_add(1);
        }

        if !stream.syn_seen {
            return vec![];
        }

        if !payload.is_empty() {
            stream.add_segment(seq, payload);
        }

        // Reassemble the stream and then try to parse the new buffer.
        stream.reassemble();
        let alerts = Self::dispatch_l7_parser(&self.rules, stream_id, &stream.l7_buffer);

        if (flags & TcpFlags::FIN) != 0 || (flags & TcpFlags::RST) != 0 {
            if self.streams.remove(&stream_id).is_some() {
                log::info!("Stream closed and removed: {:?}", stream_id);
            }
        }
        alerts
    }

    /// Dispatches the reassembled data and returns a list of alert messages.
    fn dispatch_l7_parser(rules: &Arc<Vec<Rule>>, stream_id: StreamId, data: &[u8]) -> Vec<String> {
        let (_src_ip, _src_port, _dest_ip, dest_port) = stream_id;
        let mut alerts = Vec::new();

        if data.is_empty() {
            return alerts;
        }

        match dest_port {
            80 => { // HTTP
                if let Some(http_info) = parser::handle_http_stream(data) {
                    let packet_info = crate::parser::PacketInfo {
                        source_ip: stream_id.0,
                        dest_ip: stream_id.2,
                        source_port: Some(stream_id.1),
                        dest_port: Some(stream_id.3),
                        protocol: "tcp".to_string(),
                        dns_data: None,
                        http_data: Some(http_info),
                    };

                    for rule in &**rules {
                        if rule.matches(&packet_info) {
                            alerts.push(rule.msg.clone());
                        }
                    }
                }
            }
            _ => {}
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rule;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn create_test_packet(
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 20 + payload.len()];
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer).unwrap();
        tcp_packet.set_sequence(seq);
        tcp_packet.set_flags(flags);
        tcp_packet.set_payload(payload);
        tcp_packet.set_source(12345);
        tcp_packet.set_destination(80);
        tcp_packet.set_data_offset(5);
        buffer
    }

    #[test]
    fn test_in_order_reassembly_and_alert() {
        // Arrange
        let rule = Rule {
            action: "alert".to_string(),
            msg: "Test HTTP detected".to_string(),
            protocol: "tcp".to_string(),
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: Some(80),
            dns_query: None,
            http_host: Some("example.com".to_string()),
            http_uri: None,
            http_method: None,
        };
        let rules = Arc::new(vec![rule]);
        let mut reassembler = TcpReassembler::new(rules);
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        let syn_packet_data = create_test_packet(100, TcpFlags::SYN, &[]);
        let syn_packet = TcpPacket::new(&syn_packet_data).unwrap();

        let payload1 = "GET / HTTP/1.1\r\nHost: ";
        let packet1_data = create_test_packet(101, TcpFlags::PSH | TcpFlags::ACK, payload1.as_bytes());
        let packet1 = TcpPacket::new(&packet1_data).unwrap();

        let payload2 = "example.com\r\n\r\n";
        let packet2_data = create_test_packet(101 + payload1.len() as u32, TcpFlags::PSH | TcpFlags::ACK, payload2.as_bytes());
        let packet2 = TcpPacket::new(&packet2_data).unwrap();

        // Act
        reassembler.process_tcp_packet(ip_a, ip_b, &syn_packet);
        let alerts1 = reassembler.process_tcp_packet(ip_a, ip_b, &packet1);
        let alerts2 = reassembler.process_tcp_packet(ip_a, ip_b, &packet2);

        // Assert
        assert!(alerts1.is_empty(), "Parser should not succeed on partial data");
        assert_eq!(alerts2.len(), 1, "Alert should be generated on complete data");
        assert_eq!(alerts2[0], "Test HTTP detected");
    }

    #[test]
    fn test_out_of_order_reassembly() {
        // Arrange
        let rules = Arc::new(vec![]);
        let mut reassembler = TcpReassembler::new(rules);
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        let syn_packet_data = create_test_packet(100, TcpFlags::SYN, &[]);
        let syn_packet = TcpPacket::new(&syn_packet_data).unwrap();

        let payload1 = "first part ";
        let packet1_data = create_test_packet(101, TcpFlags::PSH | TcpFlags::ACK, payload1.as_bytes());
        let packet1 = TcpPacket::new(&packet1_data).unwrap();

        let payload2 = "second part";
        let packet2_data = create_test_packet(101 + payload1.len() as u32, TcpFlags::PSH | TcpFlags::ACK, payload2.as_bytes());
        let packet2 = TcpPacket::new(&packet2_data).unwrap();

        // Act
        reassembler.process_tcp_packet(ip_a, ip_b, &syn_packet);
        let alerts1 = reassembler.process_tcp_packet(ip_a, ip_b, &packet2);
        let alerts2 = reassembler.process_tcp_packet(ip_a, ip_b, &packet1);

        // Assert
        assert!(alerts1.is_empty());
        assert!(alerts2.is_empty()); // No rules, so no alerts

        // Check internal state
        let stream_id = (ip_a, 12345, ip_b, 80);
        let stream = reassembler.streams.get(&stream_id).unwrap();
        let expected_data = "first part second part";
        assert_eq!(stream.l7_buffer, expected_data.as_bytes());
    }
}
