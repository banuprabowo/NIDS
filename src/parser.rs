use pnet_packet::ethernet::{EthernetPacket, EtherTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::net::IpAddr;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::RecordType;

/// Struct to hold parsed dns information
#[derive(Debug, PartialEq, Clone)]
pub struct DnsInfo {
    pub query_name:String,
    pub query_type:RecordType,
}

/// A struct to hold the relevant information extracted from a packet.
/// This is the output of our parsing process.
#[derive(Debug, PartialEq, Clone)] // PartialEq allows us to compare two PacketInfo structs in tests.
pub struct PacketInfo {
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: String,
    pub dns_data: Option<DnsInfo>,
}



/// Parses the raw bytes of an Ethernet frame and, if it's a supported protocol (TCP/UDP over IPv4),
/// returns a structured `PacketInfo`. Otherwise, returns `None`.
pub fn handle_packet(ethernet_packet: &EthernetPacket) -> Option<PacketInfo> {
    // We only care about IPv4 packets for now.
    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
        // Try to parse the IPv4 packet from the Ethernet frame's payload.
        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            let source_ip = IpAddr::V4(ipv4_packet.get_source());
            let dest_ip = IpAddr::V4(ipv4_packet.get_destination());

            // Check the protocol within the IPv4 packet (TCP or UDP).
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv4_packet.payload()) {

                        return Some(PacketInfo {
                            source_ip,
                            dest_ip,
                            source_port: Some(tcp.get_source()),
                            dest_port: Some(tcp.get_destination()),
                            protocol: "tcp".to_string(),
                            dns_data: None,
                        });
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4_packet.payload()) {
                        let dns_data = if udp.get_destination() == 53 {
                            handle_dns_packet(udp.payload())
                        }else {
                            None
                        };
                        return Some(PacketInfo {
                            source_ip,
                            dest_ip,
                            source_port: Some(udp.get_source()),
                            dest_port: Some(udp.get_destination()),
                            protocol: "udp".to_string(),
                            dns_data
                        });
                    }
                }
                _ => {
                    // It's another protocol over IPv4 (like ICMP), which we don't have rules for.
                    return None;
                }
            }
        }
    }
    // Not an IPv4 packet or a malformed packet.
    None
}

// New function to parse the dns payload
fn handle_dns_packet(payload: &[u8]) -> Option<DnsInfo> {
    // Using Message::from_vec to parse the raw byte.
    if let Ok(dns_message) = Message::from_vec(payload) {
        // Only care about standard query from clients
        if dns_message.message_type() == MessageType::Query && dns_message.op_code() == OpCode::Query {
            // A DNS message can have multiple queries but usually have one
            if let Some(query) = dns_message.queries().get(0){
                return Some(DnsInfo {
                    // Convert the query name to a string, triming the trailing dot
                    query_name: query.name().to_string().trim_end_matches('.').to_string(),
                    query_type: query.query_type(),
                });
            }
        }
    }

    None
}


