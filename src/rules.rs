use crate::parser::{DnsInfo, PacketInfo};
use serde::Deserialize;
use std::net::IpAddr;

/// Represents a single rule loaded from the `rules.yaml` file.
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub action: String,
    pub msg: String,
    // If `protocol` is not in the YAML, it will default to "any".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    // The key in the YAML file must match the struct field name.
    // Let's use `dest_ip` and `dest_port` to match your YAML.
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub dns_query: Option<String>,
}

// Helper function for serde to provide a default value for `protocol`.
fn default_protocol() -> String {
    "any".to_string()
}

impl Rule {
    /// Checks if a given parsed packet matches the criteria of this rule.
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // 1. Check protocol. If rule proto is not "any" and doesn't match, fail.
        if self.protocol != "any" && self.protocol != packet.protocol {
            return false;
        }

        // 2. Check source IP. If the rule specifies a source IP, and it doesn't match, fail.
        if let Some(rule_ip) = self.source_ip {
            if rule_ip != packet.source_ip {
                return false;
            }
        }

        // 3. Check destination IP.
        if let Some(rule_ip) = self.dest_ip {
            if rule_ip != packet.dest_ip {
                return false;
            }
        }

        // 4. Check source port.
        if let Some(rule_port) = self.source_port {
            if packet.source_port != Some(rule_port) {
                return false;
            }
        }

        // 5. Check destination port.
        if let Some(rule_port) = self.dest_port {
            if packet.dest_port != Some(rule_port) {
                return false;
            }
        }

        // 6. Check for DNS Query
        if let Some(rule_query) = &self.dns_query {
            // Check if the packet contain DNS data
            if let Some(dns_info) = &packet.dns_data{
                // If the rule's query string is NOT a suffix of the packet's query, it's not a match.
                // We use `ends_with` to match "google.com" against a query for "www.google.com".
                if !dns_info.query_name.ends_with(rule_query) {
                    return false;
                }
            }else {
                // The rule queries a DNS query, but this packet isn't DNS. No Match
                return false;
            }
        }

        // If all checks passed, it's a match!
        true
    }
}


// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*; // Import Rule and PacketInfo.

    // Helper function to quickly create a mock PacketInfo for our tests.
    fn mock_packet(
        source_ip: &str,
        dest_ip: &str,
        source_port: u16,
        dest_port: u16,
        protocol: &str,
    ) -> PacketInfo {
        PacketInfo {
            source_ip: source_ip.parse().unwrap(),
            dest_ip: dest_ip.parse().unwrap(),
            source_port: Some(source_port),
            dest_port: Some(dest_port),
            protocol: protocol.to_string(),
            dns_data: None
        }
    }

    #[test]
    fn test_ssh_rule_match() {
        // ARRANGE
        let packet = mock_packet("192.168.1.10", "10.0.0.5", 12345, 22, "tcp");
        let rule = Rule {
            action: "alert".to_string(),
            msg: "SSH traffic detected".to_string(),
            protocol: "tcp".to_string(),
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: Some(22),
            dns_query: None,
        };
        // ACT
        let result = rule.matches(&packet);
        // ASSERT
        assert!(result, "Rule should match SSH packet");
    }

    #[test]
    fn test_ssh_rule_no_match_on_wrong_port() {
        // ARRANGE
        let packet = mock_packet("192.168.1.10", "10.0.0.5", 12345, 80, "tcp");
        let rule = Rule {
            action: "alert".to_string(),
            msg: "SSH traffic detected".to_string(),
            protocol: "tcp".to_string(),
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: Some(22),
            dns_query: None,
        };
        // ACT
        let result = rule.matches(&packet);
        // ASSERT
        assert!(!result, "Rule should not match non-SSH packet");
    }

    #[test]
    fn test_source_ip_rule_match() {
        // ARRANGE
        let packet = mock_packet("192.168.1.50", "8.8.8.8", 10000, 53, "udp");
        let rule = Rule {
            action: "alert".to_string(),
            msg: "Traffic from specific server".to_string(),
            protocol: "any".to_string(),
            source_ip: Some("192.168.1.50".parse().unwrap()),
            source_port: None,
            dest_ip: None,
            dest_port: None,
            dns_query: None,
        };
        // ACT
        let result = rule.matches(&packet);
        // ASSERT
        assert!(result, "Rule should match packet from specified source IP");
    }

    #[test]
    fn test_protocol_mismatch() {
        // ARRANGE
        let packet = mock_packet("192.168.1.10", "10.0.0.5", 12345, 53, "tcp");
        let rule = Rule {
            action: "alert".to_string(),
            msg: "Potential DNS exfiltration attempt".to_string(),
            protocol: "udp".to_string(),
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: Some(53),
            dns_query: None,
        };
        // ACT
        let result = rule.matches(&packet);
        // ASSERT
        assert!(!result, "Rule for UDP should not match a TCP packet");
    }
}
