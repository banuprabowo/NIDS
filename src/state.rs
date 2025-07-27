use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};



// Represents the activity from a single source IP to a single destination IP.
struct HostActivity{
    // A set to store the unique destination ports contacted
    ports_contacted:HashSet<u16>,
    last_activity: Instant,
    total_byte_transferred:usize,
}

impl HostActivity {
    fn new() -> Self {
        HostActivity {
            ports_contacted: HashSet::new(),
            last_activity: Instant::now(),
            total_byte_transferred: 0,
        }
    }
}

// The main connection tracker. This is "memory" for the NIDS
pub struct ConnectionTracker {
    // The Data structure:
    // A map from source IPto (another map from destination IP to its activity).
    // HashMap<SourceIp, HashMap<DestinationIp, Activity>>
    activity_map: HashMap<IpAddr, HashMap<IpAddr, HostActivity>>,
    time_window: Duration,
    port_scan_threshold: usize,
    data_exfil_threshold_bytes: usize,
    standard_ports: HashSet<u16>,
}

impl ConnectionTracker {
    pub fn new(port_scan_threshold: usize, port_scan_window_secs: u64, data_exfil_threshold_bytes: usize, standard_ports: Vec<u16>) -> Self {
        ConnectionTracker {
            activity_map: HashMap::new(),
            time_window:Duration::from_secs(port_scan_window_secs),
            port_scan_threshold,
            data_exfil_threshold_bytes,
            standard_ports: standard_ports.into_iter().collect()
        }
    }

    // This is the main function for the tracker. It logs a packet's details
    // and returns an Option with an alert message if a port scan is detected.
    pub fn check_for_port_scan(&mut self, src_ip: IpAddr, dst_ip: IpAddr, dest_port: u16) -> Option<String> {
        // Get the activity for the source IP, or create a new entry if it's the first time we see it.
        let src_activity = self.activity_map.entry(src_ip).or_insert(HashMap::new());

        // Get activity for the destination IP from that source, or create a new one
        let host_activity = src_activity.entry(dst_ip).or_insert(HostActivity::new());

        // If let last activity was too long ago, reset the port list for this host.
        if host_activity.last_activity.elapsed() > self.time_window {
            host_activity.ports_contacted.clear();
        }

        // Add the new port to the set of contacted ports.
        host_activity.ports_contacted.insert(dest_port);
        // Update the timestamp of the last activity
        host_activity.last_activity = Instant::now();

        // Check if the number of unique ports contacted exceeded the threshold
        if host_activity.ports_contacted.len() > self.port_scan_threshold {
            // It's a port scan!
            // We clear the set to avoid sending continuous alerts for the same scan.
            host_activity.ports_contacted.clear();

            // Return alert message
            return Some(format!("Potential port scanning from {} to {} ({} ports in {}s",
                                src_ip,
                                dst_ip,
                                self.port_scan_threshold +1,
                                self.time_window.as_secs()
            ));
        }

        // No scan detected
        None
    }

    pub fn check_for_data_exfil(&mut self, src_ip: IpAddr, dest_ip: IpAddr, dest_port:u16, payload_size:usize) -> Option<String> {
        // Don't check traffic on standard ports (like HTTP/HTTPS)
        if self.standard_ports.contains(&dest_port) {
            return None;
        }

        let src_activity = self.activity_map.entry(src_ip).or_insert_with(HashMap::new);
        let host_activity = src_activity.entry(dest_ip).or_insert_with(HostActivity::new);

        host_activity.total_byte_transferred += payload_size;

        if host_activity.total_byte_transferred > self.data_exfil_threshold_bytes {
            // To prevent continuos alerts, reset the counter once an alert is fired
            let total_bytes = host_activity.total_byte_transferred;
            host_activity.total_byte_transferred = 0;

            return Some(format!("Potential data exfiltration detected from {} to {}:{} ({} bytes transferred on a non-standard port)",
                                src_ip, dest_ip, dest_port, total_bytes));
        }

        None
    }
}
