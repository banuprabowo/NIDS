use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_channel::unbounded;
use log::{error, info, warn};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;

use nids_v1::{
    handle_packet, list_devices, start_capture, ConnectionTracker, Rule, Settings, TcpReassembler,
};

fn main() -> Result<(), Box<dyn Error>> {
    let settings = Settings::new()?;

    env_logger::Builder::new()
        .parse_filters(&settings.log_level)
        .init();

    // Load rules
    info!("Loading rules from '{}'", &settings.rules_file_path);
    let rules = load_rules(&settings.rules_file_path)?;

    // Get device using function in library
    info!("Finding network devices...");
    let devices = list_devices()?;

    if devices.is_empty() {
        error!("No network devices found. Try running with sudo or as an administrator");
        return Err("No network devices found.".into());
    }

    // User selection logic
    info!("Available network devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("[{}] {}", i, device.name);
    }

    let selected_device = loop {
        print!("Enter the number of the device to capture on: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<usize>() {
            Ok(index) => {
                if let Some(device) = devices.get(index) {
                    break device;
                } else {
                    eprintln!("Invalid device number. Please try again.");
                }
            }
            Err(_) => {
                eprintln!("Please enter a valid number.");
            }
        }
    };

    // CONCURRENCY SETUP
    let (tx, rx) = unbounded::<Vec<u8>>();
    let shared_rules = Arc::new(rules);
    let connection_tracker = Arc::new(Mutex::new(ConnectionTracker::new(
        settings.port_scan_threshold,
        settings.port_scan_window_secs,
        settings.data_exfil_threshold_byte,
        settings.standard_ports,
    )));
    // Create and share the TCP Reassembler
    let reassembler = Arc::new(Mutex::new(TcpReassembler::new(Arc::clone(&shared_rules))));

    // 3. Spawn worker threads.
    let num_workers = 4; // Can be adjusted based on CPU core
    let mut worker_handles = Vec::new();

    for i in 0..num_workers {
        let rx_clone = rx.clone();
        let rules_clone = Arc::clone(&shared_rules);
        let tracker_clone = Arc::clone(&connection_tracker);
        let reassembler_clone = Arc::clone(&reassembler); // Clone for each worker

        let handle = thread::spawn(move || {
            info!("Worker {} started.", i + 1);
            while let Ok(packet_data) = rx_clone.recv() {
                if let Some(ethernet_packet) =
                    pnet_packet::ethernet::EthernetPacket::new(&packet_data)
                {
                    if let Some(ipv4_packet) =
                        pnet_packet::ipv4::Ipv4Packet::new(ethernet_packet.payload())
                    {
                        // --- TCP STREAM REASSEMBLY ---
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                let mut reassembler = reassembler_clone.lock().unwrap();
                                reassembler.process_tcp_packet(
                                    ipv4_packet.get_source().into(),
                                    ipv4_packet.get_destination().into(),
                                    &tcp_packet,
                                );
                            }
                        }

                        // --- BEGIN LEGACY PER-PACKET ANALYSIS ---
                        // Note: This section will be refactored in the next steps to use
                        // the output of the reassembler instead of individual packets.
                        let payload_size = ethernet_packet.payload().len();
                        if let Some(packet_info) = handle_packet(&ethernet_packet) {
                            // --- STATELESS RULE CHECK ---
                            for rule in &*rules_clone {
                                if rule.matches(&packet_info) {
                                    println!("\n!!!! ALERT !!!!");
                                    println!("Rule: {}", rule.msg);
                                    println!(
                                        "Packet: {} -> {} | Ports {:?} -> {:?}",
                                        packet_info.source_ip,
                                        packet_info.dest_ip,
                                        packet_info.source_port,
                                        packet_info.dest_port
                                    );
                                    println!("---------------\n");
                                }
                            }

                            // --- STATEFUL RULE CHECK ---
                            if packet_info.protocol == "tcp" {
                                if let Some(dest_port) = packet_info.dest_port {
                                    let mut tracker = tracker_clone.lock().unwrap();
                                    if let Some(alert_msg) = tracker.check_for_port_scan(
                                        packet_info.source_ip,
                                        packet_info.dest_ip,
                                        dest_port,
                                    ) {
                                        println!(
                                            "\n!!!! STATEFUL ALERT (from Worker {}) !!!!",
                                            i + 1
                                        );
                                        println!("Rule: {}", alert_msg);
                                        println!("--------------------------------------\n");
                                    }
                                }
                            }

                            // --- HEURISTIC CHECK ---
                            if let Some(dest_port) = packet_info.dest_port {
                                let mut tracker = tracker_clone.lock().unwrap();
                                if let Some(alert_msg) = tracker.check_for_data_exfil(
                                    packet_info.source_ip,
                                    packet_info.dest_ip,
                                    dest_port,
                                    payload_size,
                                ) {
                                    warn!(
                                        "Heuristic Match (from Worker {}) : {}",
                                        i + 1,
                                        alert_msg
                                    )
                                }
                            }
                        }
                    }
                }
            }
        });

        worker_handles.push(handle);
    }

    // --- START CAPTURE ---
    println!("\nStarting capture on {}...", selected_device.name);
    if let Err(e) = start_capture(&selected_device.name, tx) {
        eprintln!("Capture error: {}", e);
    }

    // --- CLEANUP ---
    for handle in worker_handles {
        handle.join().unwrap();
    }

    Ok(())
}

fn load_rules(path: &str) -> Result<Vec<Rule>, Box<dyn Error>> {
    let file = File::open(path)?;
    let rules: Vec<Rule> = serde_yaml::from_reader(file)?;
    info!("Successfully loaded {} rules.", rules.len());
    Ok(rules)
}
