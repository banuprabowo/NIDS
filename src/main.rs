use std::error::Error;
use std::io::{self, Write};
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::thread;

use log::{info, warn, error};
// use env_logger;

use crossbeam_channel::{unbounded};
use pnet_packet::{Packet};
use nids_v1::{handle_packet, list_devices, start_capture, Rule, ConnectionTracker, Settings};


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

    // CONCURENCY SETUP
    // 1. Create a channel for sending raw packet data between threads.
    // `unbounded()` means the queue can grow indefinitely
    let (tx, rx) = unbounded::<Vec<u8>>();

    // 2. Wrap the rules in an Arc to share them safely and efficiently across threads.
    let shared_rules = Arc::new(rules);

    // Create the ConnectionTracker and wrap it in an Arc<Mutex>.
    let connection_tracker = Arc::new(Mutex::new(ConnectionTracker::new(settings.port_scan_threshold, settings.port_scan_window_secs, settings.data_exfil_threshold_byte, settings.standard_ports)));

    // 3. Spawn worker threads.
    let num_workers = 4; // Can be adjusted based on CPU core
    let mut worker_handles = Vec::new();

    for i in 0..num_workers {
        let rx_clone = rx.clone(); // each worker need its own receiver handle
        let rules_clone = Arc::clone(&shared_rules); // each worker need a reference to rules
        let tracker_clone = Arc::clone(&connection_tracker); // Clone Arc for the ConnectionTracker for each worker

        // `thread::spawn` create and runs a new thread
        let handle = thread::spawn(move || {
            println!("Worker {} started.", i + 1);
            // This loop will block until a packet is received.

            while let Ok(packet_data) = rx_clone.recv(){
                if let Some(ethernet_packet) = pnet_packet::ethernet::EthernetPacket::new(&packet_data) {
                    let payload_size = ethernet_packet.payload().len();
                    if let Some(packet_info) = handle_packet(&ethernet_packet){

                        // --- STATELESS RULE CHECK ---
                        for rule in &*rules_clone{
                            if rule.matches(&packet_info){
                                println!("\n!!!! ALERT !!!!");
                                println!("Rule: {}", rule.msg);
                                println!("Packet: {} -> {} | Ports {:?} -> {:?}",
                                         packet_info.source_ip,
                                         packet_info.dest_ip,
                                         packet_info.source_port,
                                         packet_info.dest_port);

                                println!("---------------\n");
                            }
                        }

                        // --- STATEFUL RULE CHECK ---
                        if packet_info.protocol == "tcp" {
                            if let Some(dest_port) = packet_info.dest_port {
                                // Lock the mutex to get mutable access to the tracker.
                                // The lock is automatically released when `tracker` goes out of scope.

                                let mut tracker = tracker_clone.lock().unwrap();

                                // Check for port scan.
                                if let Some(alert_msg) = tracker.check_for_port_scan(
                                    packet_info.source_ip,
                                    packet_info.dest_ip,
                                    dest_port
                                ){
                                    // If scan is detected print Alert
                                    println!("\n!!!! STATEFUL ALERT (from Worker {}) !!!!", i + 1);
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
                            ){
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
        });

        worker_handles.push(handle);
    }

    // --- START CAPTURE ---
    println!("\nStarting capture on {}...", selected_device.name);

    // The capture thread takes ownership of the sender `tx`.
    // It no longer needs a closure.
    if let Err(e) = start_capture(&selected_device.name, tx){
        eprintln!("Capture error: {}", e);
    }

    // --- CLEANUP ---
    // Wait for all worker threads to finish (which they won't in this continuous loop,
    // but this is good practice for programs that do terminate).
    for handle in worker_handles{
        handle.join().unwrap();
    }

    Ok(())
}

fn load_rules(path: &str) -> Result<Vec<Rule>, Box<dyn Error>> {
    let file = File::open(path)?;
    let rules: Vec<Rule> = serde_yaml::from_reader(file)?;
    println!("Successfully loaded {} rules.", rules.len());
    Ok(rules)
}
