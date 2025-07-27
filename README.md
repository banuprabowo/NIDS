# Network Intrution Detection System

This NIDS developed in for me to familiarize and hands on learning on RUST Programming language
This project is developed with help of Gemini AI.

The system is a sophisticated, multi-threaded application featuring a hybrid detection model with three distinct engines: a signature-based engine, a stateful analysis engine, and a heuristic engine.

### High-Level Architecture
The NIDS operates on a producer-consumer concurrency model to ensure high performance.

    The Producer (Capture Thread): A single thread is dedicated to capturing raw network packets as quickly as possible and placing them into a shared channel (a queue).

    The Consumers (Worker Pool): A pool of multiple worker threads runs in parallel. Each worker pulls a packet from the channel, parses it, and runs it through the various detection engines.

This design decouples packet capture from analysis, preventing the system from dropping packets on high-traffic networks.

### Component Breakdown
   #### 1. The Orchestrator: main.rs

      Purpose: The main entry point of the application. It is responsible for initializing all components, starting the threads, and orchestrating the overall workflow.

      Key Responsibilities:

        Configuration Loading: At startup, it reads config/default.toml using the logic in settings.rs to load all application settings.

        Logger Initialization: It initializes the env_logger using the log_level specified in the configuration.

        Rule Loading: It reads the rules.yaml file and deserializes it into a vector of Rule structs.

        User Interaction: It lists available network devices and prompts the user to select one for monitoring.

        Concurrency Setup:

            It creates the crossbeam-channel for communication between the producer and consumers.

            It wraps the stateless rules (Vec<Rule>) and the stateful ConnectionTracker in an Arc (Atomically Referenced Counter) and Arc<Mutex<...>> respectively, allowing them to be shared safely across multiple threads.

        Spawning Workers: It spawns a configurable number of worker threads. Each worker receives a clone of the channel receiver and a reference to the shared rules and tracker.

        Initiating Capture: It creates the pcap::Capture handle and passes it along with the channel sender to the start_capture function, kicking off the entire process.

   #### 2. The Configuration System: settings.rs & config/default.toml

         Purpose: To provide a flexible and centralized way to configure the NIDS without recompiling the code.

         How it Works:

            config/default.toml: A human-readable file containing key-value pairs for all settings (file paths, log levels, worker counts, detection thresholds).

            src/settings.rs: Defines the Settings struct. The #[derive(Deserialize)] attribute allows serde to automatically populate this struct from the TOML file. The Settings::new() function uses the config crate to read the file and perform the deserialization, providing a type-safe Settings object to main.rs.

   #### 3. The Packet Source: capture.rs

      Purpose: The "producer" thread. Its sole responsibility is to capture raw packets from the network interface and send them to the worker pool.

      Key Logic: The start_capture function receives a pcap::Capture handle and the sender half of the channel (tx). It enters a tight loop, grabbing packets from the hardware and sending the raw byte data (packet.data.to_vec()) into the channel. It has no knowledge of parsing or analysis, making it highly specialized and efficient.

   #### 4. The Core Logic Hub: lib.rs

      Purpose: To define the public API of the nids_v1 library. It acts as the "blueprint" that connects all the modules.

      Key Logic: It uses mod to declare the existence of all other .rs files and pub use to export the specific structs and functions (Settings, Rule, handle_packet, etc.) that main.rs needs to use.

   #### 5. The Multi-Layer Parser: parser.rs

      Purpose: To translate raw, meaningless bytes into a structured, meaningful PacketInfo struct that the detection engines can understand.

      Key Logic:
   
           PacketInfo struct: The primary output of this module. It contains crucial L3/L4 information (IPs, ports, protocol) and a field for optional L7 data.
   
           handle_packet(): The main parsing function. It performs a layered unwrapping of the packet using the pnet crate.
   
           L7 DNS Parsing: If the parser identifies a UDP packet on port 53, it calls a specialized handle_dns_packet function. This function uses the trust-dns-proto crate to parse the DNS query name and type, enriching the PacketInfo with L7 data.

   #### 6. The Detection Engines

   The NIDS features three distinct, complementary detection engines.

   ##### A. Signature Engine: rules.rs & rules.yaml

       Purpose: To perform fast, stateless detection of known bad indicators.
   
       How it Works:
   
           rules.yaml: A blacklist of known bad signatures (IPs, ports, DNS queries).
   
           rules.rs: Defines the Rule struct that maps to the YAML file. The matches() method checks a PacketInfo struct against a rule's criteria. If a rule specifies dns_query: "bad.com", this method checks the dns_data field of the packet. This is a pure signature match.

   ##### B. Stateful & Heuristic Engine: state.rs

       Purpose: To perform more advanced behavioral and anomaly detection by maintaining a memory of network activity over time.
   
       ConnectionTracker struct: The core of this engine. It is wrapped in a Mutex to allow safe, mutable access from multiple worker threads. It stores a HashMap that tracks activity between pairs of IP addresses.
   
       How it Works:
   
           Stateful Pattern Detection: The check_for_port_scan() method implements this. It doesn't look for a specific signature but for a behavioral pattern: one IP connecting to many unique ports on a victim within a short time_window.
   
           Heuristic Detection: The check_for_data_exfil() method implements this. It uses a "rule of thumb" to find suspicious anomalies. The heuristic is: "A large transfer of data is suspicious, unless it's on a standard, whitelisted port." It identifies abnormal behavior by combining multiple factors (payload size, port number).

### Overall Data Flow

    Startup: main.rs loads settings and rules, then spawns the worker threads.

    Initiate: main.rs starts the capture thread, giving it the channel sender.

    Capture (Producer): The capture thread grabs a raw packet and sends its bytes into the channel.

    Receive (Consumer): A free worker thread receives the packet bytes from the channel.

    Parse: The worker calls parser::handle_packet() to convert the bytes into a structured PacketInfo.

    Analyze: The worker runs the PacketInfo through the three detection engines in order:

        It loops through the stateless rules and calls rule.matches().

        It locks the ConnectionTracker and calls check_for_port_scan().

        It locks the ConnectionTracker again and calls check_for_data_exfil().

    Alert: If any of the detection methods return a match, the worker uses the log crate to write a warn! level message to the console with the alert details.

    Loop: The worker goes back to step 4, waiting for the next packet. 