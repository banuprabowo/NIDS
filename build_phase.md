NIDS Project Development Roadmap

This document outlines the complete development plan for building a Network Intrusion Detection System (NIDS) in Rust. The project is broken down into distinct phases, each building upon the last and introducing new concepts in Rust and cybersecurity.
✅ Phase 1: Foundation & Parsing

    Goal: To build the basic skeleton of the application, capable of capturing raw network packets and understanding their fundamental structure.

    Key Concepts Learned:

        Basic Rust syntax and project structure (main.rs, lib.rs).

        Using external crates (pcap, pnet).

        Organizing code into modules (capture.rs, parser.rs).

        Zero-copy parsing of Ethernet (L2) and IPv4 (L3) headers.

        Basic error handling with Result and Option.

    Outcome: A well-organized application that can capture live network traffic and print structured Layer 2 and Layer 3 information (MAC addresses, IP addresses) to the console.

✅ Phase 2: The Rule Engine

    Goal: To give the NIDS a "brain" by creating a system that can make decisions about packets based on a predefined set of rules.

    Key Concepts Learned:

        Serialization and Deserialization with serde and serde_yaml.

        Loading configuration from external files (rules.yaml).

        Advanced struct design using Option<T> for flexible criteria.

        Implementing custom methods (matches()) on structs.

        Writing comprehensive unit tests (#[cfg(test)]) to validate logic.

    Outcome: A functional NIDS that loads detection rules from a YAML file. When a packet's properties (IPs, ports, protocol) match a rule, the system prints a formatted alert to the console.

✅ Phase 3: Performance with Concurrency

    Goal: To re-architect the NIDS to handle high-traffic loads efficiently, ensuring that packet capture is not blocked by analysis.

    Key Concepts Learned:

        The producer-consumer concurrency pattern.

        Spawning threads with std::thread.

        Thread-safe communication using channels (crossbeam-channel).

        Safe, shared ownership of data across threads using Arc<T> (Atomically Referenced Counter).

    Outcome: A scalable, multi-threaded application. One "producer" thread captures packets and places them in a queue, while a pool of "consumer" worker threads processes them in parallel, dramatically improving performance.

➡️ Phase 4: Advanced Rules & Stateful Analysis

    Why it's next: Our current NIDS is stateless; it analyzes each packet in isolation. To detect more sophisticated threats like port scans, we need to remember past events and analyze patterns over time.

    Tasks:

        Enhance Rule Syntax: Evolve the Rule struct and matching logic to support more complex conditions, such as port ranges (dest_port > 1024) or IP subnets.

        Implement a Connection Tracker: Create a new module that manages a HashMap. The key could be a tuple of (source_ip, dest_ip, source_port, dest_port), and the value could be a struct tracking connection state (e.g., timestamps, packet counts).

        Create Stateful Rules: Implement logic that uses the connection tracker to detect patterns. For example: "Alert if a single source IP creates more than 15 new TCP connections to a single destination host within 10 seconds."

➡️ Phase 5: Professional Logging & Output

    Why it's next: println! is for debugging. A real security tool needs structured, configurable, and persistent logging that can be archived or ingested by other systems (like a SIEM).

    Tasks:

        Integrate Logging Crates: Add log and a logger implementation like env_logger or fern to your Cargo.toml.

        Replace println!: Convert all println! and eprintln! calls to the appropriate logging macros (info!, warn!, error!). Alerts should be a high-priority level, like warn!.

        Structured JSON Logging: Configure the logger to output alerts as structured JSON to a file (e.g., alerts.log). Each JSON log entry should contain fields like timestamp, log_level, rule_message, source_ip, dest_port, etc.

➡️ Phase 6: Centralized Configuration

    Why it's next: Hardcoding values like the number of worker threads or file paths is inflexible. A professional tool must be configurable without recompiling.

    Tasks:

        Create a config.toml file.

        Define application settings in the file, such as rules_file_path = "rules.yaml", log_file_path = "alerts.log", log_level = "warn", and worker_threads = 4.

        Integrate config Crate: Use the config crate with serde to load this TOML file at startup into a Settings struct.

        Use the values from the loaded Settings struct to drive your application's behavior.

➡️ Phase 7: Application Layer (L7) Parsing

    Why it's next: The most valuable intelligence often lies within the application data itself (e.g., DNS queries, HTTP headers).

    Tasks:

        Choose a Protocol: Start with a simple, text-based protocol like DNS or HTTP.

        Implement L7 Parser: When the main parser identifies a packet on port 53 (DNS) or 80 (HTTP), it should pass the TCP/UDP payload to a new, specialized L7 parsing function.

        Create L7 Rules: Enhance the rule engine to support L7 criteria. Example rules:

            dns_query: "evil-domain.com"

            http_user_agent_contains: "Nmap"

            http_request_path: "/.git/config"

➡️ Phase 8: Heuristics & Anomaly Detection

    Why it's next: This is the most advanced phase, moving beyond fixed signatures into behavioral analysis. It demonstrates a deep understanding of security principles.

    Tasks:

        Establish Baselines: Use the stateful connection tracker from Phase 4 to gather metrics and establish what "normal" traffic looks like over time.

        Develop Heuristics: Create a new type of "rule" that is based on a heuristic rather than a fixed signature.

        Example Heuristics:

            "Alert if a DNS response is unusually large (> 1KB), which could indicate a tunneling attack."

            "Alert if a connection on a non-standard port transfers more than 10MB of data, which could indicate data exfiltration."

            "Alert if a host starts communicating with an IP address it has never contacted before."
