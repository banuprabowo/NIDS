use config::{Config, ConfigError, File};
use serde::Deserialize;

// The struct that will hold our application's configuration.
// The `Deserialize` trait allows `serde` to create this struct from a file.
#[derive(Debug, Deserialize)]
pub struct Settings {
    pub rules_file_path: String,
    pub log_level: String,
    pub worker_threads: usize,
    pub port_scan_threshold: usize,
    pub port_scan_window_secs: u64,
    pub data_exfil_threshold_byte: usize,
    pub standard_ports: Vec<u16>,
}

impl Settings {
    // Function to load configuration
    pub fn new() -> Result<Self, ConfigError> {
        let builder = Config::builder()
            // 1. Add configuration file
            .add_source(File::with_name("config/default.toml"));
            // 2. Also possible to add environment variable overrides
            // .add_source(config::Environment::with_prefix("ENV Prefix")

        // Build the configuration and deserialize it into string struct
        builder.build()?.try_deserialize()
    }
}