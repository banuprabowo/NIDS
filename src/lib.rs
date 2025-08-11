// In src/lib.rs
mod capture;
mod parser;
mod rules;
mod state;
mod settings;
mod reassembly;

pub use capture::{list_devices, start_capture};
// Export everything needed from the parser module
pub use parser::{handle_packet, PacketInfo};
pub use rules::Rule;
pub use state::ConnectionTracker;
pub use settings::Settings;
pub use reassembly::TcpReassembler;