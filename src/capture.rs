use pcap::{Capture, Device, Error};
use crossbeam_channel::Sender;
use log::info;

// The function signature now changes to accept a Sender half of a channel.
// The channel will send vectors of bytes (the raw packet data).
pub fn start_capture(interface_name: &str, tx: Sender<Vec<u8>>) -> Result<(), Error>{
    let mut cap = Capture::from_device(interface_name)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    // Main capture loop
    while let Ok(packet) = cap.next_packet() {
        // Instead of calling a callback, we send the packet data into the channel.
        // We use `to_vec()` to create an owned copy of the data for the other threads.
        // The `send` operation will fail if the receiver has been dropped,
        // which means the program is shutting down, so we can break the loop.
        if tx.send(packet.data.to_vec()).is_err() {
            info!("Channel closed, Shutting down capture thread."); // Use info! for a clean shutdown message, instead of println!
            break;
        }
    }

    Ok(())
}


// Helper function to list devices, made public for  main.rs to use
pub fn list_devices() -> Result<Vec<Device>, Error>{
    Device::list()
}

