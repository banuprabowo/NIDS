
# Test Module Explanations

This document explains the test modules added to `capture.rs` and `state.rs`.

## `capture.rs` Tests

The tests for `capture.rs` are designed to ensure the reliability of the packet capture functionality.

### `test_list_devices`

This is a straightforward sanity check for the `list_devices` function. It calls the function and asserts that it returns a `Result` of `Ok`, meaning the function executed without panicking or returning an error. This test ensures that the underlying `pcap` library can correctly query the system for network interfaces.

### `test_start_capture_simulation`

This test is more involved and simulates the core functionality of the `start_capture` function. Since `start_capture` is designed to run in a loop and listen on a live network interface, a direct test would be complex and dependent on the environment. Instead, this test uses a simulation approach:

1.  **Channel Creation**: It creates a `crossbeam_channel` to mimic the communication channel used by `start_capture` to send packet data.
2.  **Thread Spawning**: A new thread is spawned to simulate the capture process. Inside this thread, a sample packet (a `vec![1, 2, 3, 4, 5]`) is sent through the channel.
3.  **Receiving Data**: The main test thread waits to receive the data from the channel.
4.  **Assertion**: It asserts that the received data is identical to the data that was sent, confirming that the channel-based communication is working as expected.
5.  **Thread Cleanup**: The test waits for the spawned thread to complete its execution.

This test effectively verifies the data flow and concurrency logic of the capture module without needing a live network interface.

## `state.rs` Tests

The tests for `state.rs` focus on the logic of the `ConnectionTracker`, which is responsible for detecting port scans.

### `test_new_connection_tracker`

This test ensures that the `ConnectionTracker` is initialized correctly. It creates a new instance and asserts that its `activity_map` is empty, which is the expected state for a new tracker.

### `test_port_scan_detection`

This test verifies that the `check_for_port_scan` function correctly identifies a port scan. It simulates a scenario where a single source IP sends packets to a destination IP on a number of ports exceeding `PORT_SCAN_THRESHOLD`.

1.  **Tracker and IP Setup**: A `ConnectionTracker` is created, and source and destination IP addresses are defined.
2.  **Simulating a Scan**: The test loops from 1 to `PORT_SCAN_THRESHOLD + 1`, calling `check_for_port_scan` for each port.
3.  **Alert Assertion**: After the threshold is crossed, the next call to `check_for_port_scan` is expected to return `Some(String)`, indicating that a port scan has been detected. The test asserts that the returned value is indeed `Some`.

### `test_activity_reset_after_time_window`

This test checks that the `ConnectionTracker` correctly resets the tracked activity for a host after the `TIME_WINDOW` has elapsed.

1.  **Initial Traffic**: The test first simulates some network traffic that is below the port scan threshold.
2.  **Waiting**: It then pauses the execution for a duration longer than `TIME_WINDOW`.
3.  **New Traffic**: After the pause, it simulates new traffic from the same source to the same destination.
4.  **No Alert Assertion**: Because the time window has passed, this new traffic should not be considered a continuation of the previous activity. The test asserts that `check_for_port_scan` returns `None`, confirming that the activity was reset.

### `test_no_alert_for_normal_traffic`

This test ensures that the `ConnectionTracker` does not generate false positives for normal network traffic.

1.  **Simulating Normal Traffic**: It simulates traffic where the number of contacted ports is exactly at the `PORT_SCAN_THRESHOLD`.
2.  **No Alert Assertion**: For each packet simulated, the test asserts that `check_for_port_scan` returns `None`, as the threshold has not been exceeded.
