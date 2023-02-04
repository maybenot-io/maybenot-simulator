# The Maybenot Simulator

A simulator for the [Maybenot
framework](https://github.com/maybenot-io/maybenot/).

## Example Usage
See `cargo doc --open` for the API documentation. The following is a simple
example of how to use the simulator:

```rust
use maybenot::{framework::TriggerEvent, machine::Machine};
use maybenot_simulator::{parse_trace, sim};
use std::{str::FromStr, time::Duration};

// A trace of ten packets from the client's perspective when visiting
// google.com over WireGuard. The format is: "time,direction,size\n". The
// direction is either "s" (sent) or "r" (received). The time is in
// nanoseconds since the start of the trace. The size is in bytes.
let raw_trace = "0,s,52
19714282,r,52
183976147,s,52
243699564,r,52
1696037773,s,40
2047985926,s,52
2055955094,r,52
9401039609,s,73
9401094589,s,73
9420892765,r,191";

// The delay between client and server. This is for the simulation of the
// network between the client and server
let delay = Duration::from_millis(10);

// Parse the raw trace into a queue of events for the simulator. This uses
// the delay to generate a queue of events at the client and server in such
// a way that the client is ensured to get the packets in the same order and
// at the same time as in the raw trace.
let mut input_trace = parse_trace(raw_trace, delay);

// A simple machine that sends one padding packet of 1000 bytes 20
// milliseconds after the first NonPaddingSent is sent.
let m = "789cedcfc10900200805506d82b6688c1caf5bc3b54823f4a1a2a453b7021ff8ff49\
41261f685323426187f8d3f9cceb18039205b9facab8914adf9d6d9406142f07f0";
let m = Machine::from_str(m).unwrap();

// Run the simulator with the machine at the client. Run the simulation up
// until 100 packets have been recorded (total, client and server).
let trace = sim(vec![m], vec![], &mut input_trace, delay, 100, true);

// print packets from the client's perspective
let starting_time = trace[0].time;
trace
    .into_iter()
    .filter(|p| p.client)
    .for_each(|p| match p.event {
        TriggerEvent::NonPaddingSent { bytes_sent } => {
            println!(
                "sent {} bytes at {} ms",
                bytes_sent,
                (p.time - starting_time).as_millis()
            );
        }
        TriggerEvent::PaddingSent { bytes_sent, .. } => {
            println!(
                "sent {} bytes of padding at {} ms",
                bytes_sent,
                (p.time - starting_time).as_millis()
            );
        }
        TriggerEvent::NonPaddingRecv { bytes_recv } => {
            println!(
                "received {} bytes at {} ms",
                bytes_recv,
                (p.time - starting_time).as_millis()
            );
        }
        TriggerEvent::PaddingRecv { bytes_recv, .. } => {
            println!(
                "received {} bytes of padding at {} ms",
                bytes_recv,
                (p.time - starting_time).as_millis()
            );
        }
        _ => {}
    });
```

Produces the following output:

```
sent 52 bytes at 0 ms
received 52 bytes at 19 ms
sent 1000 bytes of padding at 20 ms
sent 52 bytes at 183 ms
received 52 bytes at 243 ms
sent 40 bytes at 1696 ms
sent 52 bytes at 2047 ms
received 52 bytes at 2055 ms
sent 73 bytes at 9401 ms
sent 73 bytes at 9401 ms
received 191 bytes at 9420 ms
```

## Key Limitations
This is a prototype simulator, and as such, it has a number of limitations. For
one, it is a simulator! We are simulating the integration with the
application/destination using the framework and the network between the client
and server. We have a *sim2real* problem.

In terms of networking, the relevant code for the simulator is in
`src/network.rs`. It is very crude: we use a fixed static delay. This should be
improved and evaluated against real-world network experiments. The goal of the
simulator is not necessarily to be a perfect simulator, but a useful simulator
for making different kinds of traffic analysis defenses.

There are also fundamental issues with simulating blocking actions of machines.
Because the simulator takes as input a base network trace of encrypted network
traffic, we do not know any semantics or inter-dependencies between the packets
in the encrypted trace. As a result, we cannot properly simulate blocking
actions. For example, if a machine blocks a packet, we cannot know if the
blocked packet contains a request for a resource that leads to a response
contained in the following received packets. The simulator will happily still
receive the resource in the encrypted network trace. Here be dragons.

## Rich Debug Output
The simulator can be run with the `RUST_LOG=debug` environment variable set to
get rich debug output. For example, to run the integration test
`test_bypass_machine`with debug output, run the following command:

```
RUST_LOG=debug cargo test test_bypass_machine
```

## Licensing
We are yet to decide on a license for this code. For now, early access is in
good faith only. Please do not redistribute this code without permission. Any
contributions to this code at this point is assumed to be the same as
transferring ownership of the contributions to Tobias Pulls (to allow maximize
flexibility for licensing lately once we decide). The simulator will be open
sourced at some point in the future.
