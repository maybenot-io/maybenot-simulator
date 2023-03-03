//! A simulator for the Maybenot framework. The [`Maybenot`](maybenot) framework
//! is intended for traffic analysis defenses that can be used to hide patterns
//! in encrypted communication. The goal of the simulator is to assist in the
//! development of such defenses.
//!
//! The simulator consists of two core functions: [`parse_trace`] and [`sim`].
//! The intended use is to first parse a trace (e.g., from a pcap file or a
//! Website Fingerprinting dataset) using [`parse_trace`], and then simulate the
//! trace using [`sim`] together with one or more Maybenot
//! [`Machines`](maybenot::machine::Machine) running at the client and/or
//! server. The output of the simulator can then be parsed to produce a
//! simulated trace that then in turn can be used to, e.g., train a Website
//! Fingerprinting attack.
//!
//! ## Example usage
//! ```
//! use maybenot::{framework::TriggerEvent, machine::Machine};
//! use maybenot_simulator::{parse_trace, sim};
//! use std::{str::FromStr, time::Duration};
//!
//! // A trace of ten packets from the client's perspective when visiting
//! // google.com over WireGuard. The format is: "time,direction,size\n". The
//! // direction is either "s" (sent) or "r" (received). The time is in
//! // nanoseconds since the start of the trace. The size is in bytes.
//! let raw_trace = "0,s,52
//! 19714282,r,52
//! 183976147,s,52
//! 243699564,r,52
//! 1696037773,s,40
//! 2047985926,s,52
//! 2055955094,r,52
//! 9401039609,s,73
//! 9401094589,s,73
//! 9420892765,r,191";
//!
//! // The delay between client and server. This is for the simulation of the
//! // network between the client and server
//! let delay = Duration::from_millis(10);
//!
//! // Parse the raw trace into a queue of events for the simulator. This uses
//! // the delay to generate a queue of events at the client and server in such
//! // a way that the client is ensured to get the packets in the same order and
//! // at the same time as in the raw trace.
//! let mut input_trace = parse_trace(raw_trace, delay);
//!
//! // A simple machine that sends one padding packet of 1000 bytes 20
//! // milliseconds after the first NonPaddingSent is sent.
//! let m = "789cedcfc10900200805506d82b6688c1caf5bc3b54823f4a1a2a453b7021ff8ff49\
//! 41261f685323426187f8d3f9cceb18039205b9facab8914adf9d6d9406142f07f0";
//! let m = Machine::from_str(m).unwrap();
//!
//! // Run the simulator with the machine at the client. Run the simulation up
//! // until 100 packets have been recorded (total, client and server).
//! let trace = sim(vec![m], vec![], &mut input_trace, delay, 100, true);
//!
//! // print packets from the client's perspective
//! let starting_time = trace[0].time;
//! trace
//!     .into_iter()
//!     .filter(|p| p.client)
//!     .for_each(|p| match p.event {
//!         TriggerEvent::NonPaddingSent { bytes_sent } => {
//!             println!(
//!                 "sent {} bytes at {} ms",
//!                 bytes_sent,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingSent { bytes_sent, .. } => {
//!             println!(
//!                 "sent {} bytes of padding at {} ms",
//!                 bytes_sent,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::NonPaddingRecv { bytes_recv } => {
//!             println!(
//!                 "received {} bytes at {} ms",
//!                 bytes_recv,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingRecv { bytes_recv, .. } => {
//!             println!(
//!                 "received {} bytes of padding at {} ms",
//!                 bytes_recv,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         _ => {}
//!     });
//!
//! ```
//!  Prints the following output:
//! ```text
//! sent 52 bytes at 0 ms
//! received 52 bytes at 19 ms
//! sent 1000 bytes of padding at 20 ms
//! sent 52 bytes at 183 ms
//! received 52 bytes at 243 ms
//! sent 40 bytes at 1696 ms
//! sent 52 bytes at 2047 ms
//! received 52 bytes at 2055 ms
//! sent 73 bytes at 9401 ms
//! sent 73 bytes at 9401 ms
//! received 191 bytes at 9420 ms
//! ```

pub mod network;
pub mod peek;
pub mod queue;

use std::{
    cmp::Reverse,
    collections::HashMap,
    time::{Duration, Instant},
};

use log::debug;
use queue::SimQueue;

use maybenot::{
    framework::{Action, Framework, MachineId, TriggerEvent},
    machine::Machine,
};

use crate::{
    network::sim_network_activity,
    peek::{peek_blocked_exp, peek_queue, peek_scheduled},
};

/// SimEvent represents an event in the simulator. It is used internally to
/// represent events that are to be processed by the simulator (in SimQueue) and
/// events that are produced by the simulator (the resulting trace).
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct SimEvent {
    pub event: TriggerEvent,
    pub time: Instant,
    pub client: bool,
    // internal flag to mark event as bypass
    bypass: bool,
    // internal flag to mark event as replace
    replace: bool,
    // prevents collisions in simulator queue (see remove() instead of pop())
    fuzz: i32,
}

/// ScheduledAction represents an action that is scheduled to be executed at a
/// certain time.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ScheduledAction {
    action: Option<Action>,
    time: Instant,
}

/// The state of the client or the server in the simulator.
pub struct SimState<'a> {
    /// an instance of the Maybenot framework
    framework: Framework<'a>,
    /// scheduled actions (timers)
    scheduled_action: HashMap<MachineId, ScheduledAction>,
    /// blocking time (active if in the future, relative to current_time)
    blocking_until: Instant,
    /// whether the active blocking bypassable or not
    blocking_bypassable: bool,
    /// time of the last sent packet
    last_sent_time: Instant,
    /// size of the last sent packet
    last_sent_size: u16,
}

impl<'a> SimState<'a> {
    pub fn new(machines: &'a [Machine], current_time: Instant) -> Self {
        Self {
            framework: Framework::new(machines, 0.0, 0.0, 1420, current_time).unwrap(),
            scheduled_action: HashMap::new(),
            // has to be in the past
            blocking_until: current_time - Duration::from_micros(1),
            blocking_bypassable: false,
            // has to be far in the past
            last_sent_time: current_time - Duration::from_millis(1000),
            last_sent_size: 0,
        }
    }
}

/// The main simulator function.
///
/// Zero or more machines can concurrently be run on the client and server. The
/// machines can be different. The framework is designed to support many
/// machines.
///
/// The queue MUST have been created by [`parse_trace`] with the same delay. The
/// queue is modified by the simulator and should be re-created for each run of
/// the simulator or cloned.
///
/// If max_trace_length is > 0, the simulator will stop after max_trace_length
/// events have been *simulated* by the simulator and added to the simulating
/// output trace. Note that some machines may schedule infinite actions (e.g.,
/// schedule new padding after sending padding), so the simulator may never
/// stop.
///
/// If only_network_activity is true, the simulator will only append events that
/// are related to network activity (i.e., packets sent and received) to the
/// output trace. This is recommended if you want to use the output trace for
/// traffic analysis without further (recursive) simulation.
pub fn sim(
    machines_client: Vec<Machine>,
    machines_server: Vec<Machine>,
    sq: &mut SimQueue,
    delay: Duration,
    max_trace_length: usize,
    only_network_activity: bool,
) -> Vec<SimEvent> {
    // the resulting simulated trace
    let mut trace: Vec<SimEvent> = vec![];

    // put the mocked current time at the first event
    let mut current_time = sq.peek().unwrap().0.time;

    // the client and server states
    let mut client = SimState::new(&machines_client, current_time);
    let mut server = SimState::new(&machines_server, current_time);

    let start_time = current_time;
    while let Some(next) = pick_next(sq, &mut client, &mut server, current_time) {
        debug!("#########################################################");
        debug!("sim(): main loop start, moving time forward");

        // move time forward
        if next.time < current_time {
            debug!("sim(): {:#?}", current_time);
            debug!("sim(): {:#?}", next.time);
            panic!("BUG: next event moves time backwards");
        }
        current_time = next.time;
        debug!(
            "sim(): at time {:#?}",
            current_time.duration_since(start_time)
        );
        if next.client {
            debug!("sim(): @client next\n{:#?}", next);
        } else {
            debug!("sim(): @server next\n{:#?}", next);
        }

        // if the client is blocked
        if client.blocking_until > current_time {
            debug!(
                "sim(): client is blocked until time {:#?}",
                client.blocking_until.duration_since(start_time)
            );
        }
        if server.blocking_until > current_time {
            debug!(
                "sim(): server is blocked until time {:#?}",
                server.blocking_until.duration_since(start_time)
            );
        }

        // For (non-)padding sent, queue the corresponding padding recv event:
        // in other words, where we simulate sending packets. The only place
        // where the simulator simulates the entire network between the client
        // and the server. TODO: make delay/network more realistic.
        let network_activity = if next.client {
            sim_network_activity(&next, sq, &client, current_time, delay)
        } else {
            sim_network_activity(&next, sq, &server, current_time, delay)
        };

        if network_activity {
            // update last packet stats in state
            match next.event {
                TriggerEvent::PaddingSent { bytes_sent, .. }
                | TriggerEvent::NonPaddingSent { bytes_sent } => {
                    if next.client {
                        client.last_sent_time = current_time;
                        client.last_sent_size = bytes_sent;
                    } else {
                        server.last_sent_time = current_time;
                        server.last_sent_size = bytes_sent;
                    }
                }
                _ => {}
            }
        }

        // get actions, update scheduled actions
        if next.client {
            debug!("sim(): trigger @client framework\n{:#?}", next.event);
            trigger_update(
                &mut client.framework,
                &mut client.scheduled_action,
                &next,
                &current_time,
            );
        } else {
            debug!("sim(): trigger @server framework\n{:#?}", next.event);
            trigger_update(
                &mut server.framework,
                &mut server.scheduled_action,
                &next,
                &current_time,
            );
        }

        // save results if either we should collect everything or if we had
        // network activity
        if !only_network_activity || network_activity {
            trace.push(next);
        }
        if max_trace_length > 0 && trace.len() >= max_trace_length {
            debug!(
                "sim(): we done, reached max trace length {}",
                max_trace_length
            );
            break;
        }

        debug!("sim(): main loop end, more work?");
        debug!("#########################################################");
    }
    trace
}

fn pick_next(
    sq: &mut SimQueue,
    client: &mut SimState,
    server: &mut SimState,
    current_time: Instant,
) -> Option<SimEvent> {
    // find the earliest scheduled, blocked, and queued events to determine the
    // next event
    let s = peek_scheduled(
        &client.scheduled_action,
        &server.scheduled_action,
        current_time,
    );
    debug!("\tpick_next(): peek_scheduled = {:?}", s);
    let b = peek_blocked_exp(&client.blocking_until, &server.blocking_until, current_time);
    debug!("\tpick_next(): peek_blocked_exp = {:?}", b);
    let (q, q_peek) = peek_queue(sq, client, server, s.min(b), current_time);
    debug!("\tpick_next(): peek_queue = {:?}", q);

    // no next?
    if s == Duration::MAX && b == Duration::MAX && q == Duration::MAX {
        return None;
    }

    // We prioritize the queue: in general, stuff happens faster outside the
    // framework than inside it. On overload, the user of the framework will
    // bulk trigger events in the framework.
    if q <= s && q <= b {
        debug!("\tpick_next(): picked queue");
        sq.remove(q_peek.as_ref().unwrap());

        // check if blocking moves the event forward in time
        let mut tmp = q_peek.unwrap();
        if current_time + q > tmp.time {
            tmp.time = current_time + q;
        }
        return Some(tmp);
    }

    // next is blocking expiry, happens outside of framework, so probably faster
    // than framework
    if b <= s {
        debug!("\tpick_next(): picked blocking");
        // create SimEvent and move blocking into (what soon will be) the past
        // to indicate that it has been processed
        let time: Instant;
        let client_earliest =
            if client.blocking_until >= current_time && server.blocking_until >= current_time {
                client.blocking_until <= server.blocking_until
            } else {
                client.blocking_until >= current_time
            };

        if client_earliest {
            time = client.blocking_until;
            client.blocking_until -= Duration::from_micros(1);
        } else {
            time = server.blocking_until;
            server.blocking_until -= Duration::from_micros(1);
        }

        return Some(SimEvent {
            client: client_earliest,
            event: TriggerEvent::BlockingEnd,
            time,
            fuzz: fastrand::i32(..),
            bypass: false,
            replace: false,
        });
    }

    // what's left is scheduled actions: find the action act on the action,
    // putting the event into the sim queue, and then recurse
    debug!("\tpick_next(): picked scheduled");
    let target = current_time + s;
    let act = do_scheduled(client, server, current_time, target);
    if let Some(a) = act {
        sq.push_sim(a, Reverse(current_time));
    }
    pick_next(sq, client, server, current_time)
}

fn do_scheduled(
    client: &mut SimState,
    server: &mut SimState,
    current_time: Instant,
    target: Instant,
) -> Option<SimEvent> {
    // find the action
    let mut a = ScheduledAction {
        action: None,
        time: current_time,
    };
    let mut a_is_client = false;

    client.scheduled_action.retain(|&_mi, sa| {
        if sa.action.is_some() && sa.time == target {
            a = sa.clone();
            a_is_client = true;
            return false;
        };
        true
    });

    // cannot schedule a None action, so if we found one, done
    if a.action.is_none() {
        server.scheduled_action.retain(|&_mi, sa| {
            if sa.action.is_some() && sa.time == target {
                a = sa.clone();
                a_is_client = false;
                return false;
            };
            true
        });
    }

    // do the action
    match a.action? {
        Action::Cancel { .. } => {
            // by being selected we set the action to None already
            None
        }
        Action::InjectPadding {
            timeout: _,
            size,
            bypass,
            replace,
            machine,
        } => Some(SimEvent {
            event: TriggerEvent::PaddingSent {
                bytes_sent: size,
                machine,
            },
            time: a.time,
            client: a_is_client,
            bypass,
            replace,
            fuzz: fastrand::i32(..),
        }),
        Action::BlockOutgoing {
            timeout: _,
            duration,
            bypass,
            replace,
            machine,
        } => {
            let block = a.time + duration;
            let event_bypass;

            // should we update client/server blocking?
            if a_is_client {
                if replace || block > client.blocking_until {
                    client.blocking_until = block;
                    client.blocking_bypassable = bypass;
                }
                event_bypass = client.blocking_bypassable;
            } else {
                if replace || block > server.blocking_until {
                    server.blocking_until = block;
                    server.blocking_bypassable = bypass;
                }
                event_bypass = server.blocking_bypassable;
            }

            // event triggered regardless
            Some(SimEvent {
                event: TriggerEvent::BlockingBegin { machine },
                time: a.time,
                client: a_is_client,
                bypass: event_bypass,
                replace: false,
                fuzz: fastrand::i32(..),
            })
        }
    }
}

fn trigger_update(
    f: &mut Framework,
    actions: &mut HashMap<MachineId, ScheduledAction>,
    next: &SimEvent,
    current_time: &Instant,
) {
    // parse actions and update
    for action in f.trigger_events(&[next.event.clone()], *current_time) {
        match action {
            Action::Cancel { machine } => {
                actions.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time,
                    },
                );
            }
            Action::InjectPadding {
                timeout,
                size: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                actions.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time + *timeout,
                    },
                );
            }
            Action::BlockOutgoing {
                timeout,
                duration: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                actions.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time + *timeout,
                    },
                );
            }
        };
    }
}

/// Parse a trace into a [`SimQueue`] for use with [`sim`].
///
/// The trace should contain one or more lines of the form
/// "time,direction,size\n", where time is in nanoseconds relative to the first
/// line, direction is either "s" for sent or "r" for received, and size is the
/// number of bytes sent or received. The delay is used to model the network
/// delay between the client and server. Returns a SimQueue with the events in
/// the trace for use with [`sim`].
pub fn parse_trace(trace: &str, delay: Duration) -> SimQueue {
    let mut sq = SimQueue::new();

    // we just need a random starting time to make sure that we don't start from
    // absolute 0
    let starting_time = Instant::now();

    for l in trace.lines() {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() == 3 {
            let timestamp =
                starting_time + Duration::from_nanos(parts[0].trim().parse::<u64>().unwrap());
            let size = parts[2].trim().parse::<u64>().unwrap();

            match parts[1] {
                "s" => {
                    // client sent at the given time
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        true,
                        timestamp,
                        Reverse(timestamp),
                    );
                }
                "r" => {
                    // sent by server delay time ago
                    let sent = timestamp - delay;
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        false,
                        sent,
                        Reverse(sent),
                    );
                }
                _ => {
                    panic!("invalid direction")
                }
            }
        }
    }

    sq
}
