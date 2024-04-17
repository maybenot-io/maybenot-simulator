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
//! use maybenot::{event::TriggerEvent, machine::Machine};
//! use maybenot_simulator::{network::Network, parse_trace, sim};
//! use std::{str::FromStr, time::Duration};
//!
//! // The first ten packets of a network trace from the client's perspective
//! // when visiting google.com. The format is: "time,direction\n". The
//! // direction is either "s" (sent) or "r" (received). The time is in
//! // nanoseconds since the start of the trace.
//! let raw_trace = "0,s
//! 19714282,r
//! 183976147,s
//! 243699564,r
//! 1696037773,s
//! 2047985926,s
//! 2055955094,r
//! 9401039609,s
//! 9401094589,s
//! 9420892765,r";
//! // The network model for simulating the network between the client and the
//! // server. Currently just a delay.
//! let network = Network::new(Duration::from_millis(10));
//! // Parse the raw trace into a queue of events for the simulator. This uses
//! // the delay to generate a queue of events at the client and server in such
//! // a way that the client is ensured to get the packets in the same order and
//! // at the same time as in the raw trace.
//! let mut input_trace = parse_trace(raw_trace, &network);
//! // A simple machine that sends one padding packet 20 milliseconds after the
//! // first normal packet is sent.
//! let m = "02eNptibENAAAIwsDH9DRH//Mh4+Jg6EBCC3xshySQfnKvpjp0GFboAmI=";
//! let m = Machine::from_str(m).unwrap();
//! // Run the simulator with the machine at the client. Run the simulation up
//! // until 100 packets have been recorded (total, client and server).
//! let trace = sim(&[m], &[], &mut input_trace, network.delay, 100, true);
//! // print packets from the client's perspective
//! let starting_time = trace[0].time;
//! trace
//!     .into_iter()
//!     .filter(|p| p.client)
//!     .for_each(|p| match p.event {
//!         TriggerEvent::NormalSent => {
//!             println!(
//!                 "sent a normal packet at {} ms",
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingSent => {
//!             println!(
//!                 "sent a padding packet at {} ms",
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::NormalRecv => {
//!             println!(
//!                 "received a padding packet at {} ms",
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingRecv => {
//!             println!(
//!                 "received a padding packet at {} ms",
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         _ => {}
//!     });
//! // Output:
//! // sent a normal packet at 0 ms
//! // received a padding packet at 19 ms
//! // sent a padding packet at 20 ms
//! // sent a normal packet at 183 ms
//! // received a padding packet at 243 ms
//! // sent a normal packet at 1696 ms
//! // sent a normal packet at 2047 ms
//! // received a padding packet at 2055 ms
//! // sent a normal packet at 9401 ms
//! // sent a normal packet at 9401 ms
//! // received a padding packet at 9420 ms
//! ```

pub mod integration;
pub mod network;
pub mod peek;
pub mod queue;

use std::{
    cmp::{Ordering, Reverse},
    collections::HashMap,
    time::{Duration, Instant},
};

use integration::Integration;
use log::debug;
use network::Network;
use queue::SimQueue;

use maybenot::{
    action::{Timer, TriggerAction},
    event::TriggerEvent,
    framework::{Framework, MachineId},
    machine::Machine,
};

use crate::{
    network::sim_network_stack,
    peek::{peek_blocked_exp, peek_internal, peek_queue, peek_scheduled},
};

/// SimEvent represents an event in the simulator. It is used internally to
/// represent events that are to be processed by the simulator (in SimQueue) and
/// events that are produced by the simulator (the resulting trace).
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct SimEvent {
    pub event: TriggerEvent,
    pub time: Instant,
    pub delay: Duration,
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
#[derive(PartialEq, Clone, Debug)]
pub struct ScheduledAction {
    action: TriggerAction,
    time: Instant,
}

/// The state of the client or the server in the simulator.
pub struct SimState<M> {
    /// an instance of the Maybenot framework
    framework: Framework<M>,
    /// scheduled action timers
    scheduled_action: HashMap<MachineId, Option<ScheduledAction>>,
    /// scheduled internal timers
    scheduled_internal: HashMap<MachineId, Option<Instant>>,
    /// blocking time (active if in the future, relative to current_time)
    blocking_until: Instant,
    /// whether the active blocking bypassable or not
    blocking_bypassable: bool,
    /// time of the last sent packet
    last_sent_time: Instant,
    /// integration aspects for this state
    integration: Option<Integration>,
}

impl<M> SimState<M>
where
    M: AsRef<[Machine]>,
{
    pub fn new(
        machines: M,
        current_time: Instant,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        integration: Option<Integration>,
    ) -> Self {
        Self {
            framework: Framework::new(machines, max_padding_frac, max_blocking_frac, current_time)
                .unwrap(),
            scheduled_action: HashMap::new(),
            scheduled_internal: HashMap::new(),
            // has to be in the past
            blocking_until: current_time.checked_sub(Duration::from_micros(1)).unwrap(),
            blocking_bypassable: false,
            // has to be far in the past
            last_sent_time: current_time
                .checked_sub(Duration::from_millis(1000))
                .unwrap(),
            integration,
        }
    }

    pub fn reporting_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.reporting_delay.sample())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn action_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.action_delay.sample())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn trigger_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.trigger_delay.sample())
            .unwrap_or(Duration::from_micros(0))
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
/// stop. Use [`sim_advanced`] to set the maximum number of iterations to run
/// the simulator for and other advanced settings.
///
/// If only_network_activity is true, the simulator will only append events that
/// are related to network activity (i.e., packets sent and received) to the
/// output trace. This is recommended if you want to use the output trace for
/// traffic analysis without further (recursive) simulation.
pub fn sim(
    machines_client: &[Machine],
    machines_server: &[Machine],
    sq: &mut SimQueue,
    delay: Duration,
    max_trace_length: usize,
    only_network_activity: bool,
) -> Vec<SimEvent> {
    let network = Network::new(delay);
    let args = SimulatorArgs::new(&network, max_trace_length, only_network_activity);
    sim_advanced(machines_client, machines_server, sq, &args)
}

/// Arguments for [`sim_advanced`].
#[derive(Clone, Debug)]
pub struct SimulatorArgs<'a> {
    pub network: &'a Network,
    pub max_trace_length: usize,
    pub max_sim_iterations: usize,
    pub only_client_events: bool,
    pub only_network_activity: bool,
    pub max_padding_frac_client: f64,
    pub max_blocking_frac_client: f64,
    pub max_padding_frac_server: f64,
    pub max_blocking_frac_server: f64,
    pub client_integration: Option<&'a Integration>,
    pub server_integration: Option<&'a Integration>,
}

impl<'a> SimulatorArgs<'a> {
    pub fn new(network: &'a Network, max_trace_length: usize, only_network_activity: bool) -> Self {
        Self {
            network,
            max_trace_length,
            max_sim_iterations: 0,
            only_client_events: false,
            only_network_activity,
            max_padding_frac_client: 0.0,
            max_blocking_frac_client: 0.0,
            max_padding_frac_server: 0.0,
            max_blocking_frac_server: 0.0,
            client_integration: None,
            server_integration: None,
        }
    }
}

/// Like [`sim`], but allows to (i) set the maximum padding and blocking
/// fractions for the client and server, (ii) specify the maximum number of
/// iterations to run the simulator for, and (iii) only returning client events.
pub fn sim_advanced(
    machines_client: &[Machine],
    machines_server: &[Machine],
    sq: &mut SimQueue,
    args: &SimulatorArgs,
) -> Vec<SimEvent> {
    // the resulting simulated trace
    let mut trace: Vec<SimEvent> = vec![];

    // put the mocked current time at the first event
    let mut current_time = sq.peek().unwrap().0.time;

    // the client and server states
    let mut client = SimState::new(
        machines_client,
        current_time,
        args.max_padding_frac_client,
        args.max_blocking_frac_client,
        args.client_integration.cloned(),
    );
    let mut server = SimState::new(
        machines_server,
        current_time,
        args.max_padding_frac_server,
        args.max_blocking_frac_server,
        args.server_integration.cloned(),
    );

    let mut sim_iterations = 0;
    let start_time = current_time;
    while let Some(next) = pick_next(sq, &mut client, &mut server, current_time) {
        debug!("#########################################################");
        debug!("sim(): main loop start");

        // move time forward?
        match next.time.cmp(&current_time) {
            Ordering::Less => {
                debug!("sim(): {:#?}", current_time);
                debug!("sim(): {:#?}", next.time);
                panic!("BUG: next event moves time backwards");
            }
            Ordering::Greater => {
                debug!("sim(): time moved forward {:#?}", next.time - current_time);
                current_time = next.time;
            }
            _ => {}
        }

        // status
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

        // Where the simulator simulates the entire network between the client
        // and the server. Returns true if there was network activity (i.e., a
        // packet was sent or received over the network), false otherwise.
        let network_activity = if next.client {
            sim_network_stack(&next, sq, &client, &server, args.network, &current_time)
        } else {
            sim_network_stack(&next, sq, &server, &client, args.network, &current_time)
        };

        if network_activity {
            // update last packet stats in state
            match next.event {
                TriggerEvent::PaddingSent | TriggerEvent::NormalSent => {
                    if next.client {
                        client.last_sent_time = current_time;
                    } else {
                        server.last_sent_time = current_time;
                    }
                }
                _ => {}
            }
        }

        // get actions, update scheduled actions
        if next.client {
            debug!("sim(): trigger @client framework\n{:#?}", next.event);
            trigger_update(&mut client, &next, &current_time, sq, true);
        } else {
            debug!("sim(): trigger @server framework\n{:#?}", next.event);
            trigger_update(&mut server, &next, &current_time, sq, false);
        }

        // conditional save to resulting trace: only on network activity if set
        // in fn arg, and only on client activity if set in fn arg
        if (!args.only_network_activity || network_activity)
            && (!args.only_client_events || next.client)
        {
            // this should be a network trace: adjust timestamps based on any
            // integration delays
            let mut n = next.clone();
            match next.event {
                TriggerEvent::PaddingSent => {
                    // padding adds the action delay
                    n.time += n.delay;
                }
                TriggerEvent::PaddingRecv | TriggerEvent::NormalRecv | TriggerEvent::NormalSent => {
                    // reported events remove the reporting delay
                    n.time -= n.delay;
                }
                _ => {}
            }

            trace.push(n);
        }

        if args.max_trace_length > 0 && trace.len() >= args.max_trace_length {
            debug!(
                "sim(): we done, reached max trace length {}",
                args.max_trace_length
            );
            break;
        }

        // check if we should stop
        sim_iterations += 1;
        if args.max_sim_iterations > 0 && sim_iterations >= args.max_sim_iterations {
            debug!(
                "sim(): we done, reached max sim iterations {}",
                args.max_sim_iterations
            );
            break;
        }

        debug!("sim(): main loop end, more work?");
        debug!("#########################################################");
    }

    // sort the trace by time
    trace.sort_by(|a, b| a.time.cmp(&b.time));

    trace
}

fn pick_next<M: AsRef<[Machine]>>(
    sq: &mut SimQueue,
    client: &mut SimState<M>,
    server: &mut SimState<M>,
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
    let i = peek_internal(
        &client.scheduled_internal,
        &server.scheduled_internal,
        current_time,
    );
    debug!("\tpick_next(): peek_internal = {:?}", i);
    let b = peek_blocked_exp(&client.blocking_until, &server.blocking_until, current_time);
    debug!("\tpick_next(): peek_blocked_exp = {:?}", b);
    let (q, q_peek) = peek_queue(sq, client, server, s.min(b), current_time);
    debug!("\tpick_next(): peek_queue = {:?}", q);

    // no next?
    if s == Duration::MAX && i == Duration::MAX && b == Duration::MAX && q == Duration::MAX {
        return None;
    }

    // We prioritize the queue: in general, stuff happens faster outside the
    // framework than inside it. On overload, the user of the framework will
    // bulk trigger events in the framework.
    if q <= s && q <= i && q <= b {
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
    if b <= s && b <= i {
        debug!("\tpick_next(): picked blocking");
        // create SimEvent and move blocking into (what soon will be) the past
        // to indicate that it has been processed
        let time: Instant;
        // ASSUMPTION: block outgoing is reported from integration
        let delay: Duration;
        let client_earliest =
            if client.blocking_until >= current_time && server.blocking_until >= current_time {
                client.blocking_until <= server.blocking_until
            } else {
                client.blocking_until >= current_time
            };

        if client_earliest {
            delay = client.reporting_delay();
            time = client.blocking_until + delay;
            client.blocking_until -= Duration::from_micros(1);
        } else {
            delay = server.reporting_delay();
            time = server.blocking_until + delay;
            server.blocking_until -= Duration::from_micros(1);
        }

        return Some(SimEvent {
            client: client_earliest,
            event: TriggerEvent::BlockingEnd,
            time,
            delay,
            fuzz: fastrand::i32(..),
            bypass: false,
            replace: false,
        });
    }

    // next we pick internal events, which should be faster than scheduled
    // actions due to less work
    if i <= s {
        debug!("\tpick_next(): picked internal");
        let target = current_time + i;
        let act = do_internal(client, server, target);
        if let Some(a) = act {
            sq.push_sim(a.clone(), Reverse(a.time));
        }
        return pick_next(sq, client, server, current_time);
    }

    // what's left is scheduled actions: find the action act on the action,
    // putting the event into the sim queue, and then recurse
    debug!("\tpick_next(): picked scheduled");
    let target = current_time + s;
    let act = do_scheduled(client, server, target);
    if let Some(a) = act {
        sq.push_sim(a.clone(), Reverse(a.time));
    }
    pick_next(sq, client, server, current_time)
}

fn do_internal<M: AsRef<[Machine]>>(
    client: &mut SimState<M>,
    server: &mut SimState<M>,
    target: Instant,
) -> Option<SimEvent> {
    let mut machine: Option<MachineId> = None;
    let mut is_client = false;

    client.scheduled_internal.retain(|mi, t| {
        if *t == Some(target) {
            machine = Some(*mi);
            is_client = true;
            return false;
        }
        true
    });

    if machine.is_none() {
        server.scheduled_internal.retain(|mi, t| {
            if *t == Some(target) {
                machine = Some(*mi);
                return false;
            }
            true
        });
    }

    assert!(machine.is_some(), "BUG: no internal action found");

    // create SimEvent with TimerEnd
    Some(SimEvent {
        client: is_client,
        event: TriggerEvent::TimerEnd {
            machine: machine.unwrap(),
        },
        time: target,
        delay: Duration::from_micros(0), // TODO: is this correct?
        fuzz: fastrand::i32(..),
        bypass: false,
        replace: false,
    })
}

fn do_scheduled<M: AsRef<[Machine]>>(
    client: &mut SimState<M>,
    server: &mut SimState<M>,
    target: Instant,
) -> Option<SimEvent> {
    // find the action
    let mut a: Option<ScheduledAction> = None;
    let mut is_client = false;

    client.scheduled_action.retain(|&_mi, sa| {
        if let Some(sa) = sa {
            if a.is_none() && sa.time == target {
                a = Some(sa.clone());
                is_client = true;
                return false;
            };
        }
        true
    });

    // cannot schedule a None action, so if we found one, done
    if a.is_none() {
        server.scheduled_action.retain(|&_mi, sa| {
            if let Some(sa) = sa {
                if a.is_none() && sa.time == target {
                    a = Some(sa.clone());
                    is_client = false;
                    return false;
                };
            }
            true
        });
    }

    // no action found
    assert!(a.is_some(), "BUG: no action found");
    let a = a.unwrap();

    // do the action
    match a.action {
        TriggerAction::Cancel { .. } => {
            // this should never happen, bug
            panic!("BUG: cancel action in scheduled action");
        }
        TriggerAction::UpdateTimer { .. } => {
            // this should never happen, bug
            panic!("BUG: update timer action in scheduled action");
        }
        TriggerAction::SendPadding {
            timeout: _,
            bypass,
            replace,
            machine,
        } => {
            let action_delay = if is_client {
                client.action_delay()
            } else {
                server.action_delay()
            };

            Some(SimEvent {
                event: TriggerEvent::PaddingQueued { machine },
                time: a.time,
                delay: action_delay,
                client: is_client,
                bypass,
                replace,
                fuzz: fastrand::i32(..),
            })
        }
        TriggerAction::BlockOutgoing {
            timeout: _,
            duration,
            bypass,
            replace,
            machine,
        } => {
            let block = a.time + duration;
            let event_bypass;
            // ASSUMPTION: block outgoing reported from integration
            let total_delay = if is_client {
                client.action_delay() + client.reporting_delay()
            } else {
                server.action_delay() + server.reporting_delay()
            };
            let reported = a.time + total_delay;

            // should we update client/server blocking?
            if is_client {
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
                time: reported,
                delay: total_delay,
                client: is_client,
                bypass: event_bypass,
                replace: false,
                fuzz: fastrand::i32(..),
            })
        }
    }
}

fn trigger_update<M: AsRef<[Machine]>>(
    state: &mut SimState<M>,
    next: &SimEvent,
    current_time: &Instant,
    sq: &mut SimQueue,
    is_client: bool,
) {
    let trigger_delay = state.trigger_delay();

    // parse actions and update
    for action in state
        .framework
        .trigger_events(&[next.event.clone()], *current_time)
    {
        match action {
            TriggerAction::Cancel { machine, timer } => {
                // here we make a simplifying assumption of no trigger delay for
                // cancel actions
                match timer {
                    Timer::Action => {
                        state.scheduled_action.insert(*machine, None);
                    }
                    Timer::Internal => {
                        state.scheduled_internal.insert(*machine, None);
                    }
                    Timer::All => {
                        state.scheduled_action.insert(*machine, None);
                        state.scheduled_internal.insert(*machine, None);
                    }
                }
            }
            TriggerAction::SendPadding {
                timeout,
                bypass: _,
                replace: _,
                machine,
            } => {
                state.scheduled_action.insert(
                    *machine,
                    Some(ScheduledAction {
                        action: action.clone(),
                        time: *current_time + *timeout + trigger_delay,
                    }),
                );
            }
            TriggerAction::BlockOutgoing {
                timeout,
                duration: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                state.scheduled_action.insert(
                    *machine,
                    Some(ScheduledAction {
                        action: action.clone(),
                        time: *current_time + *timeout + trigger_delay,
                    }),
                );
            }
            TriggerAction::UpdateTimer {
                duration,
                replace,
                machine,
            } => {
                // get current internal timer duration, if any
                let current = state
                    .scheduled_internal
                    .get(machine)
                    .cloned()
                    .unwrap_or(Some(*current_time))
                    .unwrap();

                // update the timer
                if *replace || current < *current_time + *duration {
                    state
                        .scheduled_internal
                        .insert(*machine, Some(*current_time + *duration));
                    // TimerBegin event
                    sq.push_sim(
                        SimEvent {
                            client: is_client,
                            event: TriggerEvent::TimerBegin { machine: *machine },
                            time: *current_time,
                            delay: Duration::from_micros(0), // TODO: is this correct?
                            fuzz: fastrand::i32(..),
                            bypass: false,
                            replace: false,
                        },
                        Reverse(*current_time),
                    );
                }
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

pub fn parse_trace(trace: &str, network: &Network) -> SimQueue {
    parse_trace_advanced(trace, network, None, None)
}

pub fn parse_trace_advanced(
    trace: &str,
    network: &Network,
    client: Option<&Integration>,
    server: Option<&Integration>,
) -> SimQueue {
    let mut sq = SimQueue::new();

    // we just need a random starting time to make sure that we don't start from
    // absolute 0
    let starting_time = Instant::now();

    for l in trace.lines() {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() >= 2 {
            let timestamp =
                starting_time + Duration::from_nanos(parts[0].trim().parse::<u64>().unwrap());
            // let size = parts[2].trim().parse::<u64>().unwrap();

            match parts[1] {
                "s" | "sn" => {
                    // client sent at the given time
                    let reporting_delay = client
                        .map(|i| i.reporting_delay.sample())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = timestamp + reporting_delay;
                    // TODO: add queueing delay to subtract from parsed time
                    sq.push(
                        TriggerEvent::NormalQueued,
                        true,
                        reported,
                        reporting_delay,
                        Reverse(reported),
                    );
                }
                "r" | "rn" => {
                    // sent by server delay time ago
                    let sent = timestamp.checked_sub(network.delay).unwrap();
                    // but reported to the Maybenot framework at the server with delay
                    let reporting_delay = server
                        .map(|i| i.reporting_delay.sample())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = sent + reporting_delay;
                    // TODO: add queueing delay to subtract from parsed time
                    sq.push(
                        TriggerEvent::NormalQueued,
                        false,
                        reported,
                        reporting_delay,
                        Reverse(reported),
                    );
                }
                "sp" | "rp" => {
                    // TODO: figure out of ignoring is the right thing to do
                }
                _ => {
                    panic!("invalid direction")
                }
            }
        }
    }

    sq
}
