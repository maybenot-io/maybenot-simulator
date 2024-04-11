//! For simulating the network stack and network between client and server.

use std::{
    cmp::{max, Reverse},
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{event::Event, event::TriggerEvent, machine::Machine};

use crate::{queue::SimQueue, SimEvent, SimState};

/// A model of the network between the client and server.
#[derive(Debug, Clone)]
pub struct Network {
    pub delay: Duration,
}

impl Network {
    pub fn new(delay: Duration) -> Self {
        Self { delay }
    }

    pub fn sample(&self) -> Duration {
        self.delay
    }
}

/// The network replace window is the time window in which we can replace
/// padding with existing padding or normal packets already queued (or about to
/// be queued up). The behavior here is tricky, since it'll differ how different
/// implementations handle it.
const NETWORK_REPLACE_WINDOW: Duration = Duration::from_micros(1);

// This is the only place where the simulator simulates the entire network
// between the client and the server.
//
// Queued normal or padding packets create the corresponding sent packet events.
// Here, we could simulate the egress queue of the network stack. We assume that
// it is always possible to turn a queued packet into a sent packet, but that
// sending a packet can be blocked (dealt with by the simulation of blocking in
// the main loop of the simulator).
//
// For sending a normal packet, we queue the corresponding recv event on the
// other side, simulating the network up until the point where the packet is
// received. We current do not have a receiver-side queue. TODO?
//
// For sending padding, in principle we treat it like a normal packet, but we
// need to consider the replace flag.
//
// Returns true if there was network activity (i.e., a packet was sent or
// received), false otherwise.
pub fn sim_network_stack<M: AsRef<[Machine]>>(
    next: &SimEvent,
    sq: &mut SimQueue,
    state: &SimState<M>,
    recipient: &SimState<M>,
    network: &Network,
    current_time: &Instant,
) -> bool {
    let side = if next.client { "client" } else { "server" }.to_string();

    match next.event {
        // here we simulate the queueing of packets
        TriggerEvent::NormalQueued => {
            debug!("\tqueue {}", Event::NormalSent);
            // TODO: queuing delay
            sq.push(
                TriggerEvent::NormalSent,
                next.client,
                next.time,
                next.delay,
                Reverse(next.time),
            );
            false
        }
        // here we simulate the queueing of packets
        TriggerEvent::PaddingQueued { .. } => {
            debug!("\tqueue {}", Event::PaddingSent);
            // TODO: queuing delay
            sq.push_sim(
                SimEvent {
                    event: TriggerEvent::PaddingSent,
                    time: next.time,
                    delay: next.delay,
                    client: next.client,
                    // we need to copy the bypass and replace flags, unlike for
                    // normal queued above
                    bypass: next.bypass,
                    replace: next.replace,
                    fuzz: next.fuzz,
                },
                Reverse(next.time),
            );
            false
        }
        // easy: queue up the recv event on the other side
        TriggerEvent::NormalSent => {
            debug!("\tqueue {}", Event::NormalRecv);
            // The time the event was reported to us is in next.time. We have to
            // remove the reporting delay locally, then add a network delay and
            // a reporting delay (at the recipient) for the recipient.
            //
            // LIMITATION, we also have to deal with an ugly edge-case: if the
            // reporting delay is very long *at the sender*, then the event can
            // actually arrive earlier at the recipient than it was reported to
            // the sender. This we cannot deal with in the current design of the
            // simulator (support for integration delays was bolted on late),
            // because it would move time backwards. Therefore, we clamp.
            let reporting_delay = recipient.reporting_delay();
            let reported = max(
                next.time - next.delay + network.sample() + reporting_delay,
                *current_time,
            );
            sq.push(
                TriggerEvent::NormalRecv,
                !next.client,
                reported,
                reporting_delay,
                Reverse(reported),
            );

            true
        }
        TriggerEvent::PaddingSent => {
            if next.replace {
                // This is where it gets tricky: we MAY replace the padding with
                // existing padding or a normal packet already queued (or about
                // to be queued up). The behavior here is tricky, since it'll
                // differ how different implementations handle it. Note that
                // replacing is the same as skipping to queue the padding recv
                // event below.

                // check if we can replace with last sent up to the network
                // replace window: this probably poorly simulates an egress
                // queue where it takes up to 1us to send the packet
                debug!(
                    "\treplace with earlier? {:?} <= {:?}",
                    next.time.duration_since(state.last_sent_time),
                    NETWORK_REPLACE_WINDOW
                );
                if next.time.duration_since(state.last_sent_time) <= NETWORK_REPLACE_WINDOW {
                    debug!("replacing padding sent with last sent @{}", side);
                    return false;
                }

                // can replace with normal that's queued to be sent within the
                // network replace window? FIXME: here be bugs related to
                // integration delays. Once blocking is implemented, this code
                // needs to be reworked.
                let peek = sq.peek_blocking(state.blocking_bypassable, next.client);
                if let Some((queued, _)) = peek {
                    let queued = queued.clone();
                    debug!(
                        "\treplace with queued? {:?} <= {:?}",
                        queued.time.duration_since(next.time),
                        NETWORK_REPLACE_WINDOW
                    );
                    if queued.client == next.client
                        && queued.time.duration_since(next.time) <= NETWORK_REPLACE_WINDOW
                        && TriggerEvent::NormalSent == queued.event
                    {
                        debug!("replacing padding sent with queued normal @{}", side,);
                        // let the NormalSent event bypass
                        // blocking by making a copy of the event
                        // with the appropriate flags set
                        let mut tmp = queued.clone();
                        tmp.bypass = true;
                        tmp.replace = false;
                        // we send the NormalSent now since it is queued
                        tmp.time = next.time;
                        // we need to remove and push, because we
                        // change flags and potentially time, which
                        // changes the priority
                        sq.remove(&queued);
                        sq.push_sim(tmp.clone(), Reverse(tmp.time));
                        return false;
                    }
                }
            }

            // nothing to replace with (or we're not replacing), so queue up
            debug!("\tqueue {}", Event::PaddingRecv);
            let reporting_delay = recipient.reporting_delay();
            // action delay + network + recipient reporting delay
            let reported = next.time + next.delay + network.sample() + reporting_delay;
            sq.push(
                TriggerEvent::PaddingRecv,
                !next.client,
                reported,
                reporting_delay,
                Reverse(reported),
            );

            true
        }
        // receiving a packet is network activity
        TriggerEvent::NormalRecv | TriggerEvent::PaddingRecv => true,
        // all other events are not network activity
        _ => false,
    }
}
