//! For simulating network activity: sending and receiving packets between the
//! client and server.

use std::{
    cmp::Reverse,
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{event::Event, framework::TriggerEvent};

use crate::{queue::SimQueue, SimEvent, SimState};

/// The network replace window is the time window in which we can replace
/// padding with existing padding or non-padding already queued (or about to be
/// queued up). The behavior here is tricky, since it'll differ how different
/// implementations handle it.
const NETWORK_REPLACE_WINDOW: Duration = Duration::from_micros(1);

// For (non-)padding sent, queue the corresponding padding recv event: in other
// words, where we simulate sending packets. The block below is actually the
// only place where the simulator simulates the entire network between the
// client and the server. Returns true if a (non-)padding packet was sent or
// received (i.e., there was network activity), false otherwise.
pub fn sim_network_activity(
    next: &SimEvent,
    sq: &mut SimQueue,
    state: &SimState,
    current_time: Instant,
    delay: Duration,
) -> bool {
    let side = if next.client { "client" } else { "server" }.to_string();

    match next.event {
        // easy: queue up the recv event on the other side
        TriggerEvent::NonPaddingSent { bytes_sent } => {
            debug!("\tqueue {}", Event::NonPaddingRecv);
            // TODO: make the network more than a delay!
            let time = current_time + delay;
            sq.push(
                TriggerEvent::NonPaddingRecv {
                    bytes_recv: bytes_sent,
                },
                !next.client,
                time,
                Reverse(time),
            );

            return true;
        }
        TriggerEvent::PaddingSent { bytes_sent, .. } => {
            if next.replace {
                // This is where it gets tricky: we MAY replace the padding with
                // existing padding or non-padding already queued (or about to
                // be queued up). The behavior here is tricky, since it'll
                // differ how different implementations handle it. We take a
                // conservative approach here and do not consider looking for
                // non-padding of a smaller size (that could be padded up to the
                // size of the padding we're about to send). Note that replacing
                // is the same as skipping to queue the padding recv event
                // below.

                // check if we can replace with last sent up to the network
                // replace window: this probably poorly simulates an egress
                // queue where it takes up to 1us to send the packet
                debug!(
                    "\treplace with earlier? {:?} <= {:?}",
                    next.time.duration_since(state.last_sent_time),
                    NETWORK_REPLACE_WINDOW
                );
                if next.time.duration_since(state.last_sent_time) <= NETWORK_REPLACE_WINDOW
                    && state.last_sent_size == bytes_sent
                {
                    debug!("replacing padding sent with last sent @{}", side);
                    return false;
                }

                // can replace with what's queued to be sent within the network
                // replace window?
                if let Some((queued, _)) = sq.peek_blocking(state.blocking_bypassable, next.client)
                {
                    debug!(
                        "\treplace with queued? {:?} <= {:?}",
                        queued.time.duration_since(next.time),
                        NETWORK_REPLACE_WINDOW
                    );
                    if queued.client == next.client
                        && queued.time.duration_since(next.time) <= NETWORK_REPLACE_WINDOW
                    {
                        match queued.event {
                            TriggerEvent::PaddingSent {
                                bytes_sent: queued_bytes_sent,
                                ..
                            } => {
                                if queued_bytes_sent == bytes_sent {
                                    debug!("replacing padding sent with queued padding @{}", side);
                                    return false;
                                }
                            }
                            TriggerEvent::NonPaddingSent {
                                bytes_sent: queued_bytes_sent,
                            } => {
                                if queued_bytes_sent == bytes_sent {
                                    debug!(
                                        "replacing padding sent with queued non-padding @{}",
                                        side
                                    );
                                    return false;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // nothing to replace with (or we're not replacing), so queue up
            debug!("\tqueue {}", Event::PaddingRecv);
            let time = current_time + delay;
            sq.push(
                TriggerEvent::PaddingRecv {
                    bytes_recv: bytes_sent,
                },
                !next.client,
                time,
                Reverse(time),
            );

            return true;
        }
        // receiving (non-)padding is reciving a packet
        TriggerEvent::NonPaddingRecv { .. } | TriggerEvent::PaddingRecv { .. } => true,
        _ => false,
    }
}