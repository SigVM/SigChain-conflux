//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

// Purpose of this source file is to define the global queue of slot transactions
// as well as provide helper functions for handling signal/slot state transitions.

// Global address that stores the trie containing all the future slot transactions
// that are not currently available for execution. This trie is pruned every epoch.
// When a new epoch starts, all the slot transactions that become available are
// pushed into the queues of individual accounts.

use primitives::signal::{SlotTx};
use cfx_types::{Address};
use std::str::FromStr;

lazy_static! {
    // Last 20 digits of keccak256(Boundless!!!)
    pub static ref GLOBAL_SLOT_TX_QUEUE: Address =
        Address::from_str("db73c9d8eeaac3e5de3f83b71fb7aa4e41764d09").unwrap();
}

// Below are functions that perform state transitions neccessary to facillitate signals
// and slots. Note that these functions write to a local in memory cache. These changes
// are then committed to state in account_entry.rs, alone with storage and ownership 
// changes. 

// Add a slot transaction to be executed at a future epoch number.
pub fn add_slot_tx_to_global_queue() {

}

// Prune a list of slot transactions indexed by the epoch number.
pub fn prune_slot_tx_list() -> Vec::<SlotTx> {
    Vec::new()
}

// Handle signal emission by generating and queueing slot transactions.
pub fn generate_and_queue_slot_tx() {

}

// Create a signal.
pub fn create_new_signal() {

}

// Delete a signal.
pub fn delete_signal() {

}

// Create a slot.
pub fn create_new_slot() {

}

// Delete a slot.
pub fn delete_slot() {

}

// Bind to a signal.
pub fn bind_to_signal() {

}

// Detach from a signal.
pub fn detach_from_signal() {

}

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
