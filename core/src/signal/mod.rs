
// Implementation of signal module.

use crate::{
    hash::keccak,
};

use cfx_types::{Address, H256, U256};
//use std::vec::Vec;

pub struct Signal {
    // Identifier for the signal.
    id: H256,
    // Address of contract that owns this signal.
    owner: Address,
    // Number of data arguments expected.
    argc: U256, 
}

impl Signal {
    pub fn new(owner: &Address, sig_list: &Vec::<H256>, argc: U256) -> Self {
        // Buffer used for id creation.
        let mut buffer = [0u8; 20 + 32];
        // Last id in sig_list.
        let last_sig = sig_list.last();

        // Create a new id using owner address and the last item of the sig_list.
        &mut buffer[..20].copy_from_slice(&owner[..]);
        if let Some(sig) = last_sig {
            &mut buffer[20..].copy_from_slice(&sig[..]);
        } else {
            let sig = H256::zero();
            &mut buffer[20..].copy_from_slice(&sig[..]);
        }
        let h = keccak(&buffer[..]);

        let new_signal = Signal {
            id: h,
            owner: owner.clone(),
            argc: argc,
        };

        new_signal
    }
}

pub struct Slot {
    // Address of contract that owns this slot.
    owner: Address,
    // Pointer to the entry point of this slot.
    code_entry: U256,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    // TODO: How to use floating point numbers for ratios? Do we need an implementation of fixed point U256 numbers?
}

impl Slot {
    pub fn new(owner: &Address, code_entry: U256, gas_limit: U256) -> Self {
        let new_slot = Slot {
            owner: owner.clone(),
            code_entry: code_entry,
            gas_limit: gas_limit,
        };

        new_slot
    }
}

pub struct SlotTx<'a> {
    // Signal that was emitted.
    sig: &'a Signal,
    // Slot that responds to the signal.
    slot: &'a Slot,
    // Block number of when this transaction becomes available for execution.
    block_num: U256,
    // Vector of arguments emitted with the signal.
    argv: Vec::<U256>,
}

impl<'a> SlotTx<'a> {
    pub fn new(
        sig: &'a Signal, slot: &'a Slot, 
        block_num: U256, argv: Vec::<U256>
    ) -> Self {
        let new_st = SlotTx {
            sig,
            slot,
            block_num,
            argv,
        };

        new_st
    }
}
