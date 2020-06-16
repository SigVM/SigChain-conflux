// Implementation of signal module.
use crate::{
    hash::keccak,
};
use cfx_types::{Address, H256, U256};

// Slot
#[derive(
    Debug, Clone,
)]
pub struct Slot {
    // Address of contract that owns this slot.
    owner: Address,
    // Pointer to the entry point of this slot.
    code_entry: U256,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
}

impl Slot {
    pub fn new(owner: &Address, code_entry: U256, gas_limit: U256, numerator: U256, denominator: U256) -> Self {
        let new_slot = Slot {
            owner: owner.clone(),
            code_entry: code_entry,
            gas_limit: gas_limit,
            gas_ratio_numerator: numerator,
            gas_ratio_denominator: denominator,
        };
        new_slot
    }
}

// SignalInfo
// TODO: Make this encodable?
pub struct SignalInfo {
    arg_count: U256,
    slot_list: Vec::<Slot>,
}

impl SignalInfo {
    // Return a fresh SignalInfo.
    pub fn new(arg_count: U256) -> Self {
        let new = SignalInfo {
            arg_count: arg_count,
            slot_list: Vec::new(),
        };
        new
    }
}

// SlotTx
// TODO: Make this encodable?
#[derive(Debug)]
pub struct SlotTx {
    // Slot to be executed.
    slot: Slot,
    // Block number of when this transaction becomes available for execution.
    block_num: U256,
    // Vector of arguments emitted by the signal.
    argv: Vec::<U256>,
}

impl SlotTx {
    pub fn new(
        slot: &Slot, block_num: U256, argv: Vec::<U256>
    ) -> Self {
        let new_st = SlotTx {
            slot: slot.clone(),
            block_num: block_num,
            argv: argv,
        };

        new_st
    }
}
