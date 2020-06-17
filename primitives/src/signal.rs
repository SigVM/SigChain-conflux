//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

use crate::{
    bytes::Bytes,
    hash::keccak,
};
use cfx_types::{Address, H256, U256};

// SignalLocation. Struct that keeps track of the location of a signal so that
// an account with a slot binded to a particular signal in another contract
// can find and access the SignalInfo struct.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct SignalLocation {
    address: Address,
    signal_key: Bytes,
}

impl SignalLocation {
    pub fn new(owner: &Address, signal_key: &[u8]) -> Self {
        let new = SignalLocation {
            address: owner.clone(),
            signal_key: Bytes::from(signal_key),
        };
        new
    }
}

// SlotInfo. Holds the information that the owner of the slot needs maintain.
// Whereas Slot is maintained by the owner of the signal that we binded to,
// SlotInfo is owned by the owner contract who implements the handler. As a
// result a few things are different, most notably, we need to keep a list
// of the signals this slot is binded to. 
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct SlotInfo {
    // Identifier. Used mainly to help detach or cleanup a slot.
    id: H256,
    // Pointer to the entry point of this slot.
    code_entry: U256,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
    // List of keys to the signals that this slot is binded to.
    bind_list: Vec::<SignalLocation>,
}

impl SlotInfo {
    // Create a new SlotInfo.
    pub fn new(
        owner: &Address, slot_key: &[u8], code_entry: U256, gas_limit: U256, numerator: U256, denominator: U256
    ) -> Self {
        // Create an id.
        let mut buffer = [0u8; 20 + 32];
        &mut buffer[..20].copy_from_slice(&owner[..]);
        &mut buffer[20..].copy_from_slice(&slot_key[..]);
        let h = keccak(&buffer[..]);

        let new = SlotInfo {
            id:                    h,
            code_entry:            code_entry,
            gas_limit:             gas_limit,
            gas_ratio_numerator:   numerator,
            gas_ratio_denominator: denominator,
            bind_list:             Vec::new(),
        };
        new
    }
    // Remove a signal from the bind list.
    pub fn remove_bind(loc: SignalLocation) {
        // Remove it from bind_list.
    }
}

// Slot. Holds the information that the signal needs to maintain. Helps in the creation of 
// construction of a Slot Transaction upon the emission of a signal. Although almost all
// information is derived from the SlotInfo, we need the address of the owner of the slot as
// well as a unique id to be provided. This id allows us to parse through the list of slots
// when we need to cleanup or delete entries.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct Slot {
    // Address of contract that owns this slot.
    owner: Address,
    // ID
    id: H256,
    // Pointer to the entry point of this slot.
    code_entry: U256,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
}

impl Slot {
    // Create a new slot out of a SlotInfo and Address. 
    pub fn new(slot_info: &SlotInfo, owner: &Address) -> Self {
        let new = Slot {
            owner:                 owner.clone(),
            id:                    slot_info.id.clone(),                   
            code_entry:            slot_info.code_entry.clone(),
            gas_limit:             slot_info.gas_limit.clone(),
            gas_ratio_numerator:   slot_info.gas_ratio_numerator.clone(),
            gas_ratio_denominator: slot_info.gas_ratio_denominator.clone(),
        };
        new
    }
}

// SignalInfo. Holds the mapping of a signal to a list of slots that are subscribed to it. This info
// is used when a signal is emitted. The list of slots is modified accodingly when a slot binds to it.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
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
    // Removes a slot given a location.
    pub fn remove_slot(id: H256) {
        // Remove the slot with the given id if it exists.
    }
}

// SlotTx. Transactions that execute a slot. It holds a slot as well as the block number for execution and
// the a vector of arguments passed in by the signal.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct SlotTx {
    // Slot to be executed.
    slot: Slot,
    // Block number of when this transaction becomes available for execution.
    block_num: U256,
    // Vector of arguments emitted by the signal.
    argv: Vec::<Bytes>,
}

impl SlotTx {
    pub fn new(
        slot: &Slot, block_num: U256, argv: Vec::<Bytes>
    ) -> Self {
        let new = SlotTx {
            slot:      slot.clone(),
            block_num: block_num,
            argv:      argv,
        };
        new
    }
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
