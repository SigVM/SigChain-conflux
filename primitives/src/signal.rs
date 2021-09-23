//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

// This source file holds the primitive structures for implementing signals and slots.
// SignalLocation and SlotLocation describe unique locations on the state where information is stored.
// SignalInfo and SlotInfo holds the complete information about a signal or slot. This is maintained 
// by the contract account that owns them.
// Slot holds essential information neccessary to create a slot transactions. 
// These are stored in the signal slot_list.

use crate::{bytes::Bytes};
use cfx_types::{Address, U256, H256};
use serde::{Deserialize, Serialize};

// SignalLocation and SlotLocation.
// Structs that keeps track of the location of a signal or slot on the network.
// The two types are the same. We keep them seperate just for readability.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
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
    // Getters
    pub fn address(&self) -> &Address {
        &self.address
    }
    pub fn signal_key(&self) -> &Bytes {
        &self.signal_key
    }
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct SlotLocation {
    address: Address,
    slot_key: Bytes,
}
impl SlotLocation {
    pub fn new(owner: &Address, slot_key: &[u8]) -> Self {
        let new = SlotLocation {
            address: owner.clone(),
            slot_key: Bytes::from(slot_key),
        };
        new
    }
    // Getters
    pub fn address(&self) -> &Address {
        &self.address
    }
    pub fn slot_key(&self) -> &Bytes {
        &self.slot_key
    }
}

// SignalInfo. Holds the mapping of a signal to a list of slots that are subscribed to it. This info
// is used when a signal is emitted. The list of slots is modified accodingly when a slot binds to it.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct SignalInfo {
    location:  SignalLocation,
    slot_list: Vec::<Slot>,
}
impl SignalInfo {
    // Return an empty SignalInfo.
    pub fn new(owner: &Address, signal_key: &[u8]) -> Self {
        let new = SignalInfo {
            location:  SignalLocation::new(owner, signal_key),
            slot_list: Vec::new(),
        };
        new
    }
    // Bind a slot to this signal.
    pub fn add_to_slot_list(&mut self, slot_info: &SlotInfo) {
        let slot = Slot::new(slot_info);
        self.slot_list.push(slot);
    }
    // Removes a slot given a location.
    pub fn remove_from_slot_list(&mut self, loc: &SlotLocation) {
        for i in 0..self.slot_list.clone().len() {
            let slot = &self.slot_list[i];
            if slot.location().address() == loc.address() && slot.location().slot_key() == loc.slot_key() {
                self.slot_list.remove(i);
            }
        }
    }
    // Getters
    pub fn location(&self) -> &SignalLocation {
        &self.location
    }
    pub fn slot_list(&self) -> &Vec::<Slot> {
        &self.slot_list
    }
}

// SlotInfo. Holds the information that the owner of the slot needs maintain.
// Whereas Slot is maintained by the owner of the signal that we binded to,
// SlotInfo is owned by the owner contract who implements the handler. As a
// result a few things are different, most notably, we need to keep a list
// of the signals this slot is binded to.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct SlotInfo {
    // Location on the network. Used to identify this slot uniquely.
    location: SlotLocation,
    // Method hash. Hash of the method that this slot should execute.
    method_hash: H256,
    // Gas sponsor. External account that pays for execution of slot transactions for this slot.
    gas_sponsor: Address,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
    // List of keys to the signals that this slot is binded to.
    bind_list: Vec::<SignalLocation>,
    blk: bool, 
    sigroles: Vec<Address>, 
    sigmethods: Vec<H256>,
}
impl SlotInfo {
    // Create a new SlotInfo.
    pub fn new(
        owner: &Address, 
        slot_key: &[u8],
        method_hash: &H256, 
        gas_sponsor: &Address, 
        gas_limit: &U256, 
        gas_ratio: &U256,
        blk: &bool, 
        sigroles: &Vec<u8>, 
        sigmethods: &Vec<u8>,
    ) -> Self {
        let loc = SlotLocation::new(owner, slot_key);

        let mut sigroles_in_address: Vec<Address> = Vec::new();
        let mut sigmethods_in_address: Vec<H256> = Vec::new();
        if blk.clone() && !sigroles.clone().is_empty() {
            let mut i = 12;
            let mut sigroles_slice: [u8; 20] = [0u8; 20];
            while i < sigroles.clone().len() && (i + 19) < sigroles.clone().len(){
                let mut j = i;
                while j < i + 20 {
                    sigroles_slice[j-i] = sigroles.clone()[j];
                    j+=1;
                }
                sigroles_in_address.push(Address::from(sigroles_slice));
                i += 32;
            }
        }
        if blk.clone() && !sigmethods.clone().is_empty() {
            let mut i = 0;
            let mut sigmethods_slice: [u8; 32] = [0u8; 32];
            while i < sigmethods.clone().len() && (i + 31) < sigmethods.clone().len(){
                let mut j = i;
                while j < i + 32 {
                    sigmethods_slice[j-i] = sigmethods.clone()[j];
                    j+=1;
                }
                sigmethods_in_address.push(H256::from(sigmethods_slice));
                i += 32;
            }
        }
        let new = SlotInfo {
            location:              loc,
            method_hash:           method_hash.clone(),
            gas_sponsor:           gas_sponsor.clone(),
            gas_limit:             gas_limit.clone(),
            gas_ratio_numerator:   gas_ratio.clone(),
            gas_ratio_denominator: U256::from(100),
            bind_list:             Vec::new(),
            blk:                   blk.clone(), 
            sigroles:              sigroles_in_address.clone(), 
            sigmethods:            sigmethods_in_address.clone(),
        };
        new
    }
    // Add a signal to the bind list.
    pub fn add_to_bind_list(&mut self, loc: &SignalLocation) {
        let loc = loc.clone();
        self.bind_list.push(loc);
    }
    // Remove a signal from the bind list.
    pub fn remove_from_bind_list(&mut self, loc: &SignalLocation) {
        for i in 0..self.bind_list.clone().len() {
            let sig = &self.bind_list[i];
            if sig.address() == loc.address() && sig.signal_key() == loc.signal_key() {
                self.bind_list.remove(i);
            }
        }
    }
    // Getters
    pub fn location(&self) -> &SlotLocation {
        &self.location
    }
    pub fn gas_sponsor(&self) -> &Address {
        &self.gas_sponsor
    }
    pub fn gas_limit(&self) -> &U256 {
        &self.gas_limit
    }
    pub fn gas_ratio_numerator(&self) -> &U256 {
        &self.gas_ratio_numerator
    }
    pub fn gas_ratio_denominator(&self) -> &U256 {
        &self.gas_ratio_denominator
    }
    pub fn bind_list(&self) -> &Vec<SignalLocation> {
        &self.bind_list
    }
}

// Slot. Holds the information that the signal needs to maintain. Helps in the creation of
// construction of a Slot Transaction upon the emission of a signal. Although almost all
// information is derived from the SlotInfo, we need the address of the owner of the slot as
// well as a unique id to be provided. This id allows us to parse through the list of slots
// when we need to cleanup or delete entries.
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct Slot {
    // Location of original SlotInfo.
    location: SlotLocation,
    // Method hash. Hash of the method that this slot should execute.
    method_hash: H256,
    // Gas sponsor. External account that pays for execution of slot transactions for this slot.
    gas_sponsor: Address,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
    blk: bool, 
    sigroles: Vec<Address>, 
    sigmethods: Vec<H256>,
}
impl Slot {
    // Create a new slot out of a SlotInfo.
    pub fn new(slot_info: &SlotInfo) -> Self {
        let new = Slot {
            location:              slot_info.location.clone(),
            method_hash:           slot_info.method_hash.clone(),
            gas_sponsor:           slot_info.gas_sponsor.clone(),
            gas_limit:             slot_info.gas_limit.clone(),
            gas_ratio_numerator:   slot_info.gas_ratio_numerator.clone(),
            gas_ratio_denominator: slot_info.gas_ratio_denominator.clone(),
            blk:                   slot_info.blk.clone(), 
            sigroles:              slot_info.sigroles.clone(),
            sigmethods:            slot_info.sigmethods.clone(),
        };
        new
    }
    // Getters.
    pub fn location(&self) -> &SlotLocation {
        &self.location
    }
    pub fn method_hash(&self) -> &H256 {
        &self.method_hash
    }
    pub fn gas_sponsor(&self) -> &Address {
        &self.gas_sponsor
    }
    pub fn gas_limit(&self) -> &U256 {
        &self.gas_limit
    }
    pub fn gas_ratio_numerator(&self) -> &U256 {
        &self.gas_ratio_numerator
    }
    pub fn gas_ratio_denominator(&self) -> &U256 {
        &self.gas_ratio_denominator
    }
    // Returns the first 4 bytes of the method_hash. This forms the method ID in solidity ABI.
    pub fn get_method_id(&self) -> Bytes {
        self.method_hash()[0..4].to_vec()
    }
}

// Slot transaction struct. Includes all information needed to execute 
#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct SlotTx {
    // Address of contract that owns this slot.
    location: SlotLocation,
    // Method hash.
    method_hash: H256,
    // Gas sponsor.
    gas_sponsor: Address,
    // Gas limit for slot execution.
    gas_limit: U256,
    // Gas ratio for slot execution.
    gas_ratio_numerator: U256,
    gas_ratio_denominator: U256,
    // Block number of when this transaction becomes available for execution.
    epoch_height: u64,
    // Raw byte data emitted by the signal.
    raw_data: Bytes,
    // Gas price. Determined during packing.
    gas_price: U256,
    // Gas. Determined before packing.
    gas: U256,
    // Storage limit. Determined before packing.
    storage_limit: U256,
    blk: bool, 
    sigroles: Vec<Address>, 
    sigmethods: Vec<H256>,
}
impl SlotTx {
    pub fn new(
        slot: &Slot, epoch_height: &u64, raw_data: &Bytes,
    ) -> Self {
        let new = SlotTx {
            // Cloned from slot.
            location:              slot.location().clone(),
            method_hash:           slot.method_hash.clone(),
            gas_sponsor:           slot.gas_sponsor.clone(),
            gas_limit:             slot.gas_limit.clone(),
            gas_ratio_numerator:   slot.gas_ratio_numerator().clone(),
            gas_ratio_denominator: slot.gas_ratio_denominator.clone(),
            // Dependant on the signal emitted.
            epoch_height:          epoch_height.clone(),
            raw_data:              raw_data.clone(),
            // Gas price is set when packed in the transaction pool.
            gas_price:             U256::zero(),
            gas:                   U256::zero(),
            storage_limit:         U256::zero(),
            blk:                   slot.blk.clone(), 
            sigroles:              slot.sigroles.clone(),
            sigmethods:            slot.sigmethods.clone(),
        };
        new
    }
    // Getters
    pub fn location(&self) -> &SlotLocation {
        &self.location
    }
    pub fn address(&self) -> &Address {
        &self.location.address()
    }
    pub fn slot_key(&self) -> &Bytes {
        &self.location.slot_key()
    }
    pub fn method_hash(&self) -> &H256 {
        &self.method_hash
    }
    pub fn gas_sponsor(&self) -> &Address {
        &self.gas_sponsor
    }
    pub fn gas_limit(&self) -> &U256 {
        &self.gas_limit
    }
    pub fn gas_ratio_numerator(&self) -> &U256 {
        &self.gas_ratio_numerator
    }
    pub fn gas_ratio_denominator(&self) -> &U256 {
        &self.gas_ratio_denominator
    }
    pub fn epoch_height(&self) -> u64 {
        self.epoch_height
    }
    pub fn raw_data(&self) -> &Bytes {
        &self.raw_data
    }
    pub fn gas_price(&self) -> &U256 {
        &self.gas_price
    }
    pub fn gas(&self) -> &U256 {
        &self.gas
    }
    pub fn storage_limit(&self) -> &U256 {
        &self.storage_limit
    }
    pub fn blk(&self) -> &bool {
        &self.blk
    }
    pub fn sigroles(&self) -> &Vec<Address> {
        &self.sigroles
    }
    pub fn sigmethods(&self) -> &Vec<H256> {
        &self.sigmethods
    }
    // Check if two slot transactions are identical.
    pub fn is_duplicated(&self, tx: &SlotTx) -> bool {
        self.location == *tx.location() && self.raw_data == tx.raw_data().clone()
        && self.epoch_height == tx.epoch_height()
    }

    // For robustness, we keep encoding and decoding to a minimum in the rust implementation.
    // All we do for data encoding is prepend the first 4 bytes of the method_hash onto the
    // raw_data. We trust that argument processing on the solidity side has already encoded 
    // the function arguments into proper ABI format.
    pub fn get_encoded_data(&self) -> Bytes {
        let mut buffer = self.method_hash()[0..4].to_vec().clone();
        buffer.extend_from_slice(&self.raw_data[..]);
        buffer
    }
    // Called in the transaction pool during transaction packing.
    pub fn calculate_and_set_gas_price(&mut self, average_gas_price: &U256) {
        self.gas_price = average_gas_price * self.gas_ratio_numerator / self.gas_ratio_denominator;
    }
    // Set gas.
    pub fn set_gas(&mut self, gas: U256) {
        self.gas = gas;
    }
    // Set storage limit.
    pub fn set_storage_limit(&mut self, storage_limit: U256) {
        self.storage_limit = storage_limit;
    }
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
