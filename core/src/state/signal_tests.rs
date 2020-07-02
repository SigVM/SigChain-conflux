
//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

// A collection of tests for signals and slots in the state.
// Makes sure that creation, bind, and emit, as well queueing of slot transactions
// works as planned.
// Unused imports will be cleaned up later when the tests are all written.

#[allow(unused_imports)]
use super::{CleanupMode, CollateralCheckResult, State, Substate};

#[allow(unused_imports)]
use crate::{
    parameters::staking::*,
    statedb::StateDb,
    storage::{
        tests::new_state_manager_for_unit_test, StateIndex, StorageManager,
        StorageManagerTrait,
    },
    vm::Spec,
    vm_factory::VmFactory,
    state::state_tests::get_state,
    state::state_tests::get_state_for_genesis_write,
    state::state_tests::u256_to_vec,
};
#[allow(unused_imports)]
use cfx_types::{address_util::AddressUtil, Address, BigEndianHash, U256};
#[allow(unused_imports)]
use primitives::{EpochId, StorageLayout, SignalLocation, SlotLocation};

// Create a signal and check if its found in cache.
#[test]
fn signal_creation() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    address.set_contract_type_bits();
    let argc = U256::from(5);
    let key = vec![0x41u8, 0x42u8, 0x43u8];

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&address, &key, &argc)
        .expect("Signal creation should not fail.");

    let signal = state.signal_at(&address, &key)
                      .expect("Signal should exist.")
                      .unwrap();

    assert_eq!(*signal.location().address(), address);
    assert_eq!(*signal.location().signal_key(), key);
}

// Create a slot and check if its in cache.
#[test]
fn slot_creation() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    address.set_contract_type_bits();

    let key = vec![0x31u8, 0x32u8, 0x33u8];
    let argc = U256::from(3);
    let entry = Address::zero();
    let gas_limit = U256::from(1000);
    let numerator = U256::from(3);
    let denominator = U256::from(2);

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&address, &key, &argc, &entry, &gas_limit, &numerator, &denominator)
        .expect("Slot creation should not fail.");

    let slot = state.slot_at(&address, &key)
                      .expect("Slot should exist.")
                      .unwrap();

    assert_eq!(*slot.location().address(), address);
    assert_eq!(*slot.location().slot_key(), key);
}

// Create two contract accounts, one with a signal and one with a slot.
// Bind the slot to the signal and check if lists are updated correctly.
// Detach the slot from the signal and check if lists are updated correctly.
#[test]
fn slot_bind_and_detach() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut emitter = Address::from_low_u64_be(1);
    let mut listener = Address::from_low_u64_be(2);
    emitter.set_contract_type_bits();
    listener.set_contract_type_bits();

    // Information to initialize signal.
    let sig_argc = U256::from(3);
    let sig_key = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_loc = SignalLocation::new(&emitter, &sig_key);

    // Information to initialize slot.
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let slot_argc = U256::from(3);
    let entry = Address::zero();
    let gas_limit = U256::from(1000);
    let numerator = U256::from(3);
    let denominator = U256::from(2);
    let slot_loc = SlotLocation::new(&listener, &slot_key);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key, &sig_argc)
        .expect("Signal creation should not fail.");
    // Create slot.
    state
        .new_contract(&listener, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener, &slot_key, &slot_argc, &entry, &gas_limit, &numerator, &denominator)
        .expect("Slot creation should not fail.");
    // Bind slot to signal.
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc)
        .expect("Bind should not fail.");
    
    // Check to see if signal info is correct.
    let sig = state  
                .signal_at(&emitter, &sig_key)
                .expect("Signal info retrieval should not fail")
                .unwrap();
    let slot = sig.slot_list().last().unwrap().clone();
    assert_eq!(*slot.location(), slot_loc);
    assert_eq!(*slot.gas_limit(), gas_limit);

    // Check to see if slot info is correct.
    let slot = state
                .slot_at(&listener, &slot_key)
                .expect("Slot info retrieval should not fail")
                .unwrap();
    let sig = slot.bind_list().last().unwrap().clone();
    assert_eq!(sig, sig_loc);

    // Detach slot from signal.
    state
        .detach_slot_from_signal(&sig_loc, &slot_loc)
        .expect("Detach should not fail.");
   
    // Check to see if signal info is correct.
    let sig = state  
        .signal_at(&emitter, &sig_key)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert!(sig.slot_list().is_empty());

    // Check to see if slot info is correct.
    let slot = state
            .slot_at(&listener, &slot_key)
            .expect("Slot info retrieval should not fail")
            .unwrap();
    assert!(slot.bind_list().is_empty());
}

// Test to see if signal emission works as intended.

#[test]
fn signal_emit() {

}

#[test]
fn slot_tx_distribution() {

}

#[test]
fn checkpoint_signal_and_slots() {

}

#[test]
fn commit_signal_and_slots() {

}

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
