
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
use primitives::{EpochId, StorageLayout};

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

    assert_eq!(signal.get_signal_loc().address, address);
    assert_eq!(signal.get_signal_loc().signal_key, key);
}

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

    assert_eq!(slot.get_slot_loc().address, address);
    assert_eq!(slot.get_slot_loc().slot_key, key);
}

#[test]
fn slot_bind() {

}

#[test]
fn signal_emit() {

}

#[test]
fn slot_tx_distribution() {

}

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
