
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
use cfx_types::{address_util::AddressUtil, Address, BigEndianHash, U256, H256};
#[allow(unused_imports)]
use primitives::{EpochId, StorageLayout, SignalLocation, SlotLocation};

// Create a signal and check if its found in cache.
#[test]
fn signal_creation() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    address.set_contract_type_bits();
    let key = vec![0x41u8, 0x42u8, 0x43u8];

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&address, &key)
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
    let gas_sponsor = address;
    address.set_contract_type_bits();
    let method_hash = H256::zero();
    let key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&address, &key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    let slot = state.slot_at(&address, &key)
        .expect("Slot should exist.")
        .unwrap();

    assert_eq!(*slot.location().address(), address);
    assert_eq!(*slot.location().slot_key(), key);
}

// Multiple slot creation test
// note: we are allowing this as CREATESLOT and BINDSLOT are now combined on the front-end
#[test]
fn multi_slot_creation() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    let gas_sponsor = address;
    address.set_contract_type_bits();
    let method_hash = H256::zero();
    let key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&address, &key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    state
        .create_slot(&address, &key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Duplicated slot creation should not fail.");

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

    // Information to initialize signal.
    let mut emitter = Address::from_low_u64_be(1);
    emitter.set_contract_type_bits();
    let sig_key = vec![0x41u8, 0x42u8, 0x43u8];

    // Information to initialize slot.
    let mut listener = Address::from_low_u64_be(2);
    let gas_sponsor = listener;
    listener.set_contract_type_bits();
    let method_hash = H256::zero();
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key)
        .expect("Signal creation should not fail.");
    // Create slot.
    state
        .new_contract(&listener, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener, &slot_key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");
    // Signal and slot location.
    let sig_loc = SignalLocation::new(&emitter, &sig_key);
    let slot_loc = SlotLocation::new(&listener, &slot_key);
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
    // after merging DETACH and DELETE, the slot should be gone by now
    let slot = state
            .slot_at(&listener, &slot_key)
            .expect("Slot info retrieval should not fail");
    assert!(slot.is_none());
}

// Tests to see if signal emission works as intended.
// Create a emitter contract account as well as several listeners.
// Emit once with zero delay and look into each of slot transaction queues.
// Emit another time with a delay to queue slot transactions into the global slot transaction queue.
// Drain from the global slot transaction queue and bring them to individual account slot transaction queues.
// Dequeue the account slot transaction queues and check if the ordering is correct.
#[test]
fn signal_emit_and_slot_tx_distribution_no_delay() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut emitter = Address::from_low_u64_be(1);
    let mut listener1 = Address::from_low_u64_be(2);
    let mut listener2 = Address::from_low_u64_be(3);
    let slot_owner1 = listener1;
    let slot_owner2 = listener2;
    emitter.set_contract_type_bits();
    listener1.set_contract_type_bits();
    listener2.set_contract_type_bits();

    // Information to initialize signal.
    let sig_key = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_loc = SignalLocation::new(&emitter, &sig_key);
    let sig_data1 = vec![0x01u8, 0x02u8, 0x03u8];

    // Information to initialize slot.
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let method_hash = H256::zero();
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);
    let slot_loc_1 = SlotLocation::new(&listener1, &slot_key);
    let slot_loc_2 = SlotLocation::new(&listener2, &slot_key);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key)
        .expect("Signal creation should not fail.");

    // Create slot 1.
    state
        .new_contract(&listener1, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener1, &slot_key, &method_hash, &slot_owner1, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Create slot 2.
    state
        .new_contract(&listener2, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener2, &slot_key, &method_hash, &slot_owner2, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Bind slots to signal.
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_1)
        .expect("Bind 1 should not fail.");
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_2)
        .expect("Bind 2 should not fail.");

    // Emit the signal.
    state
        .emit_signal_and_queue_slot_tx(&sig_loc, 0, 0, &sig_data1,)
        .expect("Emit signal should not fail.");

    // Check slot transaction queues.
    let queue = state
        .get_account_slot_tx_queue(&listener1)
        .expect("Getting account queue should not fail");
    let slot_tx = queue.peek(0).unwrap().clone();
    assert_eq!(*slot_tx.address(), listener1);

    let queue = state
        .get_account_slot_tx_queue(&listener2)
        .expect("Getting account queue should not fail");
    let slot_tx = queue.peek(0).unwrap().clone();
    assert_eq!(*slot_tx.address(), listener2);

    // Check address list with ready slot tx
    check_address_list(2, &mut state);
}

#[test]
fn signal_emit_and_slot_tx_distribution_with_delay() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut emitter = Address::from_low_u64_be(1);
    let mut listener1 = Address::from_low_u64_be(2);
    let mut listener2 = Address::from_low_u64_be(3);
    let slot_owner1 = listener1;
    let slot_owner2 = listener2;
    emitter.set_contract_type_bits();
    listener1.set_contract_type_bits();
    listener2.set_contract_type_bits();

    // Information to initialize signal.
    let sig_key = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_loc = SignalLocation::new(&emitter, &sig_key);
    let sig_data1 = vec![0x01u8, 0x02u8, 0x03u8];
    let sig_data2 = vec![0x09u8, 0x08u8, 0x07u8];

    // Information to initialize slot.
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let method_hash = H256::zero();
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);
    let slot_loc_1 = SlotLocation::new(&listener1, &slot_key);
    let slot_loc_2 = SlotLocation::new(&listener2, &slot_key);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key)
        .expect("Signal creation should not fail.");

    // Create slot 1.
    state
        .new_contract(&listener1, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener1, &slot_key, &method_hash, &slot_owner1, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Create slot 2.
    state
        .new_contract(&listener2, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener2, &slot_key, &method_hash, &slot_owner2, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Bind slots to signal.
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_1)
        .expect("Bind should not fail.");
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_2)
        .expect("Bind should not fail.");

    // Emit signal with delay.
    state
        .emit_signal_and_queue_slot_tx(&sig_loc, 0, 1, &sig_data1)
        .expect("Emit signal should not fail.");

    // Make sure queues have no element.
    let queue = state
        .get_account_slot_tx_queue(&listener1)
        .expect("Getting account queue should not fail");
    assert!(queue.is_empty());

    let queue = state
        .get_account_slot_tx_queue(&listener2)
        .expect("Getting account queue should not fail");
    assert!(queue.is_empty());

    check_address_list(0, &mut state);

    // Drain the global slot tx queue.
    state
        .drain_global_slot_tx_queue(1)
        .expect("Global slot tx queue drain should not fail.");

    // Make sure queues now have 1 elements.
    let queue = state
        .get_account_slot_tx_queue(&listener1)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 1);

    let queue = state
        .get_account_slot_tx_queue(&listener2)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 1);

    check_address_list(2, &mut state);

    // Emit another Signal.
    state
        .emit_signal_and_queue_slot_tx(&sig_loc, 0, 0, &sig_data2)
        .expect("Emit signal should not fail.");

    // Dequeue both slot transactions and make sure the ordering is correct.
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener1)
        .expect("Dequeue 1 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data1);
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener1)
        .expect("Dequeue 2 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data2);

    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener2)
        .expect("Dequeue 1 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data1);
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener2)
        .expect("Dequeue 2 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data2);

    // Ready slot tx address list should have 0 entry.
    check_address_list(0, &mut state);
}

// Test to see if commit actually writes to the storage db or not.
// We will commit a bunch of changes to the following: account signal info,
// account slot info, account slot tx queue, and global slot tx queue.
#[test]
fn commit_signal_and_slots() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut emitter = Address::from_low_u64_be(1);
    let mut listener1 = Address::from_low_u64_be(2);
    let mut listener2 = Address::from_low_u64_be(3);
    let slot_owner1 = listener1;
    let slot_owner2 = listener2;
    emitter.set_contract_type_bits();
    listener1.set_contract_type_bits();
    listener2.set_contract_type_bits();

    // Information to initialize signal.
    let sig_key = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_loc = SignalLocation::new(&emitter, &sig_key);
    let sig_data1 = vec![0x01u8, 0x02u8, 0x03u8];
    let sig_data2 = vec![0x09u8, 0x08u8, 0x07u8];

    // Information to initialize slot.
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let method_hash = H256::zero();
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);
    let slot_loc_1 = SlotLocation::new(&listener1, &slot_key);
    let slot_loc_2 = SlotLocation::new(&listener2, &slot_key);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key,)
        .expect("Signal creation should not fail.");

    // Create slot 1.
    state
        .new_contract(&listener1, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener1, &slot_key, &method_hash, &slot_owner1, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Create slot 2.
    state
        .new_contract(&listener2, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener2, &slot_key, &method_hash, &slot_owner2, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    // Bind slots to signal.
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_1)
        .expect("Bind should not fail.");
    state
        .bind_slot_to_signal(&sig_loc, &slot_loc_2)
        .expect("Bind should not fail.");

    // Emit the signal.
    state
        .emit_signal_and_queue_slot_tx(&sig_loc, 0, 0, &sig_data1)
        .expect("Emit signal should not fail.");

    // Emit signal again, but with delay.
    state
        .emit_signal_and_queue_slot_tx(&sig_loc, 0, 1, &sig_data2)
        .expect("Emit signal should not fail.");

    // Commit these changes.
    state
        .commit(BigEndianHash::from_uint(&U256::from(1u64)), None)
        .unwrap();

    // Clear the state caches.
    state.clear();

    // Load up signal and slot info.
    let sig = state
        .signal_at(&emitter, &sig_key)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert_eq!(sig.slot_list().len(), 2);

    let slot = state
        .slot_at(&listener1, &slot_key)
        .expect("Slot info retrieval should not fail")
        .unwrap();
    assert_eq!(slot.bind_list().len(), 1);

    // Make sure account queues still have 1 element.
    let queue = state
        .get_account_slot_tx_queue(&listener1)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 1);

    let queue = state
        .get_account_slot_tx_queue(&listener2)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 1);

    // Ready slot tx address list should still have 2 entries.
    check_address_list(2, &mut state);

    // Drain then dequeue, similar to the previous test.
    state
        .drain_global_slot_tx_queue(1)
        .expect("Global slot tx queue drain should not fail.");

    // Make sure queues now have 2 elements.
    let queue = state
        .get_account_slot_tx_queue(&listener1)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 2);

    let queue = state
        .get_account_slot_tx_queue(&listener2)
        .expect("Getting account queue should not fail");
    assert_eq!(queue.len(), 2);

    // Dequeue both slot transactions and make sure the ordering is correct.
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener1)
        .expect("Dequeue 1 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data1);
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener1)
        .expect("Dequeue 2 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data2);

    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener2)
        .expect("Dequeue 1 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data1);
    let slot_tx = state
        .dequeue_slot_tx_from_account(&listener2)
        .expect("Dequeue 2 should not fail.")
        .unwrap();
    assert_eq!(slot_tx.raw_data().clone(), sig_data2);

    // Ready slot tx address list should have no address.
    check_address_list(0, &mut state);
}

#[test]
fn checkpoint_signal_and_slots() {

}

fn check_address_list(len : usize, state : &mut State) {
    let addresses = state.get_cached_addresses_with_ready_slot_tx()
                         .expect("get_cached_addresses_with_ready_slot_tx should not fail.");
    assert_eq!(addresses.len(), len);
}

#[test]
fn ready_slot_tx_addresses_test() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let address_1 = Address::from_low_u64_be(1);
    let address_2 = Address::from_low_u64_be(2);
    let address_3 = Address::from_low_u64_be(3);

    check_address_list(0, &mut state);

    // insert one address
    state.mark_address_with_ready_slot_tx(&address_1)
         .expect("mark_address_with_ready_slot_tx should not fail.");
    check_address_list(1, &mut state);

    // duplicate insert
    state.mark_address_with_ready_slot_tx(&address_1)
         .expect("mark_address_with_ready_slot_tx should not fail.");
    check_address_list(1, &mut state);

    // insert two addresses
    state.mark_addresses_with_ready_slot_tx(vec![address_2, address_3])
         .expect("mark_addresses_with_ready_slot_tx should not fail.");
    check_address_list(3, &mut state);

    // remove one address
    state.remove_address_with_ready_slot_tx(&address_1)
         .expect("mark_address_with_ready_slot_tx should not fail.");
    check_address_list(2, &mut state);

    // commit these changes
    state
        .commit(BigEndianHash::from_uint(&U256::from(1u64)), None)
        .unwrap();

    // insert one address
    state.mark_address_with_ready_slot_tx(&address_1)
         .expect("mark_address_with_ready_slot_tx should not fail.");
    check_address_list(3, &mut state);

}

#[test]
fn ready_slot_tx_addresses_cache_test() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);

    let set = state.check_ready_slot_tx_addresses_cache(false)
                   .expect("check_ready_slot_tx_addresses_cache should not fail.");
    assert!(!set);

    let set = state.check_ready_slot_tx_addresses_cache(true)
                   .expect("check_ready_slot_tx_addresses_cache should not fail.");
    assert!(!set);
    check_address_list(0, &mut state);

    let set = state.check_ready_slot_tx_addresses_cache(true)
                   .expect("check_ready_slot_tx_addresses_cache should not fail.");
    assert!(set);
    check_address_list(0, &mut state);
}

// This test mimics the logic on the front end with merged DETACHSLOT and DELETESLOT opcodes
// if DETACHSLOT is removing the last signal a slot is listening to, it should also remove the slot
#[test]
fn slot_detach_and_delete() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);

    // Information to initialize signal.
    let mut emitter = Address::from_low_u64_be(1);
    emitter.set_contract_type_bits();
    let sig_key_1 = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_key_2 = vec![0x41u8, 0x42u8, 0x44u8];

    // Information to initialize slot.
    let mut listener = Address::from_low_u64_be(2);
    let gas_sponsor = listener;
    listener.set_contract_type_bits();
    let method_hash = H256::zero();
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key_1)
        .expect("Signal creation should not fail.");
    state
        .create_signal(&emitter, &sig_key_2)
        .expect("Signal creation should not fail.");
    // Create slot.
    state
        .new_contract(&listener, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener, &slot_key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");
    // Signal and slot location.
    let sig_loc_1 = SignalLocation::new(&emitter, &sig_key_1);
    let sig_loc_2 = SignalLocation::new(&emitter, &sig_key_2);
    let slot_loc = SlotLocation::new(&listener, &slot_key);
    // Bind slot to signal 1 and check if the binding is correct.
    state
        .bind_slot_to_signal(&sig_loc_1, &slot_loc)
        .expect("Bind should not fail.");
    let sig = state
        .signal_at(&emitter, &sig_key_1)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    let slot = sig.slot_list().last().unwrap().clone();
    assert_eq!(*slot.location(), slot_loc);
    assert_eq!(*slot.gas_limit(), gas_limit);
    // Bind slot to signal 2 and check if the binding is correct.
    state
        .bind_slot_to_signal(&sig_loc_2, &slot_loc)
        .expect("Bind should not fail.");
    let sig = state
        .signal_at(&emitter, &sig_key_2)
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
    assert_eq!(slot.bind_list().len(), 2);

    // Detach slot from signal.
    let signal_remaining = state
        .detach_slot_from_signal(&sig_loc_2, &slot_loc)
        .expect("Detach should not fail.");
    // Check to see if slot info is correct.
    let slot = state
            .slot_at(&listener, &slot_key)
            .expect("Slot info retrieval should not fail")
            .unwrap();
    assert_eq!(slot.bind_list().len(), 1);
    assert_eq!(signal_remaining, U256::one());

    // Detach sig 1
    let signal_remaining = state
        .detach_slot_from_signal(&sig_loc_1, &slot_loc)
        .expect("Detach should not fail.");
    assert_eq!(signal_remaining, U256::zero());

    // Slot has been deleted
    let slot = state.slot_at(&listener, &slot_key)
                    .expect("Slot info retrieval should not fail");
    assert!(slot.is_none());
}

// Create then delete a signal
#[test]
fn signal_deletion() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    address.set_contract_type_bits();
    let key = vec![0x41u8, 0x42u8, 0x43u8];

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&address, &key)
        .expect("Signal creation should not fail.");

    state.signal_at(&address, &key)
        .expect("Signal should exist.")
        .unwrap();

    let sig_loc = SignalLocation::new(&address, &key);
    state
        .delete_signal(&sig_loc)
        .expect("Signal deletion should not fail.");
    
    let sig = state.signal_at(&address, &key)
        .expect("Signal info retrieval should not fail");
    assert!(sig.is_none());
}

// Create then delete a slot
#[test]
fn slot_deletion() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    let gas_sponsor = address;
    address.set_contract_type_bits();
    let method_hash = H256::zero();
    let key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&address, &key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");

    let slot_loc = SlotLocation::new(&address, &key);
    state
        .delete_slot(&slot_loc)
        .expect("Slot deletion should not fail.");
    
    let slot = state.slot_at(&address, &key)
        .expect("Slot info retrieval should not fail");
    assert!(slot.is_none());
}

// Create a slot listening to multiple sig, then delete it
#[test]
fn slot_cascading() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);

    // Information to initialize signal.
    let mut emitter = Address::from_low_u64_be(1);
    emitter.set_contract_type_bits();
    let sig_key_1 = vec![0x41u8, 0x42u8, 0x43u8];
    let sig_key_2 = vec![0x41u8, 0x42u8, 0x44u8];

    // Information to initialize slot.
    let mut listener = Address::from_low_u64_be(2);
    let gas_sponsor = listener;
    listener.set_contract_type_bits();
    let method_hash = H256::zero();
    let slot_key = vec![0x31u8, 0x32u8, 0x33u8];
    let gas_limit = U256::from(1000);
    let gas_ratio = U256::from(120);

    // Create signal.
    state
        .new_contract(&emitter, U256::zero(), U256::one())
        .unwrap();
    state
        .create_signal(&emitter, &sig_key_1)
        .expect("Signal creation should not fail.");
    state
        .create_signal(&emitter, &sig_key_2)
        .expect("Signal creation should not fail.");
    // Create slot.
    state
        .new_contract(&listener, U256::zero(), U256::one())
        .unwrap();
    state
        .create_slot(&listener, &slot_key, &method_hash, &gas_sponsor, &gas_limit, &gas_ratio)
        .expect("Slot creation should not fail.");
    // Signal and slot location.
    let sig_loc_1 = SignalLocation::new(&emitter, &sig_key_1);
    let sig_loc_2 = SignalLocation::new(&emitter, &sig_key_2);
    let slot_loc = SlotLocation::new(&listener, &slot_key);
    // Bind slot to signal 1 and 2.
    state
        .bind_slot_to_signal(&sig_loc_1, &slot_loc)
        .expect("Bind should not fail.");
    let sig = state
        .signal_at(&emitter, &sig_key_1)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert_eq!(sig.slot_list().len(), 1);

    state
        .bind_slot_to_signal(&sig_loc_2, &slot_loc)
        .expect("Bind should not fail.");
    let sig = state
        .signal_at(&emitter, &sig_key_2)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert_eq!(sig.slot_list().len(), 1);
    
    // Delete slot
    state.delete_slot(&slot_loc)
        .expect("Slot deletion should not fail.");
    let slot = state.slot_at(&listener, &slot_key)
        .expect("Slot info retrieval should not fail");
    assert!(slot.is_none());

    // Check if the slot is gone from both sig 1 and 2
    let sig = state
        .signal_at(&emitter, &sig_key_2)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert_eq!(sig.slot_list().len(), 0);

    let sig = state
        .signal_at(&emitter, &sig_key_1)
        .expect("Signal info retrieval should not fail")
        .unwrap();
    assert_eq!(sig.slot_list().len(), 0);

}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
