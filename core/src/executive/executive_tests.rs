// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{executive::*, internal_contract::*, Executed, ExecutionError};
use crate::{
    evm::{Factory, FinalizationResult, VMType},
    executive::ExecutionOutcome,
    machine::Machine,
    parameters::staking::*,
    state::{CleanupMode, CollateralCheckResult, Substate},
    storage::tests::new_state_manager_for_unit_test,
    test_helpers::{
        get_state_for_genesis_write, get_state_for_genesis_write_with_factory,
    },
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
    },
};
use cfx_types::{
    address_util::AddressUtil, Address, BigEndianHash, U256, U512,
};
use keylib::{Generator, Random};
use primitives::{transaction::Action, Transaction};
use rustc_hex::FromHex;
use std::{
    cmp::{self, min},
    str::FromStr,
    sync::Arc,
};
//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use primitives::{SignalLocation,SlotLocation};
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::new_machine_with_builtin();
    machine
        .set_spec_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
    machine
}

#[test]
fn test_contract_address() {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let expected_address =
        Address::from_str("87ed868bd4e05f0be585961a5293a68cfb6ce60e").unwrap();
    assert_eq!(
        expected_address,
        contract_address(
            CreateContractAddress::FromSenderNonceAndCodeHash,
            &address,
            &U256::from(88),
            &[]
        )
        .0
    );
}

#[test]
fn test_sender_balance() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
    params.value = ActionValue::Transfer(U256::from(0x7));
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &COLLATERAL_PER_STORAGE_KEY, CleanupMode::NoEmpty)
        .unwrap();
    state
        .add_balance(&sender, &U256::from(0x100u64), CleanupMode::NoEmpty)
        .unwrap();
    assert_eq!(
        state.balance(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(0x100)
    );
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params, &mut substate).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_595));
    assert_eq!(
        state.storage_at(&address, &vec![0; 32]).unwrap(),
        BigEndianHash::from_uint(
            &(*COLLATERAL_PER_STORAGE_KEY + U256::from(0xf9))
        )
    );
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0xf9));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.balance(&address).unwrap(), U256::from(0x7));
    assert_eq!(substate.contracts_created.len(), 0);
}

#[test]
fn test_create_contract_out_of_depth() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 17
    // f0 - create
    // 60 00 - push 0
    // 55 sstore
    //
    // other code:
    //
    // 60 10 - push 16
    // 80 - duplicate first stack item
    // 60 0c - push 12
    // 60 00 - push 0
    // 39 - copy current code to memory
    // 60 00 - push 0
    // f3 - return

    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let sender =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty)
        .unwrap();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params, &mut substate).unwrap()
    };

    assert_eq!(gas_left, U256::from(62_976));
    assert_eq!(substate.contracts_created.len(), 0);
}

#[test]
// Tracing is not suported in JIT
fn test_call_to_create() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 23
    // f0 - create
    // 60 00 - push 0
    // 55 sstore
    //
    // other code:
    //
    // 60 10 - push 16
    // 80 - duplicate first stack item
    // 60 0c - push 12
    // 60 00 - push 0
    // 39 - copy current code to memory
    // 60 00 - push 0
    // f3 - return

    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let sender =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    let mut params = ActionParams::default();
    params.address = address;
    params.code_address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));
    params.call_type = CallType::Call;

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    state
        .new_contract(&address, U256::zero(), U256::one())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .add_balance(
            &sender,
            &(U256::from(100)
                + *COLLATERAL_PER_STORAGE_KEY
                + U256::from(15_625_000_000_000_000u64)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(100)
            + *COLLATERAL_PER_STORAGE_KEY
            + U256::from(15_625_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        U256::from(0)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    let env = Env::default();
    let machine = make_byzantium_machine(5);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params, &mut substate).unwrap()
    };
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(15_625_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(15_625_000_000_000_000u64)
    );

    assert_eq!(gas_left, U256::from(59_752));
}

#[test]
fn test_revert() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let contract_address =
        Address::from_str("8d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();

    let code = "6c726576657274656420646174616000557f726576657274206d657373616765000000000000000000000000000000000000600052600e6000fd".from_hex().unwrap();
    let returns = "726576657274206d657373616765".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(
        &storage_manager,
        factory.clone(),
    );
    state
        .add_balance(
            &sender,
            &U256::from_str("152d02c7e14af68000000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .new_contract(&contract_address, U256::zero(), U256::one())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .commit(BigEndianHash::from_uint(&U256::from(1)), None)
        .unwrap();

    let mut params = ActionParams::default();
    params.address = contract_address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = contract_address;
    params.gas = U256::from(20025);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::zero());
    let env = Env::default();
    let machine = crate::machine::new_machine_with_builtin();
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let mut output = [0u8; 14];
    let FinalizationResult {
        gas_left: result,
        return_data,
        ..
    } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params, &mut substate).unwrap()
    };
    (&mut output)
        .copy_from_slice(&return_data[..(cmp::min(14, return_data.len()))]);

    assert_eq!(result, U256::from(15_001));
    assert_eq!(output[..], returns[..]);
    assert_eq!(
        state.storage_at(&contract_address, &vec![0; 32]).unwrap(),
        BigEndianHash::from_uint(&U256::zero())
    );
}

#[test]
fn test_keccak() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let code = "6064640fffffffff20600055".from_hex().unwrap();

    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    //let next_address = contract_address(&address, &U256::zero());
    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = address;
    params.gas = U256::from(0x0186a0);
    params.code = Some(Arc::new(code));
    params.value =
        ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(
            &sender,
            &U256::from_str("152d02c7e14af6800000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let result = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params, &mut substate)
    };

    match result {
        Err(_) => {}
        _ => panic!("Expected OutOfGas"),
    }
}

#[test]
fn test_not_enough_cash() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let keypair = Random.generate().unwrap();
    let t = Transaction {
        action: Action::Create,
        value: U256::from(18),
        data: "3331600055".from_hex().unwrap(),
        gas: U256::from(100_000),
        gas_price: U256::one(),
        storage_limit: U256::zero(),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::zero(),
        slot_tx: None,
    }
    .sign(keypair.secret());
    let sender = t.sender();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &U256::from(100_017), CleanupMode::NoEmpty)
        .unwrap();
    let correct_cost = min(t.gas_price * t.gas, 100_017.into());
    let mut env = Env::default();
    env.gas_limit = U256::from(100_000);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&t).unwrap()
    };

    match res {
        ExecutionOutcome::ExecutionErrorBumpNonce(
            ExecutionError::NotEnoughCash {
                required,
                got,
                actual_gas_cost,
                max_storage_limit_cost,
            },
            _executed,
        ) if required == U512::from(100_018)
            && got == U512::from(100_017)
            && correct_cost == actual_gas_cost
            && max_storage_limit_cost.is_zero() =>
        {
            ()
        }
        _ => assert!(false, "Expected not enough cash error. {:?}", res),
    }
}

#[test]
fn test_deposit_withdraw_lock() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let mut sender = Address::zero();
    sender.set_user_account_type_bits();
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();
    state
        .add_balance(
            &sender,
            &U256::from(2_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state.add_total_issued(U256::from(2_000_000_000_000_000_000u64));
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(*state.total_staking_tokens(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    let mut params = ActionParams::default();
    params.code_address = STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS.clone();
    params.address = params.code_address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = params.code_address;
    params.gas = U256::from(1000000);
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a7640000".from_hex().unwrap());

    // wrong call type
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("Incorrect call type.")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::zero());
    assert_eq!(state.block_number(), 0);

    // deposit 10^18 - 1, not enough
    params.call_type = CallType::Call;
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a763ffff".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid deposit amount")
    );

    // deposit 10^18, it should work fine
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a7640000".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // empty data
    params.data = None;
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // less data
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e8".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // more data
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e80000".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // withdraw
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7400".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);
    // withdraw more than staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288c01".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw"
        )
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // lock until block_number = 0
    params.data = Some("5547dedb00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid unlock_block_number")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    // lock 1 until 106751991167301 blocks, should succeed
    params.data = Some("5547dedb00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000611722833944".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_999u64)
    );
    // lock 2 until block_number=2
    params.data = Some("5547dedb00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );
    // withdraw more than withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bff".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw"
        )
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );

    // withdraw exact withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bfe".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_999_999_999_999_999_998u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::from(2));
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(2));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(0)
    );
}

#[test]
fn test_commission_privilege() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 23
    // f0 - create
    // 60 00 - push 0
    // 55 sstore

    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender.address()).unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(1000000),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(sender.secret());
    assert_eq!(tx.sender(), sender.address());
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&sender.address()).unwrap(), U256::from(1));
    assert_eq!(state.balance(&address).unwrap(), U256::from(1_000_000));
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(999_999_999_998_925_000u64)
    );

    state
        .add_balance(
            &caller1.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    // add commission privilege to caller1 and caller2
    state
        .add_commission_privilege(address, sender.address(), caller1.address())
        .unwrap();
    state
        .add_commission_privilege(address, sender.address(), caller2.address())
        .unwrap();
    assert!(state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());
    assert!(state
        .check_commission_privilege(&address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());
    state
        .set_sponsor_for_gas(
            &address,
            &sender.address(),
            &U256::from(110_000),
            &U256::from(110_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(110_000)
    );
    assert_eq!(
        state.sponsor_gas_bound(&address).unwrap(),
        U256::from(110_000)
    );

    // call with no commission privilege
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(60_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(110_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller1.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(100_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(35_000)
    );

    // call with commission privilege and not enough commission balance
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller2.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(35_000)
    );

    // add more commission balance
    state
        .set_sponsor_for_gas(
            &address,
            &sender.address(),
            &U256::from(200_000),
            &U256::from(200_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(200_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller2.address()).unwrap(), U256::from(2));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(125_000)
    );

    // add commission privilege to caller3
    state
        .add_commission_privilege(address, sender.address(), caller3.address())
        .unwrap();
    assert!(state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());
    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: U256::from(0),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(2));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(50_000)
    );
}

#[test]
fn test_storage_commission_privilege() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 01 - push 0
    // 52
    // 33 - caller
    // 60 01 - push 1
    // 55 sstore

    let privilege_control_address = &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "7c601080600c6000396000f3006000355415600957005b6020356000355560005233600155".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender.address()).unwrap();

    state
        .add_balance(
            &sender.address(),
            &U256::from(2_000_000_000_000_075_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // simple call to create a storage entry
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: *COLLATERAL_PER_STORAGE_KEY,
        action: Action::Call(address),
        storage_limit: U256::from(BYTES_PER_STORAGE_KEY),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(sender.secret());
    assert_eq!(tx.sender(), sender.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();
    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, sender.address());
    assert_eq!(storage_collateralized[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(storage_released.len(), 0);

    state
        .set_sponsor_for_collateral(
            &address,
            &sender.address(),
            &COLLATERAL_PER_STORAGE_KEY,
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);

    state
        .add_balance(
            &caller1.address(),
            &(*COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address(),
            &(*COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address(),
            &(*COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // add privilege to caller1 and caller2
    let mut substate = Substate::new();
    state.checkpoint();
    state
        .add_commission_privilege(address, sender.address(), caller1.address())
        .unwrap();
    state
        .add_commission_privilege(address, sender.address(), caller2.address())
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &privilege_control_address,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(
        substate.storage_collateralized[&sender.address()],
        2 * BYTES_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_750_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3),
    );
    assert!(state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());
    assert!(state
        .check_commission_privilege(&address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());

    // caller3 call with no privilege
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: U256::from(BYTES_PER_STORAGE_KEY),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller3.address());
    assert_eq!(storage_collateralized[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, sender.address());
    assert_eq!(storage_released[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller3.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // caller1 call with privilege
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: U256::from(BYTES_PER_STORAGE_KEY),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, address);
    assert_eq!(storage_collateralized[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, caller3.address());
    assert_eq!(storage_released[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(925_000),
    );
    assert_eq!(
        state.staking_balance(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // caller2 call with commission privilege and not enough sponsor
    // balance, the owner will transfer to caller2.
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(1000_000),
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: U256::from(BYTES_PER_STORAGE_KEY),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller2.address());
    assert_eq!(storage_collateralized[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, address);
    assert_eq!(storage_released[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller2.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller2.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // remove privilege from caller1
    state.checkpoint();
    state
        .remove_commission_privilege(
            address,
            sender.address(),
            caller1.address(),
        )
        .unwrap();
    let mut substate = Substate::new();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &privilege_control_address,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    state.discard_checkpoint();
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(1),
    );
    assert_eq!(substate.storage_released.len(), 1);
    assert_eq!(
        substate.storage_released[&sender.address()],
        BYTES_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );

    assert!(!state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());

    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(925_000),
    );
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: U256::from(BYTES_PER_STORAGE_KEY),
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
        slot_tx: None,
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller1.address());
    assert_eq!(storage_collateralized[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, caller2.address());
    assert_eq!(storage_released[0].amount, BYTES_PER_STORAGE_KEY);
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(850_000)
    );
    assert_eq!(
        state.staking_balance(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller1.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.collateral_for_storage(&caller2.address()).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(925_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
}
//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
#[test]
fn test_slottx_execute() {
    // pragma solidity ^0.6.9;
    // contract B {
    //     bytes3 public LocalPriceSum;
    //     uint public priceReceive_status;
    //     bytes32 public priceReceive_codePtr;//codePtr is useless now
    //     bytes32 public priceReceive_key;
    //     function priceReceive() public{
    //         priceReceive_key = keccak256("priceReceive_func(bytes3)");
    //         assembly {
    //             sstore(priceReceive_status_slot,createslot(3,10,30000,sload(priceReceive_key_slot)))
    //         }		
    //     }
    //     function priceReceive_func(bytes3 obj) public returns (bytes3 ret){
    //         ret = ~ obj;
    //     }
    //     constructor() public {
    //         priceReceive();
    //     }
    // }
    //
    //the test will execute slot priceReceive, it will do call priceReceive_func(bytes3 obj)
    //the solidity source code is in solidity/signalslot_parse_script/tb/tb7

    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let create_code = "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f7072696365526563656976655f66756e6328627974657333290000000000000081525060190190506040518091039020600381905550600354617530600a6003c1600155565b6102d08061007f6000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80630cd2542e146100675780630f91288114610085578063255286301461012757806368c0b03814610145578063b6675486146101a3578063fd0bf5a3146101ad575b600080fd5b61006f6101cb565b6040518082815260200191505060405180910390f35b6100d16004803603602081101561009b57600080fd5b8101908080357cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690602001909291905050506101d1565b60405180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b61012f610206565b6040518082815260200191505060405180910390f35b61014d61020c565b60405180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b6101ab61021e565b005b6101b561026a565b6040518082815260200191505060405180910390f35b60025481565b6000816000806101000a81548162ffffff021916908360e81c02179055506000809054906101000a900460e81b199050919050565b60015481565b6000809054906101000a900460e81b81565b60405180807f7072696365526563656976655f66756e6328627974657333290000000000000081525060190190506040518091039020600381905550600354617530600a6003c1600155565b6003548156fea26469706673582212206c5d65486a71d7534b8309409b32ebcf14c1b19d5f661a088a2b3cb3360a5a8164736f6c63782c302e362e31312d646576656c6f702e323032302e372e31342b636f6d6d69742e63333731353564362e6d6f64005d"
    .from_hex().unwrap();
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::zero(),
        &create_code,
    )
    .0;
    state
        .add_balance(
            &sender.address(),
            &U256::from(2_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    //deploy contract
    let contract_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: create_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::zero(),
        slot_tx: None,
    }
    .sign(sender.secret());
    let _res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&contract_tx).unwrap()
    };
    assert_eq!(state.is_contract(&address),true);
    // state
    // .add_balance(
    //     &address,
    //     &U256::from(2_000_000_010_000_210_010u64),
    //     CleanupMode::NoEmpty,
    // )
    // .unwrap();
    //add sponsor as itself
    state.set_sponsor_for_gas(&address, &address, &U256::from(2_000_000_010_000_210_010u64), &U256::from(2_000_000_010_000_210_010u64)).unwrap();
    state.set_sponsor_for_collateral(&address, &address, &U256::from(2_000_000_010_000_210_010u64)).unwrap();
    //add commission privilege for user address
    state
        .add_commission_privilege(address, address, address)
        .unwrap();    
    //create a virtual signal
    let sigkey = vec![0x01u8, 0x02u8, 0x03u8];
    let _result = state.create_signal(
        &address, 
        &sigkey,
        &U256::from(3),
    );
    
    let slot_key = "0f912881556b2e01fbe4a30eea53c1e292615c8fc30a7893a93ff5a64aea4e8a".from_hex().unwrap();

    //remove create a virual slot, let contract constructor above create slot itself
    // let _slt_result = state.create_slot(
    //     &address, 
    //     &slot_key,
    //     &U256::from(3),
    //     &U256::from(100000),
    //     &U256::from(1), 
    //     &U256::from(10),
    // );

    //bind slot with signal
    let sig_loc = SignalLocation::new(&address, &sigkey);
    let slt_loc = SlotLocation::new(&address, &slot_key);
    let _bindresult = state.bind_slot_to_signal(&sig_loc, &slt_loc);

    // fake emit sig
    let current_epoch_height: u64 = 0;
    let epoch_height_delay: u64 = 0;
    let argv = vec![0x12u8,0x34u8,0x56u8]; //argument obj = 0x123456
    let _emitsigresult = state.emit_signal_and_queue_slot_tx(
        &sig_loc, 
        current_epoch_height, 
        epoch_height_delay, 
        &argv
    );

    let queue = state
    .get_account_slot_tx_queue(&address)
    .unwrap();
    let mut slttx = queue.peek(0).unwrap().clone();
    slttx.calculate_and_set_gas_price(&U256::from(100));
    slttx.set_gas_upfront(U256::from(1021301));
    //now fake get slot tx
    let tx = Transaction {
        nonce: U256::zero(),
        gas_price: U256::zero(),
        gas: U256::zero(),
        value: U256::zero(),
        action: Action::SlotTx,
        storage_limit: U256::zero(),
        epoch_height: 0,
        chain_id: 0,
        data: Vec::new(),
        slot_tx: Some(slttx),
    };
    let tx = Transaction::create_signed_tx_with_slot_tx(tx.clone());
    let Executed {
        output,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();
    assert_eq!(output, vec![0xed, 0xcb, 0xa9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
