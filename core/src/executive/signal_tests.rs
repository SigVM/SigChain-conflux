//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

use super::{executive::*, internal_contract::*, Executed};
use crate::{
    evm::{Factory, VMType},
    machine::Machine,
    state::{CleanupMode},
    storage::tests::new_state_manager_for_unit_test,
    test_helpers::{
        get_state_for_genesis_write_with_factory,
    },
    vm::{
        CreateContractAddress, Env,
    },
};
use cfx_types::{
    U256,
};
use keylib::{Generator, Random};
use primitives::{transaction::Action, Transaction};
use rustc_hex::FromHex;
use primitives::{SignalLocation,SlotLocation};

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::new_machine_with_builtin();
    machine
        .set_spec_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
    machine
}

#[test]
#[should_panic]
fn test_slot_exec_error() {
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
    let create_code = "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610
    070565b60405180807f7072696365526563656976655f66756e63286279746573332900000000000000815
    25060190190506040518091039020600381905550600354617530600a6003c1600155565b6102d08061007
    f6000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80630cd
    2542e146100675780630f91288114610085578063255286301461012757806368c0b03814610145578063b
    6675486146101a3578063fd0bf5a3146101ad575b600080fd5b61006f6101cb565b6040518082815260200
    191505060405180910390f35b6100d16004803603602081101561009b57600080fd5b8101908080357cfff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffff191690602001909291905050506101d
    1565b60405180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cfffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffff191681526020019150506040518091039
    0f35b61012f610206565b6040518082815260200191505060405180910390f35b61014d61020c565b60405
    180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cfffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b6101a
    b61021e565b005b6101b561026a565b6040518082815260200191505060405180910390f35b60025481565
    b6000816000806101000a81548162ffffff021916908360e81c02179055506000809054906101000a90046
    0e81b199050919050565b60015481565b6000809054906101000a900460e81b81565b60405180807f70726
    96365526563656976655f66756e63286279746573332900000000000000815250601901905060405180910
    39020600381905550600354617530600a6003c1600155565b6003548156fea26469706673582212206c5d6
    5486a71d7534b8309409b32ebcf14c1b19d5f661a088a2b3cb3360a5a8164736f6c63782c302e362e31312
    d646576656c6f702e323032302e372e31342b636f6d6d69742e63333731353564362e6d6f64005d"
    .from_hex().unwrap();
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let receiver = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &receiver.address(),
        &U256::zero(),
        &create_code,
    )
    .0;
    state
        .add_balance(
            &receiver.address(),
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
    .sign(receiver.secret());
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

    //create a virtual signal
    let sigkey = vec![0x01u8, 0x02u8, 0x03u8];
    let _result = state.create_signal(
        &receiver.address(),
        &sigkey,
        &U256::from(3),
    );

    let slot_key = "0f912881556b2e01fbe4a30eea53c1e292615c8fc30a7893a93ff5a64aea4e8a".from_hex().unwrap();

    //bind slot with signal
    let sig_loc = SignalLocation::new(&receiver.address(), &sigkey);
    let slt_loc = SlotLocation::new(&receiver.address(), &address, &slot_key);
    let _bindresult = state.bind_slot_to_signal(&sig_loc, &slt_loc).unwrap();

    // fake emit sig
    let current_epoch_height: u64 = 0;
    let epoch_height_delay: u64 = 0;
    let argv = vec![0x12u8,0x34u8,0x56u8];
    let _emitsigresult = state.emit_signal_and_queue_slot_tx(
        &sig_loc,
        current_epoch_height,
        epoch_height_delay,
        &argv,
        true,
        &vec![0u8,32]
    ).unwrap();

    let queue = state
    .get_account_slot_tx_queue(&address)
    .unwrap();
    let mut slttx = queue.peek(0).unwrap().clone();
    slttx.calculate_and_set_gas_price(&U256::from(100));
    slttx.set_gas(U256::from(1021301));
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
    Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .expect("Should get SlotExecutionError(VmError(Reverted)");
}

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
    let create_code = "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610
    070565b60405180807f7072696365526563656976655f66756e63286279746573332900000000000000815
    25060190190506040518091039020600381905550600354617530600a6003c1600155565b6102d08061007
    f6000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80630cd
    2542e146100675780630f91288114610085578063255286301461012757806368c0b03814610145578063b
    6675486146101a3578063fd0bf5a3146101ad575b600080fd5b61006f6101cb565b6040518082815260200
    191505060405180910390f35b6100d16004803603602081101561009b57600080fd5b8101908080357cfff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffff191690602001909291905050506101d
    1565b60405180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cfffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffff191681526020019150506040518091039
    0f35b61012f610206565b6040518082815260200191505060405180910390f35b61014d61020c565b60405
    180827cffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167cfffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b6101a
    b61021e565b005b6101b561026a565b6040518082815260200191505060405180910390f35b60025481565
    b6000816000806101000a81548162ffffff021916908360e81c02179055506000809054906101000a90046
    0e81b199050919050565b60015481565b6000809054906101000a900460e81b81565b60405180807f70726
    96365526563656976655f66756e63286279746573332900000000000000815250601901905060405180910
    39020600381905550600354617530600a6003c1600155565b6003548156fea26469706673582212206c5d6
    5486a71d7534b8309409b32ebcf14c1b19d5f661a088a2b3cb3360a5a8164736f6c63782c302e362e31312
    d646576656c6f702e323032302e372e31342b636f6d6d69742e63333731353564362e6d6f64005d"
    .from_hex().unwrap();
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let receiver = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &receiver.address(),
        &U256::zero(),
        &create_code,
    )
    .0;
    state
        .add_balance(
            &receiver.address(),
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
    .sign(receiver.secret());
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
    // //add sponsor as itself
    // state.set_sponsor_for_gas(&address, &address, &U256::from(2_000_000_010_000_210_010u64), &U256::from(2_000_000_010_000_210_010u64)).unwrap();
    // state.set_sponsor_for_collateral(&address, &address, &U256::from(2_000_000_010_000_210_010u64)).unwrap();
    // //add commission privilege for user address
    // state
    //     .add_commission_privilege(address, address, address)
    //     .unwrap();
    //create a virtual signal
    let sigkey = vec![0x01u8, 0x02u8, 0x03u8];
    let _result = state.create_signal(
        &receiver.address(),
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
    let sig_loc = SignalLocation::new(&receiver.address(), &sigkey);
    let slt_loc = SlotLocation::new(&receiver.address(), &address, &slot_key);
    let _bindresult = state.bind_slot_to_signal(&sig_loc, &slt_loc).unwrap();

    // fake emit sig
    let current_epoch_height: u64 = 0;
    let epoch_height_delay: u64 = 0;
    let argv = vec![0x12u8,0x34u8,0x56u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let _emitsigresult = state.emit_signal_and_queue_slot_tx(
        &sig_loc,
        current_epoch_height,
        epoch_height_delay,
        &argv,
        true,
        &vec![0u8,32]
    ).unwrap();

    let queue = state
    .get_account_slot_tx_queue(&address)
    .unwrap();
    let mut slttx = queue.peek(0).unwrap().clone();
    slttx.calculate_and_set_gas_price(&U256::from(100));
    slttx.set_gas(U256::from(1021301));
    slttx.set_storage_limit(U256::from(100));
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

#[test]
fn test_broadcast() {
    // BEFORE PARSING:
    //
    // pragma solidity ^0.6.9;
    // contract Emitter {
    //     signal Alert();
    //     function send_alert() public view {
    //         emitsig Alert().delay(0);
    //     }
    // }
    //
    // contract ReceiverA {
    //     bytes32 private data;
    //     slot HandleAlert() {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         HandleAlert.bind(addr.Alert);
    //     }
    // }
    //
    // contract ReceiverB {
    //     bytes32 private data;
    //     slot HandleAlert() {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         HandleAlert.bind(addr.Alert);
    //     }
    // }
    //
    // AFTER PARSING:
    //
    // pragma solidity ^0.6.9;


    // contract Emitter {
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original code:
    //     // signal Alert

    //     // Generated variables that represent the signal
    //     bytes32 private Alert_dataslot;//the data pointer is NULL
    //     uint private Alert_status;
    //     bytes32 private Alert_key;

    //     // Get the signal key
    //     function get_Alert_key() public view returns (bytes32 key) {
    //        return Alert_key;
    //     }

    //     // Get the data slot
    //     function get_Alert_dataslot() private view returns (bytes32 dataslot) {
    //        return Alert_dataslot;
    //     }

    //     // signal Alert construction
    //     // This should be called once in the contract construction.
    //     // This parser should automatically call it.
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(0, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, 0x0)
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////

    //     function send_alert() public view {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // emitsig Alert().delay(0)

    //         // Get the data slot
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         // Get the signal key
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         // Use assembly to emit the signal and queue up slot transactions
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, 2))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    Alert();
    // }
    // }

    // contract ReceiverA {
    //     bytes32 private data;
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // slot HandleAlert {...}

    //     // Generated variables that represent the slot
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;

    //     // Get the signal key
    //     function get_HandleAlert_key() public view returns (bytes32 key) {
    //        return HandleAlert_key;
    //     }

    //     // HandleAlert construction
    //     // Should be called once in the contract construction
    //     function HandleAlert() private {
    //         HandleAlert_key = keccak256("HandleAlert_func()");
    //         assembly {
    //             sstore(HandleAlert_status_slot, createslot(0, 10, 30000, sload(HandleAlert_key_slot)))
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////

    //     // HandleAlert code to be executed
    //     // The slot is converted to a function that will be called in slot transactions.
    //     function HandleAlert_func() public {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // HandleAlert.bind(addr.Alert)

    //         // Convert to address
    //         address addr_bindslot_address = address(addr);
    //         // Get signal key from emitter contract
    //         bytes32 addr_bindslot_Alert_key = keccak256("Alert()");
    //         // Get slot key from receiver contract
    //         bytes32 this_addr_bindslot_HandleAlert_key = get_HandleAlert_key();
    //         // Use assembly to bind slot to signal
    //         assembly {
    //             mstore(0x40, bindslot(addr_bindslot_address, addr_bindslot_Alert_key, this_addr_bindslot_HandleAlert_key))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    HandleAlert();
    // }
    // }

    // contract ReceiverB {
    //     bytes32 private data;
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // slot HandleAlert {...}

    //     // Generated variables that represent the slot
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;

    //     // Get the signal key
    //     function get_HandleAlert_key() public view returns (bytes32 key) {
    //        return HandleAlert_key;
    //     }

    //     // HandleAlert construction
    //     // Should be called once in the contract construction
    //     function HandleAlert() private {
    //         HandleAlert_key = keccak256("HandleAlert_func()");
    //         assembly {
    //             sstore(HandleAlert_status_slot, createslot(0, 10, 30000, sload(HandleAlert_key_slot)))
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////

    //     // HandleAlert code to be executed
    //     // The slot is converted to a function that will be called in slot transactions.
    //     function HandleAlert_func() public {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // HandleAlert.bind(addr.Alert)

    //         // Convert to address
    //         address addr_bindslot_address = address(addr);
    //         // Get signal key from emitter contract
    //         bytes32 addr_bindslot_Alert_key = keccak256("Alert()");
    //         // Get slot key from receiver contract
    //         bytes32 this_addr_bindslot_HandleAlert_key = get_HandleAlert_key();
    //         // Use assembly to bind slot to signal
    //         assembly {
    //             mstore(0x40, bindslot(addr_bindslot_address, addr_bindslot_Alert_key, this_addr_bindslot_HandleAlert_key))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    HandleAlert();
    // }
    // }

    // Test overview:
    // 1. Deploy contract accounts
    // 2. Bind each receiver to the signal
    // 3. Emit the signal
    // 4. Verify that both slot transactions are created

    // set up factory.
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    // set up state.
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
    // set up machine, contract map, env, and spec.
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec(env.number);

    // Create a sender account. This is the account that will pay for each of
    // the contract creations. We also have to transfer some balance to the sender.
    // We just give the sender a huge balance so it can pay for everything...
    let sender = Random.generate().unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // Set up and deploy the emitter contract.
    let emitter_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b61006f565b6040518080
        7f416c6572742829000000000000000000000000000000000000000000000000008152506007019050604
        05180910390206002819055506002546000c060015560008055565b60f08061007d6000396000f3fe6080
        604052348015600f57600080fd5b506004361060325760003560e01c806365410bf11460375780637ced9
        53e146053575b600080fd5b603d605b565b6040518082815260200191505060405180910390f35b605960
        65565b005b6000600254905090565b6000606d6087565b905060006077605b565b9050600282600083c46
        040525050565b6000805490509056fea2646970667358221220d8c7e0f70c20322d41aa7ae7f94c8bc532
        def40b80fff7da6c6bbecc958d995264736f6c63782c302e362e31312d646576656c6f702e323032302e3
        72e32322b636f6d6d69742e36646666643637632e6d6f64005d"
        .from_hex().unwrap();
    // Hash of function identifier. First 8 bytes form the methodid. keccak256("send_alert()").
    let _emitter_send_alert_hash = "7ced953e";
    // Create emitter contract account address.
    let emitter_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::zero(),
        &emitter_code,
    ).0;
    // Emitter contract creation transaction.
    let emitter_contract_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: emitter_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::zero(),
        slot_tx: None,
    }
    .sign(sender.secret());
    // Execute this transaction.
    let _res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&emitter_contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&emitter_address));

    // Check to see if signal got created.
    let sig_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex()
        .unwrap();
    let sig = state
        .signal_at(&emitter_address, &sig_key)
        .expect("Should not be db error");
    assert!(sig.is_some());

    // Set up and deploy the first receiver contract.
    let receiver_a_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b604
        05180807f48616e646c65416c6572745f66756e632829000000000000000000000000000081525
        060120190506040518091039020600281905550600254617530600a6000c1600155565b6101808
        061007f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003
        560e01c806334bcebd0146100465780633e2f5fe5146100505780639981f1bc14610094575b600
        080fd5b61004e6100b2565b005b6100926004803603602081101561006657600080fd5b8101908
        0803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100be5
        65b005b61009c610116565b6040518082815260200191505060405180910390f35b6000801b600
        081905550565b6000819050600060405180807f416c65727428290000000000000000000000000
        000000000000000000000000081525060070190506040518091039020905060006101076101165
        65b9050808284c260405250505050565b600060025490509056fea2646970667358221220f6f3a
        c9da55d86bda2ca9cb62974c6bee02221177834124e8d41fecbd09b4ed464736f6c63782c302e3
        62e31312d646576656c6f702e323032302e372e32322b636f6d6d69742e36646666643637632e6
        d6f64005d"
        .from_hex().unwrap();

    // Create receiver contract address.
    let receiver_a_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(1),
        &receiver_a_code,
    ).0;

    // Method ID's of relevant functions.
    // let _get_data_hash = "50bf8b0d"; // KEC("get_data()")
    let _bind_to_alert_hash = "3e2f5fe5"; // KEC("bind_to_alert(address)")

    // Contract creation transaction.
    let receiver_a_contract_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: receiver_a_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(1),
        slot_tx: None,
    }
    .sign(sender.secret());
    // Execute this transaction.
    let _res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_a_contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&receiver_a_address));

    // Check to see if all the slots were created properly.
    let slot_key = "34bcebd0f43644043f131abeb6c64b669940d5d0ff219d264bfd86ba70484633"
        .from_hex().unwrap();
    let slot = state
        .slot_at(&sender.address(), &receiver_a_address, &slot_key)
        .expect("Should not have db failure.");
    assert!(slot.is_some());

    // Set up and deploy the second receiver contract.
    // The solidity code for receiver A and B are exactly identical so the compiled code should be as well.
    let receiver_b_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405
        180807f48616e646c65416c6572745f66756e6328290000000000000000000000000000815250601
        20190506040518091039020600281905550600254617530600a6000c1600155565b6101808061007
        f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8
        06334bcebd0146100465780633e2f5fe5146100505780639981f1bc14610094575b600080fd5b610
        04e6100b2565b005b6100926004803603602081101561006657600080fd5b81019080803573fffff
        fffffffffffffffffffffffffffffffffff1690602001909291905050506100be565b005b61009c6
        10116565b6040518082815260200191505060405180910390f35b6000801b600081905550565b600
        0819050600060405180807f416c65727428290000000000000000000000000000000000000000000
        00000008152506007019050604051809103902090506000610107610116565b9050808284c260405
        250505050565b600060025490509056fea2646970667358221220fc3e30a25afa46381b6b5595f9f
        574569640e5baf7721e151241e10be6e25eb664736f6c63782c302e362e31312d646576656c6f702
        e323032302e372e32322b636f6d6d69742e36646666643637632e6d6f64005d"
        .from_hex().unwrap();

    let receiver_b_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(2),
        &receiver_b_code,
    ).0;

    let receiver_b_contract_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: receiver_b_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(2),
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
        ex.transact(&receiver_b_contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&receiver_b_address));

    // Check to see if all the slots were created properly.
    let slot_key = "34bcebd0f43644043f131abeb6c64b669940d5d0ff219d264bfd86ba70484633"
        .from_hex().unwrap();
    let slot = state
        .slot_at(&sender.address(), &receiver_b_address, &slot_key)
        .expect("Should not have db failure.");
    assert!(slot.is_some());

    // Contract are now all deployed. Now we call the bind function for each of the receivers.
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // Bind the slots from receiver A and B to the emitter signal.
    let sig_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex().unwrap();
    let sig = state
        .signal_at(&emitter_address, &sig_key)
        .expect("Should not get db result")
        .unwrap();
    assert!(sig.slot_list().len() == 0);

    // Bind receiver A slot to signal.
    let mut receiver_a_bind_call_data = "3e2f5fe5".from_hex().unwrap();
    receiver_a_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    receiver_a_bind_call_data.extend_from_slice(&emitter_address[..]);
    let receiver_a_bind_tx = Transaction {
        action: Action::Call(receiver_a_address.clone()),
        value: U256::from(0),
        data: receiver_a_bind_call_data.clone(),
        gas: U256::from(200000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(3),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_a_bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());
    // Let's check if the bind actually went through
    let sig_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex().unwrap();
    let sig = state
        .signal_at(&emitter_address, &sig_key)
        .expect("Should not get db result")
        .unwrap();
    assert!(sig.slot_list().len() == 1);

    // Bind receiver B slot to signal.
    let mut receiver_b_bind_call_data = "3e2f5fe5".from_hex().unwrap();
    receiver_b_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    receiver_b_bind_call_data.extend_from_slice(&emitter_address[..]);
    let receiver_b_bind_tx = Transaction {
        action: Action::Call(receiver_b_address.clone()),
        value: U256::from(0),
        data: receiver_b_bind_call_data.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(4),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_b_bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());
    // Let's check if the bind actually went through
    let sig_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex().unwrap();
    let sig = state
        .signal_at(&emitter_address, &sig_key)
        .expect("Should not get db result")
        .unwrap();
    assert!(sig.slot_list().len() == 2);

    // Next step is to emit the signal through the send_alert function.
    // The contract data field will be set to call the send_alert function.
    // It will be set to the method id appended by an argument of our choice.
    let send_alert_call_data = "7ced953e"
        .from_hex().unwrap();
    // Create the transaction with this call data.
    let send_alert_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: send_alert_call_data.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(5),
        slot_tx:None,
    }
    .sign(sender.secret());
    // Execute this transaction.
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&send_alert_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Now we check if both contracts have queued up slot transactions.
    assert!(!state.is_account_slot_tx_queue_empty(&receiver_a_address).expect("Db error not expected!"));
    assert!(!state.is_account_slot_tx_queue_empty(&receiver_b_address).expect("Db error not expected!"));
}

#[test]
fn test_multibind() {
    // BEFORE PARSING:
    //
    // pragma solidity ^0.6.9;
    // contract EmitOnTime {
    //     signal Alert(bytes32 data);
    //
    //     function send_alert(bytes32 data) public {
    //         emitsig Alert(data).delay(0);
    //     }
    // }
    // contract EmitLate {
    //     signal Alert(bytes32 data);
    //
    //     function send_alert(bytes32 data) public {
    //         emitsig Alert(data).delay(10);
    //     }
    // }
    // // Multiple binds! Hopefully it works.
    // contract Receiver {
    //     bytes32 data;
    //     uint32 alert_count;
    //
    //     slot Receive(bytes32 incoming_data) {
    //         data = incoming_data;
    //         alert_count = alert_count + 1;
    //     }
    //     function get_data() public view returns (bytes32 ret) {
    //         ret = data;
    //     }
    //     function get_alert_count() public view returns (uint32 ret) {
    //         ret = alert_count;
    //     }
    //     function bind_to_signal(address emitter) public view {
    //         Receive.bind(emitter.Alert);
    //     }
    //     constructor() public {
    //         data = 0;
    //         alert_count = 0;
    //     }
    // }
    //
    // AFTER PARSING:
    //
    // pragma solidity ^0.6.9;
    // contract EmitOnTime {
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // signal Alert;

    //     // TODO: Arguments should not be limited to one 32 byte value

    //     // Generated variables that represent the signal
    //     bytes32 private Alert_data;
    //     bytes32 private Alert_dataslot;
    //     uint private Alert_status;
    //     bytes32 private Alert_key;

    //     // Set the data to be emitted
    //     function set_Alert_data(bytes32  dataSet) private {
    //        Alert_data = dataSet;
    //     }

    //     // Get the argument count
    //     function get_Alert_argc() public pure returns (uint argc) {
    //        return 1;
    //     }

    //     // Get the signal key
    //     function get_Alert_key() public view returns (bytes32 key) {
    //        return Alert_key;
    //     }

    //     // Get the data slot
    //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
    //        return Alert_dataslot;
    //     }

    //     // signal Alert construction
    //     // This should be called once in the contract construction.
    //     // This parser should automatically call it.
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(1, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, Alert_data_slot)
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////


    //     function send_alert(bytes32 data) public {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // emitsig Alert(data).delay(0)

    //         // Set the data field in the signal
    //         set_Alert_data(data);
    //         // Get the argument count
    //         uint this_emitsig_Alert_argc = get_Alert_argc();
    //         // Get the data slot
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         // Get the signal key
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         // Use assembly to emit the signal and queue up slot transactions
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    Alert();
    // }
    // }
    // contract EmitLate {
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // signal Alert;

    //     // TODO: Arguments should not be limited to one 32 byte value

    //     // Generated variables that represent the signal
    //     bytes32 private Alert_data;
    //     bytes32 private Alert_dataslot;
    //     uint private Alert_status;
    //     bytes32 private Alert_key;

    //     // Set the data to be emitted
    //     function set_Alert_data(bytes32  dataSet) private {
    //        Alert_data = dataSet;
    //     }

    //     // Get the argument count
    //     function get_Alert_argc() public pure returns (uint argc) {
    //        return 1;
    //     }

    //     // Get the signal key
    //     function get_Alert_key() public view returns (bytes32 key) {
    //        return Alert_key;
    //     }

    //     // Get the data slot
    //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
    //        return Alert_dataslot;
    //     }

    //     // signal Alert construction
    //     // This should be called once in the contract construction.
    //     // This parser should automatically call it.
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(1, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, Alert_data_slot)
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////


    //     function send_alert(bytes32 data) public {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // emitsig Alert(data).delay(10)

    //         // Set the data field in the signal
    //         set_Alert_data(data);
    //         // Get the argument count
    //         uint this_emitsig_Alert_argc = get_Alert_argc();
    //         // Get the data slot
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         // Get the signal key
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         // Use assembly to emit the signal and queue up slot transactions
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 10, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    Alert();
    // }
    // }
    // contract Receiver {
    //     bytes32 data;
    //     uint32 alert_count;

    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // slot Receive {...}

    //     // Generated variables that represent the slot
    //     uint private Receive_status;
    //     bytes32 private Receive_key;

    //     // Get the signal key
    //     function get_Receive_key() public view returns (bytes32 key) {
    //        return Receive_key;
    //     }

    //     // Receive construction
    //     // Should be called once in the contract construction
    //     function Receive() private {
    //         Receive_key = keccak256("Receive_func(bytes32)");
    //         assembly {
    //             sstore(Receive_status_slot, createslot(1, 10, 30000, sload(Receive_key_slot)))
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////

    //     // Receive code to be executed
    //     // The slot is converted to a function that will be called in slot transactions.
    //     function Receive_func(bytes32 incoming_data) public {
    //         data = incoming_data;
    //         alert_count = alert_count + 1;
    //     }
    //     function get_data() public view returns (bytes32 ret) {
    //         ret = data;
    //     }
    //     function get_alert_count() public view returns (uint32 ret) {
    //         ret = alert_count;
    //     }
    //     function bind_to_signal(address emitter) public view {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // Receive.bind(emitter.Alert)

    //         // Convert to address
    //         address emitter_bindslot_address = address(emitter);
    //         // Get signal key from emitter contract
    //         bytes32 emitter_bindslot_Alert_key = keccak256("Alert()");
    //         // Get slot key from receiver contract
    //         bytes32 this_emitter_bindslot_Receive_key = get_Receive_key();
    //         // Use assembly to bind slot to signal
    //         assembly {
    //             mstore(0x40, bindslot(emitter_bindslot_address, emitter_bindslot_Alert_key, this_emitter_bindslot_Receive_key))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    //     constructor() public {
    //    Receive();
    //         data = 0;
    //         alert_count = 0;
    //     }
    // }

    // Test outline:
    // 1. Deploy both contract accounts
    // 2. Bind to each signal
    // 3. Emit both signals in succession
    // 4. Verify that one slot transaction arrives on time
    // 5. Verify that data is transferred over successfully
    // 6. Drain epoch 10
    // 7. Verify that slot transaction is transferred over to the receiver

    // VM and state setup.
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec(env.number);

    // Create a sender account and give it balance.
    let sender = Random.generate().unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // Deploy contract accounts using the sender balance.
    let emit_late_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b
        610070565b60405180807f416c657274282900000000000000000000000000000
        00000000000000000000081525060070190506040518091039020600381905550
        6003546001c06002556000600155565b61019c8061007f6000396000f3fe60806
        0405234801561001057600080fd5b506004361061004c5760003560e01c806365
        410bf114610051578063b5d359171461006f578063dd5e12011461009d578063e
        0b31950146100bb575b600080fd5b6100596100d9565b60405180828152602001
        91505060405180910390f35b61009b6004803603602081101561008557600080f
        d5b81019080803590602001909291905050506100e3565b005b6100a561011f56
        5b6040518082815260200191505060405180910390f35b6100c3610129565b604
        0518082815260200191505060405180910390f35b6000600354905090565b6100
        ec81610132565b60006100f6610129565b9050600061010261011f565b9050600
        061010e6100d9565b90508282600a83c460405250505050565b60006001549050
        90565b60006001905090565b806000819055505056fea26469706673582212201
        14d561e782f1e462bc135b2bc0051bcfdd5902ca7166bb9c6960d5ecdc94cb764
        736f6c63782c302e362e31312d646576656c6f702e323032302e372e32322b636
        f6d6d69742e36646666643637632e6d6f64005d"
        .from_hex()
        .unwrap();
    let emit_late_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(0),
        &emit_late_code,
    ).0;
    let emit_late_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: emit_late_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(0),
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
        ex.transact(&emit_late_creation_tx).unwrap()
    };
    assert!(state.is_contract(&emit_late_address));

    let emit_on_time_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565
        b610070565b60405180807f416c6572742829000000000000000000000000000
        0000000000000000000000081525060070190506040518091039020600381905
        5506003546001c06002556000600155565b61019c8061007f6000396000f3fe6
        08060405234801561001057600080fd5b506004361061004c5760003560e01c8
        06365410bf114610051578063b5d359171461006f578063dd5e12011461009d5
        78063e0b31950146100bb575b600080fd5b6100596100d9565b6040518082815
        260200191505060405180910390f35b61009b600480360360208110156100855
        7600080fd5b81019080803590602001909291905050506100e3565b005b6100a
        561011f565b6040518082815260200191505060405180910390f35b6100c3610
        129565b6040518082815260200191505060405180910390f35b6000600354905
        090565b6100ec81610132565b60006100f6610129565b9050600061010261011
        f565b9050600061010e6100d9565b90508282600083c460405250505050565b6
        000600154905090565b60006001905090565b806000819055505056fea264697
        0667358221220da595e67dd5d008658bab4cda6de617838d83fd5d8c9bfc9cdf
        fb1478cb1d24964736f6c63782c302e362e31312d646576656c6f702e3230323
        02e372e32322b636f6d6d69742e36646666643637632e6d6f64005d"
        .from_hex()
        .unwrap();
    let emit_on_time_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(1),
        &emit_on_time_code,
    ).0;
    let emit_on_time_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: emit_on_time_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(1),
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
        ex.transact(&emit_on_time_creation_tx).unwrap();
    };
    assert!(state.is_contract(&emit_on_time_address));

    let receiver_code =
        "608060405234801561001057600080fd5b5061001f61005060201b60201c56
        5b6000801b6000819055506000600160006101000a81548163ffffffff02191
        6908363ffffffff16021790555061009c565b60405180807f52656365697665
        5f66756e6328627974657333322900000000000000000000008152506015019
        0506040518091039020600381905550600354617530600a6001c1600255565b
        610258806100ab6000396000f3fe608060405234801561001057600080fd5b5
        0600436106100575760003560e01c80630eea95011461005c5780634b918fee
        1461008a57806350bf8b0d146100a85780635e69ae7e146100c6578063fa7d8
        4831461010a575b600080fd5b61008860048036036020811015610072576000
        80fd5b8101908080359060200190929190505050610134565b005b610092610
        173565b6040518082815260200191505060405180910390f35b6100b061017d
        565b6040518082815260200191505060405180910390f35b610108600480360
        360208110156100dc57600080fd5b81019080803573ffffffffffffffffffff
        ffffffffffffffffffff169060200190929190505050610186565b005b61011
        26101de565b604051808263ffffffff1663ffffffff16815260200191505060
        405180910390f35b8060008190555060018060009054906101000a900463fff
        fffff1601600160006101000a81548163ffffffff021916908363ffffffff16
        021790555050565b6000600354905090565b60008054905090565b600081905
        0600060405180807f416c657274282900000000000000000000000000000000
        00000000000000000081525060070190506040518091039020905060006101c
        f610173565b9050808284c260405250505050565b6000600160009054906101
        000a900463ffffffff1690509056fea2646970667358221220b62b1f0beb11f
        eb951a268f4da319e486f417e374b2bbe28b24f0d79de04e73464736f6c6378
        2c302e362e31312d646576656c6f702e323032302e372e32322b636f6d6d697
        42e36646666643637632e6d6f64005d"
        .from_hex()
        .unwrap();
    let receiver_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(2),
        &receiver_code,
    ).0;
    let receiver_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: receiver_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(2),
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
        ex.transact(&receiver_creation_tx)
    };
    assert!(state.is_contract(&receiver_address));

    // Bind receiver to each of the signals.
    // keccak256("bind_to_signal(address)") = 5e69ae7e29957ae633e7e1889ffff5e98388c08ac61025880730a9e4a5249f85
    // keccak256("get_alert_count()") = fa7d8483cb3c806d0cc2c575057b74d506ce0f06ef1cffc927b500ddc29c82c0
    // keccak256("get_data()") = 50bf8b0d9555c4c967ba76650ec27a097cd05a0fdb928be06dad27b5ca0f2b2d
    let mut receiver_bind_call_data = "5e69ae7e".from_hex().unwrap();
    receiver_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    receiver_bind_call_data.extend_from_slice(&emit_late_address[..]);
    let receiver_bind_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: receiver_bind_call_data.clone(),
        gas: U256::from(200000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(3),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    let mut receiver_bind_call_data = "5e69ae7e".from_hex().unwrap();
    receiver_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    receiver_bind_call_data.extend_from_slice(&emit_on_time_address[..]);
    let receiver_bind_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: receiver_bind_call_data.clone(),
        gas: U256::from(200000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(4),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Gas up...
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // Emit both the signals.
    // keccak("send_alert(bytes32)) = b5d3591711ff1f95e39893400602222afd9c57badda564e992f77a8aa4b6d250
    let mut emit_late_call_data = "b5d35917".from_hex().unwrap();
    emit_late_call_data.extend_from_slice(
        &(vec![0u8; 32 - 4])[..]
    );
    emit_late_call_data.extend_from_slice(&("deadbeef".from_hex().unwrap()));
    let emit_late_tx = Transaction {
        action: Action::Call(emit_late_address.clone()),
        value: U256::from(0),
        data: emit_late_call_data.clone(),
        gas: U256::from(200000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(5),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&emit_late_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    let mut emit_on_time_call_data = "b5d35917".from_hex().unwrap();
    emit_on_time_call_data.extend_from_slice(
        &(vec![0u8; 32 - 4])[..]
    );
    emit_on_time_call_data.extend_from_slice(&("abcdabcd".from_hex().unwrap()));
    let emit_on_time_tx = Transaction {
        action: Action::Call(emit_on_time_address.clone()),
        value: U256::from(0),
        data: emit_on_time_call_data.clone(),
        gas: U256::from(200000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(6),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&emit_on_time_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Check to see what the slot tx queues look like.
    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert!(slot_tx_queue.len() == 1);

    state
        .drain_global_slot_tx_queue(10)
        .expect("No db errors!");

    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert!(slot_tx_queue.len() == 2);

    // TODO: Check to see if the slottx's are correct.
}

// #[test]
// fn test_bind_detach() {
//     // BEFORE PARSING:
//     //
//     // pragma solidity ^0.6.9;
//     // contract Emitter {
//     //     signal Alert();
//     //     function send_alert() public view {
//     //         emitsig Alert().delay(0);
//     //     }
//     // }
//     // contract Receiver {
//     //     uint data;
//     //     address source;
//     //     slot HandleAlert() {
//     //         data = 0;
//     //     }
//     //     function set_source(address addr) public {
//     //         source = addr;
//     //     }
//     //     function bind_to_alert() public view {
//     //         HandleAlert.bind(source.Alert);
//     //     }
//     //     function detach_from_alert() public view {
//     //         HandleAlert.detach(source.Alert);
//     //     }
//     // }
//     //
//     // AFTER PARSING:
//     //
//     // pragma solidity ^0.6.9;

//     // contract Emitter {
//     //     //////////////////////////////////////////////////////////////////////////////////////////////////
//     //     // GENERATED BY SIGNALSLOT PARSER

//     //     // Original Code:
//     //     // signal Alert;

//     //     // TODO: Arguments should not be limited to one 32 byte value

//     //     // Generated variables that represent the signal
//     //     bytes32 private Alert_data;
//     //     bytes32 private Alert_dataslot;
//     //     uint private Alert_status;
//     //     bytes32 private Alert_key;

//     //     // Set the data to be emitted
//     //     function set_Alert_data(bytes32  dataSet) private {
//     //        Alert_data = dataSet;
//     //     }

//     //     // Get the argument count
//     //     function get_Alert_argc() public pure returns (uint argc) {
//     //        return 1;
//     //     }

//     //     // Get the signal key
//     //     function get_Alert_key() public view returns (bytes32 key) {
//     //        return Alert_key;
//     //     }

//     //     // Get the data slot
//     //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
//     //        return Alert_dataslot;
//     //     }

//     //     // signal Alert construction
//     //     // This should be called once in the contract construction.
//     //     // This parser should automatically call it.
//     //     function Alert() private {
//     //         Alert_key = keccak256("Alert()");
//     //         assembly {
//     //             sstore(Alert_status_slot, createsig(1, sload(Alert_key_slot)))
//     //             sstore(Alert_dataslot_slot, Alert_data_slot)
//     //         }
//     //     }
//     //     //////////////////////////////////////////////////////////////////////////////////////////////////


//     //     function send_alert(bytes32 value) public {
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////
//     //         // GENERATED BY SIGNALSLOT PARSER

//     //         // Original Code:
//     //         // emitsig Alert(value).delay(0)

//     //         // Set the data field in the signal
//     //         set_Alert_data(value);
//     //         // Get the argument count
//     //         uint this_emitsig_Alert_argc = get_Alert_argc();
//     //         // Get the data slot
//     //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
//     //         // Get the signal key
//     //         bytes32 this_emitsig_Alert_key = get_Alert_key();
//     //         // Use assembly to emit the signal and queue up slot transactions
//     //         assembly {
//     //             mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
//     //         }
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////

//     //     }
//     // constructor() public {
//     //    Alert();
//     // }
//     // }

//     // contract Receiver {
//     //     Emitter source;
//     //     bytes32 private data;

//     //     //////////////////////////////////////////////////////////////////////////////////////////////////
//     //     // GENERATED BY SIGNALSLOT PARSER

//     //     // Original Code:
//     //     // slot HandleAlert {...}

//     //     // Generated variables that represent the slot
//     //     uint private HandleAlert_status;
//     //     bytes32 private HandleAlert_key;

//     //     // Get the signal key
//     //     function get_HandleAlert_key() public view returns (bytes32 key) {
//     //        return HandleAlert_key;
//     //     }

//     //     // HandleAlert construction
//     //     // Should be called once in the contract construction
//     //     function HandleAlert() private {
//     //         HandleAlert_key = keccak256("HandleAlert_func(bytes32)");
//     //         assembly {
//     //             sstore(HandleAlert_status_slot, createslot(1, 10, 30000, sload(HandleAlert_key_slot)))
//     //         }
//     //     }
//     //     //////////////////////////////////////////////////////////////////////////////////////////////////

//     //     // HandleAlert code to be executed
//     //     // The slot is converted to a function that will be called in slot transactions.
//     //     function HandleAlert_func(bytes32 value) public {
//     //         data = value;
//     //     }

//     //     function get_data() public view returns (bytes32 ret) {
//     //         ret = data;
//     //     }

//     //     function bind_to_alert() public view {
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////
//     //         // GENERATED BY SIGNALSLOT PARSER

//     //         // Original Code:
//     //         // HandleAlert.bind(source.Alert)

//     //         // Convert to address
//     //         address source_bindslot_address = address(source);
//     //         // Get signal key from emitter contract
//     //         bytes32 source_bindslot_Alert_key = keccak256("Alert()");
//     //         // Get slot key from receiver contract
//     //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
//     //         // Use assembly to bind slot to signal
//     //         assembly {
//     //             mstore(0x40, bindslot(source_bindslot_address, source_bindslot_Alert_key, this_source_bindslot_HandleAlert_key))
//     //         }
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////

//     //     }

//     //     function detach_from_alert() public view {
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////
//     //         // GENERATED BY SIGNALSLOT PARSER

//     //         // Original Code:
//     //         // this.HandleAlert.detach(source.Alert)

//     //         // Get the signal key
//     //         bytes32 source_detach_Alert_key = keccak256("Alert()");
//     //         // Get the address
//     //         address source_detach_address = address(source);
//     //         //Get the slot key
//     //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
//     //         // Use assembly to detach the slot
//     //         assembly{
//     //             mstore(0x40, detachslot(source_detach_address, source_detach_Alert_key, this_source_bindslot_HandleAlert_key))
//     //         }
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////

//     //     }

//     //     constructor(Emitter addr) public {
//     //    HandleAlert();
//     //         source = addr;
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////
//     //         // GENERATED BY SIGNALSLOT PARSER

//     //         // Original Code:
//     //         // HandleAlert.bind(source.Alert)

//     //         // Convert to address
//     //         address source_bindslot_address = address(source);
//     //         // Get signal key from emitter contract
//     //         bytes32 source_bindslot_Alert_key = keccak256("Alert()");
//     //         // Get slot key from receiver contract
//     //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
//     //         // Use assembly to bind slot to signal
//     //         assembly {
//     //             mstore(0x40, bindslot(source_bindslot_address, source_bindslot_Alert_key, this_source_bindslot_HandleAlert_key))
//     //         }
//     //         //////////////////////////////////////////////////////////////////////////////////////////////////

//     //     }
//     // }

//     // Test overview.
//     // 1. Deploy contract accounts
//     // 2. Bind slot to signal
//     // 3. Emit signal
//     // 4. Verify that slottx was created
//     // 5. Detach slot from signal
//     // 6. Emit signal
//     // 7. Verify that slottx was not created

//     // VM and state setup.
//     let factory = Factory::new(VMType::Interpreter, 1024 * 32);
//     let storage_manager = new_state_manager_for_unit_test();
//     let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
//     let machine = make_byzantium_machine(0);
//     let internal_contract_map = InternalContractMap::new();
//     let mut env = Env::default();
//     env.gas_limit = U256::MAX;
//     let spec = machine.spec(env.number);

//     // Create a sender account and give it balance.
//     let sender = Random.generate().unwrap();
//     state
//         .add_balance(
//             &sender.address(),
//             &U256::from(9_000_000_000_000_210_010u64),
//             CleanupMode::NoEmpty,
//         )
//         .unwrap();

//     // Deploy contracts
//     let emitter_code =
//         "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070
//         565b60405180807f416c657274282900000000000000000000000000000000000000000
//         000000000815250600701905060405180910390206003819055506003546001c0600255
//         6000600155565b61019c8061007f6000396000f3fe60806040523480156100105760008
//         0fd5b506004361061004c5760003560e01c806365410bf114610051578063b5d3591714
//         61006f578063dd5e12011461009d578063e0b31950146100bb575b600080fd5b6100596
//         100d9565b6040518082815260200191505060405180910390f35b61009b600480360360
//         2081101561008557600080fd5b81019080803590602001909291905050506100e3565b0
//         05b6100a561011f565b6040518082815260200191505060405180910390f35b6100c361
//         0129565b6040518082815260200191505060405180910390f35b6000600354905090565
//         b6100ec81610132565b60006100f6610129565b9050600061010261011f565b90506000
//         61010e6100d9565b90508282600083c460405250505050565b6000600154905090565b6
//         0006001905090565b806000819055505056fea2646970667358221220dfecc7b346bf9a
//         2f34e5cdf713d1c81b2a915e2e7b8927f88fa5d91400bc9bcc64736f6c63782c302e362
//         e31312d646576656c6f702e323032302e372e32322b636f6d6d69742e36646666643637
//         632e6d6f64005d"
//         .from_hex()
//         .unwrap();
//     let emitter_address = contract_address(
//         CreateContractAddress::FromSenderNonceAndCodeHash,
//         &sender.address(),
//         &U256::from(0),
//         &emitter_code,
//     ).0;
//     let emitter_creation_tx = Transaction {
//         action: Action::Create,
//         value: U256::from(0),
//         data: emitter_code.clone(),
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(0),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let _res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&emitter_creation_tx)
//     };
//     assert!(state.is_contract(&emitter_address));
//     state
//         .add_balance(
//             &sender.address(),
//             &U256::from(9_000_000_000_000_210_010u64),
//             CleanupMode::NoEmpty,
//         )
//         .unwrap();
//     let receiver_code =
//         "608060405234801561001057600080fd5b506040516103c13803806103c18339818
//         101604052602081101561003357600080fd5b8101908080519060200190929190505
//         05061005261011460201b60201c565b806000806101000a81548173fffffffffffff
//         fffffffffffffffffffffffffff021916908373fffffffffffffffffffffffffffff
//         fffffffffff16021790555060008060009054906101000a900473fffffffffffffff
//         fffffffffffffffffffffffff169050600060405180807f416c65727428290000000
//         00000000000000000000000000000000000000000008152506007019050604051809
//         10390209050600061010261016060201b60201c565b9050808284c26040525050505
//         061016a565b60405180807f48616e646c65416c6572745f66756e632862797465733
//         33229000000000000008152506019019050604051809103902060038190555060035
//         4617530600a6001c1600255565b6000600354905090565b610248806101796000396
//         000f3fe608060405234801561001057600080fd5b50600436106100575760003560e
//         01c80630e3b85901461005c57806314583309146100665780631671379c146100705
//         7806350bf8b0d1461009e5780639981f1bc146100bc575b600080fd5b6100646100d
//         a565b005b61006e610152565b005b61009c600480360360208110156100865760008
//         0fd5b81019080803590602001909291905050506101ca565b005b6100a66101d4565
//         b6040518082815260200191505060405180910390f35b6100c46101de565b6040518
//         082815260200191505060405180910390f35b600060405180807f416c65727428290
//         00000000000000000000000000000000000000000000000008152506007019050604
//         0518091039020905060008060009054906101000a900473fffffffffffffffffffff
//         fffffffffffffffffff16905060006101446101de565b9050808383c360405250505
//         0565b60008060009054906101000a900473fffffffffffffffffffffffffffffffff
//         fffffff169050600060405180807f416c65727428290000000000000000000000000
//         00000000000000000000000008152506007019050604051809103902090506000610
//         1bc6101de565b9050808284c2604052505050565b8060018190555050565b6000600
//         154905090565b600060035490509056fea2646970667358221220b98bd84e059e88c
//         61ab5dee8e328f6a357c23be5407f7e5826a30469d22710ae64736f6c63782c302e3
//         62e31312d646576656c6f702e323032302e372e32322b636f6d6d69742e366466666
//         43637632e6d6f64005d"
//         .from_hex()
//         .unwrap();
//     let receiver_address = contract_address(
//         CreateContractAddress::FromSenderNonceAndCodeHash,
//         &sender.address(),
//         &U256::from(1),
//         &receiver_code,
//     ).0;
//     let receiver_creation_tx = Transaction {
//         action: Action::Create,
//         value: U256::from(0),
//         data: receiver_code.clone(),
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(1),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let _res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&receiver_creation_tx)
//     };
//     assert!(state.is_contract(&receiver_address));

//     // Give emitter address to receiver.
//     // keccak("set_source(address)") = 2de681ebdca726d72c94bf1523fb481dc947bdf132d3b75dffb3671b5bcfb042
//     let mut set_source_call_data = "2de681eb".from_hex().unwrap();
//     set_source_call_data.extend_from_slice(
//         &(vec![0u8; 32 - 20])[..]
//     );
//     set_source_call_data.extend_from_slice(&emitter_address[..]);
//     let set_source_tx = Transaction {
//         action: Action::Call(receiver_address.clone()),
//         value: U256::from(0),
//         data: set_source_call_data,
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(2),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&set_source_tx).unwrap()
//     };
//     assert!(res.successfully_executed().is_some());

//     // Bind slot to signal.
//     // keccak256("bind_to_alert()") = 14583309ad14d9f5f5ada6b94129244a6e5c5eb0d21ac966c65d03b8305854a1
//     let bind_call_data = "14583309".from_hex().unwrap();
//     let bind_tx = Transaction {
//         action: Action::Call(receiver_address.clone()),
//         value: U256::from(0),
//         data: bind_call_data,
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(3),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&bind_tx).unwrap()
//     };
//     assert!(res.successfully_executed().is_some());

//     // Emit signal.
//     // keccak256("send_alert()") = 7ced953e3a98fed2864b59f525e7909dcb6165ad544dfec26c846abd73b6b8e1
//     let emit_call_data = "7ced953e".from_hex().unwrap();
//     let emit_tx = Transaction {
//         action: Action::Call(emitter_address.clone()),
//         value: U256::from(0),
//         data: emit_call_data,
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(4),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&emit_tx).unwrap()
//     };
//     assert!(res.successfully_executed().is_some());

//     // Verify that slottx has been generated.
//     let slot_tx_queue = state
//         .get_account_slot_tx_queue(&receiver_address)
//         .expect("No db errors pls");
//     assert!(slot_tx_queue.len() == 1);

//     // Gas Up!
//     state
//     .add_balance(
//         &sender.address(),
//         &U256::from(9_000_000_000_000_210_010u64),
//         CleanupMode::NoEmpty,
//     )
//     .unwrap();

//     // Detach slot from signal.
//     // keccak256("detach_from_alert()") = 0e3b8590bd5848e66f1d64b50c2998d1a10b7c8ff9d3296df4ec7c445f290d11
//     let detach_call_data = "0e3b8590".from_hex().unwrap();
//     let detach_tx = Transaction {
//         action: Action::Call(receiver_address.clone()),
//         value: U256::from(0),
//         data: detach_call_data,
//         gas: U256::from(10800000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(10000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(5),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&detach_tx).unwrap()
//     };
//     assert!(res.successfully_executed().is_some());

//     // Emit a signal again.
//     let emit_call_data = "7ced953e".from_hex().unwrap();
//     let emit_tx = Transaction {
//         action: Action::Call(emitter_address.clone()),
//         value: U256::from(0),
//         data: emit_call_data,
//         gas: U256::from(1080000),
//         gas_price: U256::one(),
//         storage_limit: U256::from(1000),
//         epoch_height: 0,
//         chain_id: 0,
//         nonce: U256::from(6),
//         slot_tx: None,
//     }
//     .sign(sender.secret());
//     let res = {
//         let mut ex = Executive::new(
//             &mut state,
//             &env,
//             &machine,
//             &spec,
//             &internal_contract_map,
//         );
//         ex.transact(&emit_tx).unwrap()
//     };
//     assert!(res.successfully_executed().is_some());

//     // Verify that no new slot tx has been created.
//     let slot_tx_queue = state
//         .get_account_slot_tx_queue(&receiver_address)
//         .expect("No db errors pls");
//     assert!(slot_tx_queue.len() == 1);
// }

#[test]
fn test_bind_detach_v2() {
    // BEFORE PARSING:
    //
    // pragma solidity ^0.6.9;
    // contract Emitter {
    //     signal Alert();
    //     function send_alert() public view {
    //         emitsig Alert().delay(0);
    //     }
    // }
    // contract Receiver {
    //     uint data;
    //     address source;
    //     slot HandleAlert() {
    //         data = 0;
    //     }
    //     function set_source(address addr) public {
    //         source = addr;
    //     }
    //     function bind_to_alert() public view {
    //         HandleAlert.bind(source.Alert);
    //     }
    //     function detach_from_alert() public view {
    //         HandleAlert.detach(source.Alert);
    //     }
    // }
    //
    // AFTER PARSING:
    //
    // pragma solidity ^0.6.9;

    // contract Emitter {
    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // signal Alert;

    //     // TODO: Arguments should not be limited to one 32 byte value

    //     // Generated variables that represent the signal
    //     bytes32 private Alert_data;
    //     bytes32 private Alert_dataslot;
    //     uint private Alert_status;
    //     bytes32 private Alert_key;

    //     // Set the data to be emitted
    //     function set_Alert_data(bytes32  dataSet) private {
    //        Alert_data = dataSet;
    //     }

    //     // Get the argument count
    //     function get_Alert_argc() public pure returns (uint argc) {
    //        return 1;
    //     }

    //     // Get the signal key
    //     function get_Alert_key() public view returns (bytes32 key) {
    //        return Alert_key;
    //     }

    //     // Get the data slot
    //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
    //        return Alert_dataslot;
    //     }

    //     // signal Alert construction
    //     // This should be called once in the contract construction.
    //     // This parser should automatically call it.
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(1, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, Alert_data_slot)
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////


    //     function send_alert(bytes32 value) public {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // emitsig Alert(value).delay(0)

    //         // Set the data field in the signal
    //         set_Alert_data(value);
    //         // Get the argument count
    //         uint this_emitsig_Alert_argc = get_Alert_argc();
    //         // Get the data slot
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         // Get the signal key
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         // Use assembly to emit the signal and queue up slot transactions
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }
    // constructor() public {
    //    Alert();
    // }
    // }

    // contract Receiver {
    //     Emitter source;
    //     bytes32 private data;

    //     //////////////////////////////////////////////////////////////////////////////////////////////////
    //     // GENERATED BY SIGNALSLOT PARSER

    //     // Original Code:
    //     // slot HandleAlert {...}

    //     // Generated variables that represent the slot
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;

    //     // Get the signal key
    //     function get_HandleAlert_key() public view returns (bytes32 key) {
    //        return HandleAlert_key;
    //     }

    //     // HandleAlert construction
    //     // Should be called once in the contract construction
    //     function HandleAlert() private {
    //         HandleAlert_key = keccak256("HandleAlert_func(bytes32)");
    //         assembly {
    //             sstore(HandleAlert_status_slot, createslot(1, 10, 30000, sload(HandleAlert_key_slot)))
    //         }
    //     }
    //     //////////////////////////////////////////////////////////////////////////////////////////////////

    //     // HandleAlert code to be executed
    //     // The slot is converted to a function that will be called in slot transactions.
    //     function HandleAlert_func(bytes32 value) public {
    //         data = value;
    //     }

    //     function get_data() public view returns (bytes32 ret) {
    //         ret = data;
    //     }

    //     function bind_to_alert(Emitter addr) public{
    //         source = addr;
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // HandleAlert.bind(source.Alert)

    //         // Convert to address
    //         address source_bindslot_address = address(source);
    //         // Get signal key from emitter contract
    //         bytes32 source_bindslot_Alert_key = keccak256("Alert()");
    //         // Get slot key from receiver contract
    //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
    //         // Use assembly to bind slot to signal
    //         assembly {
    //             mstore(0x40, bindslot(source_bindslot_address, source_bindslot_Alert_key, this_source_bindslot_HandleAlert_key))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }

    //     function detach_from_alert() public view {
    //         //////////////////////////////////////////////////////////////////////////////////////////////////
    //         // GENERATED BY SIGNALSLOT PARSER

    //         // Original Code:
    //         // this.HandleAlert.detach(source.Alert)

    //         // Get the signal key
    //         bytes32 source_detach_Alert_key = keccak256("Alert()");
    //         // Get the address
    //         address source_detach_address = address(source);
    //         //Get the slot key
    //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
    //         // Use assembly to detach the slot
    //         assembly{
    //             mstore(0x40, detachslot(source_detach_address, source_detach_Alert_key, this_source_bindslot_HandleAlert_key))
    //         }
    //         //////////////////////////////////////////////////////////////////////////////////////////////////

    //     }

    // constructor() public {
    //    HandleAlert();
    // }
    // }

    // Test overview.
    // 1. Deploy contract accounts
    // 2. Bind slot to signal
    // 3. Emit signal
    // 4. Verify that slottx was created
    // 5. Detach slot from signal
    // 6. Emit signal
    // 7. Verify that slottx was not created

    // VM and state setup.
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec(env.number);

    // Create a sender account and give it balance.
    let sender = Random.generate().unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // Deploy contracts
    let emitter_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070
        565b60405180807f416c657274282900000000000000000000000000000000000000000
        000000000815250600701905060405180910390206003819055506003546001c0600255
        6000600155565b61019c8061007f6000396000f3fe60806040523480156100105760008
        0fd5b506004361061004c5760003560e01c806365410bf114610051578063b5d3591714
        61006f578063dd5e12011461009d578063e0b31950146100bb575b600080fd5b6100596
        100d9565b6040518082815260200191505060405180910390f35b61009b600480360360
        2081101561008557600080fd5b81019080803590602001909291905050506100e3565b0
        05b6100a561011f565b6040518082815260200191505060405180910390f35b6100c361
        0129565b6040518082815260200191505060405180910390f35b6000600354905090565
        b6100ec81610132565b60006100f6610129565b9050600061010261011f565b90506000
        61010e6100d9565b90508282600083c460405250505050565b6000600154905090565b6
        0006001905090565b806000819055505056fea2646970667358221220cf3afad188efec
        92fcbc4110aeaa87a0f001cadf269a31688c098b79c5625db964736f6c63782c302e362
        e31312d646576656c6f702e323032302e372e32322b636f6d6d69742e36646666643637
        632e6d6f64005d"
        .from_hex()
        .unwrap();
    let emitter_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(0),
        &emitter_code,
    ).0;
    let emitter_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: emitter_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(0),
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
        ex.transact(&emitter_creation_tx)
    };
    assert!(state.is_contract(&emitter_address));
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let receiver_code =
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b
        60405180807f48616e646c65416c6572745f66756e632862797465733332290000000000000
        081525060190190506040518091039020600381905550600354617530600a6001c160025556
        5b6102c38061007f6000396000f3fe608060405234801561001057600080fd5b50600436106
        100575760003560e01c80630e3b85901461005c5780631671379c146100665780633e2f5fe5
        1461009457806350bf8b0d146100d85780639981f1bc146100f6575b600080fd5b610064610
        114565b005b6100926004803603602081101561007c57600080fd5b81019080803590602001
        9092919050505061018c565b005b6100d6600480360360208110156100aa57600080fd5b810
        19080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050
        610196565b005b6100e061024f565b6040518082815260200191505060405180910390f35b6
        100fe610259565b6040518082815260200191505060405180910390f35b600060405180807f
        416c65727428290000000000000000000000000000000000000000000000000081525060070
        190506040518091039020905060008060009054906101000a900473ffffffffffffffffffff
        ffffffffffffffffffff169050600061017e610259565b9050808383c3604052505050565b8
        060018190555050565b806000806101000a81548173ffffffffffffffffffffffffffffffff
        ffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600
        08060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905060
        0060405180807f416c657274282900000000000000000000000000000000000000000000000
        0008152506007019050604051809103902090506000610240610259565b9050808284c26040
        5250505050565b6000600154905090565b600060035490509056fea26469706673582212201
        c894b53dadbb14a891d7e56e5daafee8aabc871c061f59c40c3ee3d7b1affe864736f6c6378
        2c302e362e31312d646576656c6f702e323032302e372e32322b636f6d6d69742e366466666
        43637632e6d6f64005d"
        .from_hex()
        .unwrap();
    let receiver_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(1),
        &receiver_code,
    ).0;
    let receiver_creation_tx = Transaction {
        action: Action::Create,
        value: U256::from(0),
        data: receiver_code.clone(),
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(1),
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
        ex.transact(&receiver_creation_tx)
    };
    assert!(state.is_contract(&receiver_address));
    // Bind slot to signal.
    // keccak256("bind_to_alert(address)") = 3e2f5fe5be1d07de87002290543224120f0c99f35cfcbb53c397a211e4e3edea
    let mut bind_call_data = "3e2f5fe5".from_hex().unwrap();
    bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    bind_call_data.extend_from_slice(&emitter_address[..]);
    let bind_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: bind_call_data,
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(2),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Emit signal.
    // keccak256("send_alert(bytes32)") = b5d3591711ff1f95e39893400602222afd9c57badda564e992f77a8aa4b6d250
    let mut emit_call_data = "b5d35917".from_hex().unwrap();
    emit_call_data.extend_from_slice(
        &[255u8,254u8]
    );
    emit_call_data.extend_from_slice(
        &(vec![0u8; 32 - 4])[..]
    );
    emit_call_data.extend_from_slice(
        &[253u8,252u8]
    );
    println!("now emit_call_data is {:?}",emit_call_data);
    let emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emit_call_data,
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(3),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Verify that slottx has been generated.
    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert!(slot_tx_queue.len() == 1);
    state.dequeue_slot_tx_from_account(&receiver_address).expect("No slottx found");
    // Gas Up!
    state
    .add_balance(
        &sender.address(),
        &U256::from(9_000_000_000_000_210_010u64),
        CleanupMode::NoEmpty,
    )
    .unwrap();

    // Detach slot from signal.
    // keccak256("detach_from_alert()") = 0e3b8590bd5848e66f1d64b50c2998d1a10b7c8ff9d3296df4ec7c445f290d11
    let detach_call_data = "0e3b8590".from_hex().unwrap();
    let detach_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: detach_call_data,
        gas: U256::from(10800000),
        gas_price: U256::one(),
        storage_limit: U256::from(10000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(4),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&detach_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Emit a signal again.
    // keccak256("send_alert(bytes32)") = b5d3591711ff1f95e39893400602222afd9c57badda564e992f77a8aa4b6d250
    let mut emit_call_data = "b5d35917".from_hex().unwrap();
    emit_call_data.extend_from_slice(
        &[1u8,2u8]
    );
    emit_call_data.extend_from_slice(
        &(vec![0u8; 32 - 4])[..]
    );
    emit_call_data.extend_from_slice(
        &[3u8,4u8]
    );
    let emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emit_call_data,
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(1000),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(5),
        slot_tx: None,
    }
    .sign(sender.secret());
    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Verify that no new slot tx has been created.
    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert_eq!(slot_tx_queue.len(), 0);
}

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
