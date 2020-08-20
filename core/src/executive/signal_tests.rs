//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use super::{executive::*, internal_contract::*};
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

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::new_machine_with_builtin();
    machine
        .set_spec_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
    machine
}

// Signal and handler creation.
// No argument emit functionality.
// Bind and detach functionality.
#[test]
fn test_bind_and_detach() {
    //////////////////////////////////////////////////////////////////////////////////////////
    // BEFORE PARSING 
    //
    // contract Emitter {
    //     signal Alert();
    //     function emit_alert() public view {
    //         Alert.emit().delay(0);
    //     }
    //     constructor() {
    //         Alert.create_signal();
    //     }
    // }
    // contract Receiver {
    //     uint updated;
    //     handler Receive();
    //     function update_data() public {
    //         updated = 1;
    //         return;
    //     }
    //     function bind_to_alert(address source) public view {
    //         Receive.bind(source, "Alert()");
    //     }
    //     function detach_from_alert(address source) public view {
    //         Receive.detach(source, "Alert()");
    //     }
    //     constructor() {
    //         Receive.create_handler("update_data()", 100000, 120);
    //         updated = 0;
    //     }
    // }
    //////////////////////////////////////////////////////////////////////////////////////////
    // AFTER PARSING 
    // contract Emitter {
    //     // Original code: signal Alert();
    //     bytes32 private Alert_key;
    //     function set_Alert_key() private {
    //         Alert_key = keccak256("Alert()");
    //     }
    //     ////////////////////
    //     function emit_alert() public view {
    //         // Original code: Alert.emit().delay(0);
    //         assembly {
    //             mstore(
    //                 0x00,
    //                 sigemit(
    //                     sload(Alert_key.slot), 
    //                     0,
    //                     0,
    //                     0
    //                 )
    //             )
    //         }
    //         ////////////////////
    //     }
    //     constructor() {
    //         // Original code: Alert.create_signal();
    //         set_Alert_key();
    //         assembly {
    //             mstore(0x00, createsignal(sload(Alert_key.slot)))
    //         }
    //         ////////////////////
    //     }
    // }
    // contract Receiver {
    //     uint updated;
    //     // Original code: handler Receive;
    //     bytes32 private Receive_key;
    //     function set_Receive_key() private {
    //         Receive_key = keccak256("Receive()");
    //     }
    //     ////////////////////
    //     function update_data() public {
    //         updated = 1;
    //         return;
    //     }
    //     function bind_to_alert(address source) public view {
    //         // Original code: Receive.bind(source,"Alert()");
    //         bytes32 Receive_signal_prototype_hash = keccak256("Alert()");
    //         assembly {
    //             mstore(
    //                 0x00,
    //                 sigbind(
    //                     sload(Receive_key.slot),
    //                     source,
    //                     Receive_signal_prototype_hash
    //                 )
    //             )
    //         }
    //         ////////////////////
    //     }
    //     function detach_from_alert(address source) public view {
    //         // Original code: Receive.detach(source,"Alert()");
    //         bytes32 Receive_signal_prototype_hash = keccak256("Alert()");
    //         assembly {
    //             mstore(
    //                 0x00,
    //                 sigdetach(
    //                     sload(Receive_key.slot),
    //                     source,
    //                     Receive_signal_prototype_hash
    //                 )
    //             )
    //         }
    //         ////////////////////
    //     }
    //     constructor() {
    //         // Original code: Receive.create_handler("update_data()",100000,120);
    //         set_Receive_key();
    //         bytes32 Receive_method_hash = keccak256("update_data()");
    //         uint Receive_gas_limit = 100000;
    //         uint Receive_gas_ratio = 120;
    //         assembly {
    //             mstore(
    //                 0x00, 
    //                 createhandler(
    //                     sload(Receive_key.slot), 
    //                     Receive_method_hash, 
    //                     Receive_gas_limit, 
    //                     Receive_gas_ratio
    //                 )
    //             )
    //         }
    //         ////////////////////
    //         updated = 0;
    //     }
    // }
    //////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////////////////////
    // Set up environment
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec(env.number);
    // Initialize sender. This account pays for all transactions.
    let sender = Random.generate().unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();   

    //////////////////////////////////////////////////////////////////////////////////////////
    // Deploy emitter contract
    let emitter_code =
    "608060405234801561001057600080fd5b5061001f61002b60201b60201c565b600054c0600052610054565b7fffd2909f706e1243eefed477dac70a13bfca2e
    2f005110f7733a1de8f88b47c3600081905550565b60a1806100626000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8
    06353180e3c14602d575b600080fd5b60336035565b005b60008060008054c460005256fea2646970667358221220a22e698f0631e722a34f0550adfb314f8299
    07b60060b0f7c980fff321c3e99864736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d6f640
    05c"
    .from_hex().unwrap();
    // Emitter contract account address.
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

    //////////////////////////////////////////////////////////////////////////////////////////
    // Deploy receiver contract
    let receiver_code =
    "608060405234801561001057600080fd5b5061001f61006b60201b60201c565b60007fc79f5321ec3d769feb76cb965aeebabfc421b9dae7cd4c835ad2a577ad
    5ac1e690506000620186a09050600060789050808284600154c160005260008081905550505050610094565b7f9f1b3bad61172afd7ac57ee5c5873e1c8fad6c4
    b8e0fe408853ffbd909aaa830600181905550565b6101a5806100a36000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560
    e01c80633e2f5fe514610046578063c79f53211461008a578063d00c2d1614610094575b600080fd5b6100886004803603602081101561005c57600080fd5b810
    19080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100d8565b005b61009261010a565b005b6100d660048036036020
    8110156100aa57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610114565b005b60007fffd2909
    f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c390508082600154c26000525050565b6001600081905550565b60007fffd2909f706e1243
    eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c390508082600154c3600052505056fea26469706673582212206ef95e8613471a0d9d99f2810d293f5
    58819769772810a2253ad80dcde715bef64736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d
    6f64005c"
    .from_hex().unwrap();
    // Receiver contract account address.
    let receiver_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(1),
        &receiver_code,
    ).0;
    // Receiver contract creation transaction.
    let receiver_contract_creation_tx = Transaction {
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
    // Execute this transaction.
    let _res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&receiver_contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&receiver_address));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Bind
    let mut receiver_bind_call_data = "3e2f5fe5".from_hex().unwrap(); // KEC("bind_to_alert(address)") = 0x3e2f5fe5...
    receiver_bind_call_data.extend_from_slice(&(vec![0u8; 32 - 20])[..]);
    receiver_bind_call_data.extend_from_slice(&emitter_address[..]);

    let receiver_bind_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: receiver_bind_call_data.clone(),
        gas: U256::from(200000),
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
        ex.transact(&receiver_bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // KEC("Alert()") = 0xffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3
    let signal_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex().unwrap();
    let signal = state
        .signal_at(&emitter_address, &signal_key)
        .expect("Should not get db result")
        .unwrap();
    assert!(signal.slot_list().len() == 1);

    //////////////////////////////////////////////////////////////////////////////////////////
    // Emit
    let emitter_emit_call_data = "53180e3c".from_hex().unwrap(); // KEC("emit_alert()") = 0x53180e3c...
    let emitter_emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emitter_emit_call_data.clone(),
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
        ex.transact(&emitter_emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Check slot tx queue
    assert!(!state.is_account_slot_tx_queue_empty(&receiver_address).expect("Db error not expected!"));
    // Remove that tx so we can do another transaction
    let _slottx = state.dequeue_slot_tx_from_account(&receiver_address).expect("Db error not expected").unwrap();

    //////////////////////////////////////////////////////////////////////////////////////////
    // Detach
    let mut receiver_detach_call_data = "d00c2d16".from_hex().unwrap(); // KEC("detach_from_alert(address)") = 0xd00c2d16...
    receiver_detach_call_data.extend_from_slice(&(vec![0u8; 32 - 20])[..]);
    receiver_detach_call_data.extend_from_slice(&emitter_address[..]);

    let receiver_detach_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: receiver_detach_call_data.clone(),
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
        ex.transact(&receiver_detach_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // KEC("Alert()") = 0xffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3
    let signal_key = "ffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c3"
        .from_hex().unwrap();
    let signal = state
        .signal_at(&emitter_address, &signal_key)
        .expect("Should not get db result")
        .unwrap();
    assert!(signal.slot_list().len() == 0);

    //////////////////////////////////////////////////////////////////////////////////////////
    // Emit
    let emitter_emit_call_data = "53180e3c".from_hex().unwrap(); // KEC("emit_alert()") = 0x53180e3c...
    let emitter_emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emitter_emit_call_data.clone(),
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
        ex.transact(&emitter_emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());
    // Should be empty...
    assert!(state.is_account_slot_tx_queue_empty(&receiver_address).expect("Db error not expected!"));
}

// Multi argument signal emission.
// Delayed signal emission.
#[test]
fn test_signal_multi_arg_emit() {
    //////////////////////////////////////////////////////////////////////////////////////////
    // BEFORE PARSING
    //
    // contract SelfAlerter {
    //     signal BigAlert(string, uint8[5], uint32);
    //     handler BigHandler(string, uint8[5], uint32);
    //     string fooo;
    //     uint8[] barr;
    //     uint32 bazz;
    //     function update(string calldata foo, uint8[5] calldata bar, uint32 baz) public {
    //         fooo = foo;
    //         barr = bar;
    //         bazz = baz;
    //         return;
    //     }
    //     function signal_emit() public view {
    //         string memory foo = "Hello World!";
    //         uint8[5] memory bar = ([1, 1, 2, 2, 4]);
    //         uint32 baz = 42;
    //         BigAlert.emit(foo, bar, baz).delay(1);
    //     }
    //     constructor() {
    //         BigAlert.create_signal();
    //         BigHandler.create_handler("update(string,uint8[5],uint32)", 1000000, 120);
    //         address this_address = address(this);
    //         BigHandler.bind(this_address, "BigAlert(string,uint8[5],uint32)");
    //     }
    // }
    ////////////////////////////////////////////////////////////////////////////////////////
    // AFTER PARSING
    //
    // contract SelfAlerter {
    //     // Original code: signal BigAlert(string,uint8[5],uint32);
    //     bytes32 private BigAlert_key;
    //     function set_BigAlert_key() private {
    //         BigAlert_key = keccak256("BigAlert(string,uint8[5],uint32)");
    //     }
    //     ////////////////////
    //     // Original code: handler BigHandler;
    //     bytes32 private BigHandler_key;
    //     function set_BigHandler_key() private {
    //         BigHandler_key = keccak256("BigHandler(string,uint8[5],uint32)");
    //     }
    //     ////////////////////
    //     string fooo;
    //     uint8[] barr;
    //     uint32 bazz;
    //     function update(string calldata foo, uint8[5] calldata bar, uint32 baz) public {
    //         fooo = foo;
    //         barr = bar;
    //         bazz = baz;
    //         return;
    //     }
    //     function signal_emit() public view {
    //         string memory foo = "Hello World!";
    //         uint8[5] memory bar = ([1, 1, 2, 2, 4]);
    //         uint32 baz = 42;
    //         // Original code: BigAlert.emit(foo,bar,baz).delay(1);
    //         bytes memory abi_encoded_BigAlert_data = abi.encode(foo,bar,baz);
    //         // This length is measured in bytes and is always a multiple of 32.
    //         uint abi_encoded_BigAlert_length = abi_encoded_BigAlert_data.length;
    //         assembly {
    //             mstore(
    //                 0x00,
    //                 sigemit(
    //                     sload(BigAlert_key.slot), 
    //                     abi_encoded_BigAlert_data,
    //                     abi_encoded_BigAlert_length,
    //                     1
    //                 )
    //             )
    //         }
    //         ////////////////////
    //     }
    //     constructor() {
    //         // Original code: BigAlert.create_signal();
    //         set_BigAlert_key();
    //         assembly {
    //             mstore(0x00, createsignal(sload(BigAlert_key.slot)))
    //         }
    //         ////////////////////
    //         // Original code: BigHandler.create_handler("update(string,uint8[5],uint32)",1000000,120);
    //         set_BigHandler_key();
    //         bytes32 BigHandler_method_hash = keccak256("update(string,uint8[5],uint32)");
    //         uint BigHandler_gas_limit = 1000000;
    //         uint BigHandler_gas_ratio = 120;
    //         assembly {
    //             mstore(
    //                 0x00, 
    //                 createhandler(
    //                     sload(BigHandler_key.slot), 
    //                     BigHandler_method_hash, 
    //                     BigHandler_gas_limit, 
    //                     BigHandler_gas_ratio
    //                 )
    //             )
    //         }
    //         ////////////////////
    //         address this_address = address(this);
    //         // Original code: BigHandler.bind(this_address,"BigAlert(string,uint8[5],uint32)");
    //         bytes32 BigHandler_signal_prototype_hash = keccak256("BigAlert(string,uint8[5],uint32)");
    //         assembly {
    //             mstore(
    //                 0x00,
    //                 sigbind(
    //                     sload(BigHandler_key.slot),
    //                     this_address,
    //                     BigHandler_signal_prototype_hash
    //                 )
    //             )
    //         }
    //         ////////////////////
    //     }
    // }
    //////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////////////////////
    // Set up environment
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec(env.number);
    // Initialize sender. This account pays for all transactions.
    let sender = Random.generate().unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(10_000_000_000_000_000_000_000u128),
            CleanupMode::NoEmpty,
        )
        .unwrap();  

    //////////////////////////////////////////////////////////////////////////////////////////
    // Deploy contract
    let code = 
    "608060405234801561001057600080fd5b5061001f6100ae60201b60201c565b600054c06000526100346100d760201b60201c565b60007f5d163d171a40d2e1
    a13987bb0887fff55a9eedc7ee2b3f9e84676d512a6cb9f890506000620f42409050600060789050808284600154c1600052600030905060007fdb3a29a183b55
    3142f68db6907139a10a735c21635562497d990d66a6e38e6a190508082600154c26000525050505050610100565b7fdb3a29a183b553142f68db6907139a10a7
    35c21635562497d990d66a6e38e6a1600081905550565b7f2a8b37379988a0d21ef440d818ea7ac1275f4b85135a5eeaf895a754f6e13bf8600181905550565b6
    104778061010f6000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80635d163d171461003b578063f1293c211461
    00ce575b600080fd5b6100cc600480360360e081101561005157600080fd5b810190808035906020019064010000000081111561006e57600080fd5b820183602
    08201111561008057600080fd5b803590602001918460018302840111640100000000831117156100a257600080fd5b90919293919293908060a0019091929192
    90803563ffffffff1690602001909291905050506100d8565b005b6100d6610123565b005b8383600291906100e9929190610287565b508160039060056100fb9
    29190610307565b5080600460006101000a81548163ffffffff021916908363ffffffff16021790555050505050565b60606040518060400160405280600c8152
    6020017f48656c6c6f20576f726c6421000000000000000000000000000000000000000081525090506101656103b1565b6040518060a00160405280600160ff1
    68152602001600160ff168152602001600260ff168152602001600260ff168152602001600460ff1681525090506000602a905060608383836040516020018080
    60200184600560200280838360005b838110156101df5780820151818401526020810190506101c4565b505050509050018363ffffffff1681526020018281038
    25285818151815260200191508051906020019080838360005b8381101561022a57808201518184015260208101905061020f565b50505050905090810190601f
    1680156102575780820380516001836020036101000a031916815260200191505b509450505050506040516020818303038152906040529050600081519050600
    18183600054c46000525050505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106102c857
    803560ff19168380011785556102f6565b828001600101855582156102f6579182015b828111156102f55782358255916020019190600101906102da565b5b509
    05061030391906103d3565b5090565b82805482825590600052602060002090601f016020900481019282156103a05791602002820160005b8382111561037157
    833560ff1683826101000a81548160ff021916908360ff1602179055509260200192600101602081600001049283019260010302610330565b801561039e57828
    16101000a81549060ff0219169055600101602081600001049283019260010302610371565b505b5090506103ad91906103f0565b5090565b6040518060a00160
    405280600590602082028036833780820191505090505090565b5b808211156103ec5760008160009055506001016103d4565b5090565b5b80821115610414576
    00081816101000a81549060ff0219169055506001016103f1565b509056fea2646970667358221220516a91c6eea30c9691c39a67d5e66dd388449c1cc3f13156
    05a438b409aa311e64736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d6f64005c"
    .from_hex().unwrap();

    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::zero(),
        &code,
    ).0;

    // Emitter contract creation transaction.
    let contract_creation_tx = Transaction {
        action: Action::Create,
        value: U256::zero(),
        data: code.clone(),
        gas: U256::from(1_000_000_000u64),
        gas_price: U256::one(),
        storage_limit: U256::from(10_000u64),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::zero(),
        slot_tx: None,
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
        ex.transact(&contract_creation_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());
    assert!(state.is_contract(&address));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Emit with delay
    let emit_call_data = "f1293c21".from_hex().unwrap(); // KEC("signal_emit()") = 0xf1293c21...
    let emit_tx = Transaction {
        action: Action::Call(address.clone()),
        value: U256::from(0),
        data: emit_call_data.clone(),
        gas: U256::from(1_000_000u64),
        gas_price: U256::one(),
        storage_limit: U256::from(1_000u64),
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::from(1),
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

    //////////////////////////////////////////////////////////////////////////////////////////
    // Dequeue from global slottx queue
    assert!(state.is_account_slot_tx_queue_empty(&address).expect("No db errors here pls."));
    state
        .drain_global_slot_tx_queue(1)
        .expect("Drain should not fail");
    assert!(!state.is_account_slot_tx_queue_empty(&address).expect("No db errors here pls."));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Execute slot transaction
    let mut tx = state
        .get_account_slot_tx_queue(&address)
        .unwrap()
        .peek(0)
        .unwrap()
        .clone();
    tx.calculate_and_set_gas_price(&U256::from(1));
    tx.set_gas(U256::from(9_999_999_999_999_999u128));
    tx.set_storage_limit(U256::from(10000000));
    // Create a regular transaction and execute it.
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
        slot_tx: Some(tx),
    };
    let tx = Transaction::create_signed_tx_with_slot_tx(tx.clone());
    let res = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap();
    assert!(res.successfully_executed().is_some());
}

#[test]
fn test_signal_delete() {
    // TODO
}

#[test]
fn test_slot_delete() {
    // TODO
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////