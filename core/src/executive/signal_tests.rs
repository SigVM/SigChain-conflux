//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

use super::{executive::*, internal_contract::*, /* Executed */};
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
// use primitives::{SignalLocation,SlotLocation};

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::new_machine_with_builtin();
    machine
        .set_spec_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
    machine
}

#[test]
fn test_bind_and_detach() {

    //////////////////////////////////////////////////////////////////////////////////////////
    // BEFORE PARSING 

    // pragma solidity ^0.7.0;

    // // This contract is used to test basic functionality of binding and detaching to signals.
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

    // pragma solidity ^0.7.0;

    // contract Emitter {
    // // Original code: signal Alert();
    // bytes32 private Alert_key;
    // function set_Alert_key() private {
    //     Alert_key = keccak256("Alert()");
    // }
    // ////////////////////
    //     function emit_alert() public view {
    // // Original code: Alert.emit().delay(0);
    // bytes memory abi_encoded_Alert_data = abi.encode();
    // // This length is measured in bytes and is always a multiple of 32.
    // uint abi_encoded_Alert_length = abi_encoded_Alert_data.length;
    // assembly {
    //     mstore(
    //         0x00,
    //         sigemit(
    //             sload(Alert_key.slot), 
    //             abi_encoded_Alert_data,
    //             abi_encoded_Alert_length,
    //             0
    //         )
    //     )
    // }
    // ////////////////////
    //     }
    //     constructor() {
    // // Original code: Alert.create_signal();
    // set_Alert_key();
    // assembly {
    //     mstore(0x00, createsignal(sload(Alert_key.slot)))
    // }
    // ////////////////////
    //     }
    // }
    // contract Receiver {
    //     uint updated;
    // // Original code: handler Receive;
    // bytes32 private Receive_key;
    // function set_Receive_key() private {
    //     Receive_key = keccak256("Receive()");
    // }
    // ////////////////////
    //     function update_data() public {
    //         updated = 1;
    //         return;
    //     }
    //     function bind_to_alert(address source) public view {
    // // Original code: Receive.bind(source,"Alert()");
    // bytes32 Receive_signal_prototype_hash = keccak256("Alert()");
    // assembly {
    //     mstore(
    //         0x00,
    //         sigbind(
    //             sload(Receive_key.slot),
    //             source,
    //             Receive_signal_prototype_hash
    //         )
    //     )
    // }
    // ////////////////////
    //     }
    //     function detach_from_alert(address source) public view {
    // // Original code: Receive.detach(source,"Alert()");
    // bytes32 Receive_signal_prototype_hash = keccak256("Alert()");
    // assembly {
    //     mstore(
    //         0x00,
    //         sigdetach(
    //             sload(Receive_key.slot),
    //             source,
    //             Receive_signal_prototype_hash
    //         )
    //     )
    // }
    // ////////////////////
    //     }
    //     constructor() {
    // // Original code: Receive.create_handler("update_data()",100000,120);
    // set_Receive_key();
    // bytes32 Receive_method_hash = keccak256("update_data()");
    // uint Receive_gas_limit = 100000;
    // uint Receive_gas_ratio = 120;
    // assembly {
    //     mstore(
    //         0x00, 
    //         createhandler(
    //             sload(Receive_key.slot), 
    //             Receive_method_hash, 
    //             Receive_gas_limit, 
    //             Receive_gas_ratio
    //         )
    //     )
    // }
    // ////////////////////
    //         updated = 0;
    //     }
    // }

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
    "608060405234801561001057600080fd5b5061001f61002b60201b60201c565b600054c0600052610054565b7fffd2909f706e1243eefed
    477dac70a13bfca2e2f005110f7733a1de8f88b47c3600081905550565b60c2806100626000396000f3fe6080604052348015600f5760008
    0fd5b506004361060285760003560e01c806353180e3c14602d575b600080fd5b60336035565b005b6060604051602001604051602081830
    303815290604052905060008151905060008183600054c4600052505056fea264697066735822122028e66059103b699ad147813644e31d7
    857e234a2add97712b06436790bf496c464736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e303
    13263666338642e6d6f64005c"
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
    "608060405234801561001057600080fd5b5061001f61006b60201b60201c565b60007fc79f5321ec3d769feb76cb965aeebabfc421b9d
    ae7cd4c835ad2a577ad5ac1e690506000620186a09050600060789050808284600154c160005260008081905550505050610094565b7f9
    f1b3bad61172afd7ac57ee5c5873e1c8fad6c4b8e0fe408853ffbd909aaa830600181905550565b6101a5806100a36000396000f3fe608
    060405234801561001057600080fd5b50600436106100415760003560e01c80633e2f5fe514610046578063c79f53211461008a578063d
    00c2d1614610094575b600080fd5b6100886004803603602081101561005c57600080fd5b81019080803573fffffffffffffffffffffff
    fffffffffffffffff1690602001909291905050506100d8565b005b61009261010a565b005b6100d6600480360360208110156100aa576
    00080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610114565b005b60007fffd
    2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c390508082600154c26000525050565b6001600081905550565
    b60007fffd2909f706e1243eefed477dac70a13bfca2e2f005110f7733a1de8f88b47c390508082600154c3600052505056fea26469706
    67358221220492f7f054be9c65363becc8f68f03bfc1986bdb961ebeedbbc566e092c2cf9e464736f6c63782b302e372e312d646576656
    c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d6f64005c"
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

#[test]
fn test_simple_slot_tx_execution() {
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
            &U256::from(999_999_999_999_999_999_999u128),
            CleanupMode::NoEmpty,
        )
        .unwrap();  

    //////////////////////////////////////////////////////////////////////////////////////////
    // Deploy contract
    let code = 
    "608060405234801561001057600080fd5b5061001f6100af60201b60201c565b600054c06000526100346100d860201b60201c565b60007fa2e62045dc01b31218a31cb72c1fcd6276334c46fe7a034acac6b489293a201a905060006305f5e0ff9050600060789050808284600154c1600052600030905060007f5c8c677c56bdf6c90761a88f118eeb9aa8917bcda347cff849e85eb69c032beb90508082600154c26000525050505050610101565b7f5c8c677c56bdf6c90761a88f118eeb9aa8917bcda347cff849e85eb69c032beb600081905550565b7fba6c67039d62b457443ae81da1de49f611e6608efeea531dd8b57c78638ff713600181905550565b60c18061010f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c8063a2e62045146037578063f1293c2114603f575b600080fd5b603d6047565b005b60456055565b005b600160025401600281905550565b60008060008054c460005256fea26469706673582212207e0e924b20a87c4aaa57ddc4cf332e498d9f288a957b088f56599e27d0a45d0564736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d6f64005c"
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
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(10000),
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
        ex.transact(&contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&address));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Emit no delay
    let emit_call_data = "f1293c21".from_hex().unwrap(); // KEC("signal_emit()") = 0xf1293c21...
    let emit_tx = Transaction {
        action: Action::Call(address.clone()),
        value: U256::from(0),
        data: emit_call_data.clone(),
        gas: U256::from(2000000),
        gas_price: U256::one(),
        storage_limit: U256::from(10000),
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
    assert!(!state.is_account_slot_tx_queue_empty(&address).expect("No db errors here pls."));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Execute slot transaction
    let mut tx = state
        .get_account_slot_tx_queue(&address)
        .unwrap()
        .peek(0)
        .unwrap()
        .clone();
    tx.calculate_and_set_gas_price(&U256::from(10));
    tx.set_gas(U256::from(1021301));
    tx.set_storage_limit(U256::from(100000));
    println!("Encoded Data:");
    println!("{:?}\n", tx.get_encoded_data());
    println!("Slot Transaction:");
    println!("{:?}\n", tx);

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
    println!("Transaction Result:");
    println!("{:#?}\n", res);
    assert!(res.successfully_executed().is_some());
}

#[test]
fn test_signal_multi_arg_emit() {
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
            &U256::from(999_999_999_999_999_999_999u128),
            CleanupMode::NoEmpty,
        )
        .unwrap();  

    //////////////////////////////////////////////////////////////////////////////////////////
    // Deploy contract
    let code = 
    "608060405234801561001057600080fd5b5061001f6100ae60201b60201c565b600054c06000526100346100d760201b60201c565b60007fc49e5bbdbd443373232b9b1aca32a8edac327c3c88e00ad88ce95c0e002549d8905060006201869f9050600060789050808284600154c1600052600030905060007f49cdfef795faf4915389bdfe9be716986482454e74bf88d006a76a156256aaeb90508082600154c26000525050505050610100565b7f49cdfef795faf4915389bdfe9be716986482454e74bf88d006a76a156256aaeb600081905550565b7fbd4d0fd4ebd1e9fdbeffeb242b310fe74e3bc35cb00987a3820e3c5beb16b167600181905550565b6105268061010f6000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063e597e5dd1461003b578063f1293c2114610194575b600080fd5b6101926004803603606081101561005157600080fd5b810190808035906020019064010000000081111561006e57600080fd5b82018360208201111561008057600080fd5b803590602001918460018302840111640100000000831117156100a257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019064010000000081111561010557600080fd5b82018360208201111561011757600080fd5b8035906020019184602083028401116401000000008311171561013957600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019092919050505061019e565b005b61019c6101d8565b005b82600290805190602001906101b4929190610339565b5081600390805190602001906101cb9291906103b9565b5080600481905550505050565b60606040518060400160405280600c81526020017f48656c6c6f20576f726c64210000000000000000000000000000000000000000815250905061021a610460565b6040518060a00160405280600160ff168152602001600160ff168152602001600260ff168152602001600260ff168152602001600460ff1681525090506000602a90506060838383604051602001808060200184600560200280838360005b83811015610294578082015181840152602081019050610279565b50505050905001838152602001828103825285818151815260200191508051906020019080838360005b838110156102d95780820151818401526020810190506102be565b50505050905090810190601f1680156103065780820380516001836020036101000a031916815260200191505b50945050505050604051602081830303815290604052905060006020825101905060018183600054c46000525050505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061037a57805160ff19168380011785556103a8565b828001600101855582156103a8579182015b828111156103a757825182559160200191906001019061038c565b5b5090506103b59190610482565b5090565b82805482825590600052602060002090601f0160209004810192821561044f5791602002820160005b8382111561042057835183826101000a81548160ff021916908360ff16021790555092602001926001016020816000010492830192600103026103e2565b801561044d5782816101000a81549060ff0219169055600101602081600001049283019260010302610420565b505b50905061045c919061049f565b5090565b6040518060a00160405280600590602082028036833780820191505090505090565b5b8082111561049b576000816000905550600101610483565b5090565b5b808211156104c357600081816101000a81549060ff0219169055506001016104a0565b509056fea26469706673582212207cbb2433b4f7854252dbb860501d75456d38f4a38d5c1cc17119863cfd1a456b64736f6c63782b302e372e312d646576656c6f702e323032302e382e31342b636f6d6d69742e30313263666338642e6d6f64005c"
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
        gas: U256::from(1080000),
        gas_price: U256::one(),
        storage_limit: U256::from(10000),
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
        ex.transact(&contract_creation_tx).unwrap()
    };
    assert!(state.is_contract(&address));

    //////////////////////////////////////////////////////////////////////////////////////////
    // Emit with delay
    let emit_call_data = "f1293c21".from_hex().unwrap(); // KEC("signal_emit()") = 0xf1293c21...
    let emit_tx = Transaction {
        action: Action::Call(address.clone()),
        value: U256::from(0),
        data: emit_call_data.clone(),
        gas: U256::from(2000000),
        gas_price: U256::one(),
        storage_limit: U256::from(10000),
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
    tx.calculate_and_set_gas_price(&U256::from(10));
    tx.set_gas(U256::from(1021301));
    tx.set_storage_limit(U256::from(100000));
    println!("Encoded Data:");
    println!("{:?}\n", tx.get_encoded_data());
    println!("Slot Transaction:");
    println!("{:?}\n", tx);
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
    println!("Transaction Result:");
    println!("{:#?}\n", res);
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

#[test]
fn test_slottx_execution() {
    // TODO
}

#[test]
#[should_panic]
fn test_slottx_execution_error() {
    // TODO
    panic!("wellp");
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////