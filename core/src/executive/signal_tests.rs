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

#[test]
fn test_broadcast() {
    // pragma solidity ^0.6.9;
    // contract Emitter {
    //     signal Alert(bytes32 value);
    //     function send_alert(bytes32 value) public {
    //         emitsig Alert(value).delay(0);
    //     }
    // }
    //
    // contract ReceiverA {
    //     bytes32 private data;
    //     slot HandleAlert(bytes32 value) {
    //         data = value;
    //     }
    //     function get_data() public view returns (bytes32 ret) {
    //         ret = data;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         HandleAlert.bind(addr.Alert);
    //     }
    // }
    //
    // contract ReceiverB {
    //     bytes32 private data;
    //     slot HandleAlert(bytes32 value) {
    //         data = value;
    //     }
    //     function get_data() public view returns (bytes32 ret) {
    //         ret = data;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    //         HandleAlert.bind(addr.Alert);
    //     }
    // }

    // This test involves three seperate contract accounts.
    // We start by creating each contract. We then call "send_alert" from the emitter account.
    // This signal should be picked up by both the receiver accounts. A slot transaction for each receiver
    // should then be generated. We then peak at these slot transactions and execute both of them. 
    // We then create two more transactions, one for each receiver, to check if the data field is updated properly
    // from the signal emission.
    
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f66756e6374696f6
        e20416c65727428290000000000000000000000000000000081525060100190506040518091039020600381905550600354602
        0c06002556000600155565b6102998061007f6000396000f3fe608060405234801561001057600080fd5b506004361061004c5
        760003560e01c806365410bf114610051578063b5d359171461006f578063dd5e12011461009d578063e0b3195014610120575
        b600080fd5b61005961013e565b6040518082815260200191505060405180910390f35b61009b6004803603602081101561008
        557600080fd5b8101908080359060200190929190505050610148565b005b6100a5610184565b6040518080602001828103825
        283818151815260200191508051906020019080838360005b838110156100e55780820151818401526020810190506100ca565
        b50505050905090810190601f1680156101125780820380516001836020036101000a031916815260200191505b50925050506
        0405180910390f35b610128610226565b6040518082815260200191505060405180910390f35b6000600354905090565b61015
        18161022f565b600061015b610226565b90506060610167610184565b9050600061017361013e565b90508282600083c460405
        250505050565b606060018054600181600116156101000203166002900480601f0160208091040260200160405190810160405
        2809291908181526020018280546001816001161561010002031660029004801561021c5780601f106101f1576101008083540
        4028352916020019161021c565b820191906000526020600020905b8154815290600101906020018083116101ff57829003601
        f168201915b5050505050905090565b60006020905090565b806000819055505056fea264697066735822122092b0828271b2a
        069ddfa4908348241c2dfc87f8e8d6ad0213df288274e753d2864736f6c63782c302e362e31312d646576656c6f702e3230323
        02e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
        .from_hex().unwrap();
    // Hash of function identifier. First 8 bytes form the methodid. keccak256("function send_alert(bytes32)").
    let _emitter_send_alert_hash = "b5d35917";
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

    // Set up and deploy the first receiver contract.
    let receiver_a_code = 
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f48616e646c
        65416c6572745f66756e63286279746573333229000000000000008152506019019050604051809103902060028190555
        0600254617530600a6020c1600155565b61021f8061007f6000396000f3fe608060405234801561001057600080fd5b50
        6004361061004c5760003560e01c80631671379c146100515780633e2f5fe51461007f57806350bf8b0d146100c357806
        39981f1bc146100e1575b600080fd5b61007d6004803603602081101561006757600080fd5b8101908080359060200190
        9291905050506100ff565b005b6100c16004803603602081101561009557600080fd5b81019080803573fffffffffffff
        fffffffffffffffffffffffffff169060200190929190505050610109565b005b6100cb6101ac565b6040518082815260
        200191505060405180910390f35b6100e96101b5565b6040518082815260200191505060405180910390f35b806000819
        0555050565b600081905060008273ffffffffffffffffffffffffffffffffffffffff166365410bf16040518163ffffff
        ff1660e01b815260040160206040518083038186803b15801561015657600080fd5b505afa15801561016a573d6000803
        e3d6000fd5b505050506040513d602081101561018057600080fd5b810190808051906020019092919050505090506000
        61019d6101b5565b9050808284c260405250505050565b60008054905090565b600060025490509056fea264697066735
        8221220e7f3ac9ece40f6cda6802692d2b8b75b8fe6254e3efd980aeb3599c3df3f700164736f6c63782c302e362e3131
        2d646576656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
        .from_hex().unwrap();

    // Create receiver contract address.
    let receiver_a_address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender.address(),
        &U256::from(1),
        &receiver_a_code,
    ).0;

    // Method ID's of relevant functions.
    let _get_data_hash = "50bf8b0d"; // KEC("get_data()")
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

    // Set up and deploy the second receiver contract.
    // The solidity code for receiver A and B are exactly identical so the compiled code should be as well.
    let receiver_b_code = 
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f48616e646c
        65416c6572745f66756e63286279746573333229000000000000008152506019019050604051809103902060028190555
        0600254617530600a6020c1600155565b61021f8061007f6000396000f3fe608060405234801561001057600080fd5b50
        6004361061004c5760003560e01c80631671379c146100515780633e2f5fe51461007f57806350bf8b0d146100c357806
        39981f1bc146100e1575b600080fd5b61007d6004803603602081101561006757600080fd5b8101908080359060200190
        9291905050506100ff565b005b6100c16004803603602081101561009557600080fd5b81019080803573fffffffffffff
        fffffffffffffffffffffffffff169060200190929190505050610109565b005b6100cb6101ac565b6040518082815260
        200191505060405180910390f35b6100e96101b5565b6040518082815260200191505060405180910390f35b806000819
        0555050565b600081905060008273ffffffffffffffffffffffffffffffffffffffff166365410bf16040518163ffffff
        ff1660e01b815260040160206040518083038186803b15801561015657600080fd5b505afa15801561016a573d6000803
        e3d6000fd5b505050506040513d602081101561018057600080fd5b810190808051906020019092919050505090506000
        61019d6101b5565b9050808284c260405250505050565b60008054905090565b600060025490509056fea264697066735
        8221220447354085eee9e6a9fd78a08538a549a00fa6c23dea328af55fed034c8242ef064736f6c63782c302e362e3131
        2d646576656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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

    // Contract are now all deployed. Now we call the bind function for each of the receivers.
    state
        .add_balance(
            &sender.address(),
            &U256::from(9_000_000_000_000_210_010u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let mut receiver_a_bind_call_data = "3e2f5fe5".from_hex().unwrap();
    receiver_a_bind_call_data.extend_from_slice(&emitter_address[..]);
    receiver_a_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
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

    let mut receiver_b_bind_call_data = "3e2f5fe5".from_hex().unwrap();
    receiver_b_bind_call_data.extend_from_slice(&emitter_address[..]);
    receiver_b_bind_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
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

    // Next step is to emit the signal through the send_alert function. 
    // The contract data field will be set to call the send_alert function. 
    // It will be set to the method id appended by an argument of our choice.
    let send_alert_call_data = "b5d35917deadbeef00000000000000000000000000000000000000000000000000000000"
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
    state.drain_global_slot_tx_queue(0).expect("Db error not expected!");
    assert!(!state.is_account_slot_tx_queue_empty(&receiver_a_address).expect("Db error not expected!"));
    assert!(!state.is_account_slot_tx_queue_empty(&receiver_b_address).expect("Db error not expected!"));
}

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
