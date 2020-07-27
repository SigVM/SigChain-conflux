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
    //
    // contract Emitter {
    // 	bytes32 private Alert_dataslot;
    // 	uint private Alert_status;
    //     bytes32 private Alert_key;
    //
    // 	function get_Alert_key() public view returns (bytes32 key) {
    //        return Alert_key;
    //     }
    //     function get_Alert_dataslot() private view returns (bytes32 dataslot) {
    //        return Alert_dataslot;
    //     }
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    // 		assembly {
    // 			sstore(Alert_status_slot, createsig(0, sload(Alert_key_slot)))
    // 			sstore(Alert_dataslot_slot, 0x0)
    // 		}
    //     }
    //     function send_alert() public view {
    // 		bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    // 		bytes32 this_emitsig_Alert_key = get_Alert_key();
    // 		assembly {
    // 			mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, 0))
    // 	    }
    //     }
    //     constructor() public {
    //         Alert();
    //     }
    // }
    //
    // contract ReceiverA {
    //     bytes32 private data;
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;
    //
    // 	function get_HandleAlert_key() public view returns (bytes32 key) {
    //        return HandleAlert_key;
    //     }
    //     function HandleAlert() private {
    //         HandleAlert_key = keccak256("HandleAlert_func()");
    //         assembly {
    //             sstore(HandleAlert_status_slot, createslot(0, 10, 30000, sload(HandleAlert_key_slot)))
    //         }
    //     }
    //     function HandleAlert_func() public {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    // 		address addr_bindslot_address = address(addr);
    // 		bytes32 addr_bindslot_Alert_key = keccak256("Alert()");
    //         bytes32 this_addr_bindslot_HandleAlert_key = get_HandleAlert_key();
    // 		assembly {
    // 			mstore(0x40, bindslot(addr_bindslot_address, addr_bindslot_Alert_key, this_addr_bindslot_HandleAlert_key))
    //         }
    //     }
    //     constructor() public {
    //         HandleAlert();
    //     }   
    // }
    //
    // contract ReceiverB {
    //     bytes32 private data;
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;
    //
    // 	   function get_HandleAlert_key() public view returns (bytes32 key) {
    //        return HandleAlert_key;
    //     }
    //     function HandleAlert() private {
    //         HandleAlert_key = keccak256("HandleAlert_func()");
    //         assembly {
    //             sstore(HandleAlert_status_slot, createslot(0, 10, 30000, sload(HandleAlert_key_slot)))
    //         }
    //     }
    //     function HandleAlert_func() public {
    //         data = 0;
    //     }
    //     function bind_to_alert(Emitter addr) public view {
    // 		    address addr_bindslot_address = address(addr);
    // 		    bytes32 addr_bindslot_Alert_key = keccak256("Alert()");
    //          bytes32 this_addr_bindslot_HandleAlert_key = get_HandleAlert_key();
    // 		    assembly {
    // 			    mstore(0x40, bindslot(addr_bindslot_address, addr_bindslot_Alert_key, this_addr_bindslot_HandleAlert_key))
    // 	        }
    //     }
    //     constructor() public {
    //         HandleAlert();
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b61006f565b60405180807f416c6572742829000000000000000
        00000000000000000000000000000000000815250600701905060405180910390206002819055506002546000c060015560008055565b60f0806
        1007d6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806365410bf11460375780637ced953e14605
        3575b600080fd5b603d605b565b6040518082815260200191505060405180910390f35b60596065565b005b6000600254905090565b6000606d6
        087565b905060006077605b565b9050600082600083c46040525050565b6000805490509056fea26469706673582212206fd086039e3cdf80de2
        714e2f45950017587c2f6c3a544ff7ae9618cfcc97fa364736f6c63782c302e362e31312d646576656c6f702e323032302e372e32312b636f6d6
        d69742e63316635663761632e6d6f64005d"
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f48616e646c65416c6572745f66756
        e632829000000000000000000000000000081525060120190506040518091039020600281905550600254617530600a6000c1600155565b61018
        08061007f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806334bcebd0146100465780633e2
        f5fe5146100505780639981f1bc14610094575b600080fd5b61004e6100b2565b005b6100926004803603602081101561006657600080fd5b810
        19080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100be565b005b61009c610116565b60405180828
        15260200191505060405180910390f35b6000801b600081905550565b6000819050600060405180807f416c65727428290000000000000000000
        00000000000000000000000000000008152506007019050604051809103902090506000610107610116565b9050808284c260405250505050565
        b600060025490509056fea26469706673582212205af6c498b812f6223cd2cfa51358cbedfb28f630bfba5c83797c06fcc941140d64736f6c637
        82c302e362e31312d646576656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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
        .slot_at(&receiver_a_address, &slot_key)
        .expect("Should not have db failure.");
    assert!(slot.is_some());

    // Set up and deploy the second receiver contract.
    // The solidity code for receiver A and B are exactly identical so the compiled code should be as well.
    let receiver_b_code = 
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f48616e646c65416c6572745f66756
        e632829000000000000000000000000000081525060120190506040518091039020600281905550600254617530600a6000c1600155565b61018
        08061007f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806334bcebd0146100465780633e2
        f5fe5146100505780639981f1bc14610094575b600080fd5b61004e6100b2565b005b6100926004803603602081101561006657600080fd5b810
        19080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100be565b005b61009c610116565b60405180828
        15260200191505060405180910390f35b6000801b600081905550565b6000819050600060405180807f416c65727428290000000000000000000
        00000000000000000000000000000008152506007019050604051809103902090506000610107610116565b9050808284c260405250505050565
        b600060025490509056fea2646970667358221220ff588b2a00eb14e8243ce5e49dace1602962f520fa34dd88f706a6b9bcc028bb64736f6c637
        82c302e362e31312d646576656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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
        .slot_at(&receiver_b_address, &slot_key)
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

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
