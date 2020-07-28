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
    //     bytes32 private Alert_data;
    //     bytes32 private Alert_dataslot;
    //     uint private Alert_status;
    //     bytes32 private Alert_key;
    //    
    //     function set_Alert_data(bytes32 dataSet) private {
    //          Alert_data = dataSet;
    //     }
    //     function get_Alert_argc() public pure returns (uint argc) {
    //          return 32;
    //     }
    //     function get_Alert_key() public view returns (bytes32 key) {
    //          return Alert_key;
    //     }
    //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
    //          return Alert_dataslot;
    //     }
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(32, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, Alert_data_slot)
    //         }
    //     }
    //     function send_alert(bytes32 data) public {
    //         set_Alert_data(data);
    //         uint this_emitsig_Alert_argc = get_Alert_argc();
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 0, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
    //         }
    //     }
    //     constructor() public {
    //         Alert();
    //     }
    // }
    // contract EmitLate {
    //     bytes32 private Alert_data;
    //     bytes32 private Alert_dataslot;
    //     uint private Alert_status;
    //     bytes32 private Alert_key;
    //     function set_Alert_data(bytes32 dataSet) private {
    //          Alert_data = dataSet;
    //     }
    //     function get_Alert_argc() public pure returns (uint argc) {
    //          return 32;
    //     }
    //     function get_Alert_key() public view returns (bytes32 key) {
    //          return Alert_key;
    //     }
    //     function get_Alert_dataslot() public view returns (bytes32 dataslot) {
    //          return Alert_dataslot;
    //     }
    //     function Alert() private {
    //         Alert_key = keccak256("Alert()");
    //         assembly {
    //             sstore(Alert_status_slot, createsig(32, sload(Alert_key_slot)))
    //             sstore(Alert_dataslot_slot, Alert_data_slot)
    //         }
    //     }
    //     function send_alert(bytes32 data) public {
    //         set_Alert_data(data);
    //         uint this_emitsig_Alert_argc = get_Alert_argc();
    //         bytes32 this_emitsig_Alert_dataslot = get_Alert_dataslot();
    //         bytes32 this_emitsig_Alert_key = get_Alert_key();
    //         assembly {
    //             mstore(0x40, emitsig(this_emitsig_Alert_key, 10, this_emitsig_Alert_dataslot, this_emitsig_Alert_argc))
    //         }
    //     }
    //     constructor() public {
    //         Alert();
    //     }
    // }
    // contract Receiver {
    //     bytes32 data;
    //     uint32 alert_count;
    //     uint private Receive_status;
    //     bytes32 private Receive_key;
    //     function get_Receive_key() public view returns (bytes32 key) {
    //          return Receive_key;
    //     }
    //     function Receive() private {
    //         Receive_key = keccak256("Receive_func(bytes32)");
    //         assembly {
    //             sstore(Receive_status_slot, createslot(32, 10, 30000, sload(Receive_key_slot)))
    //         }
    //     }
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
    //         address emitter_bindslot_address = address(emitter);
    //         bytes32 emitter_bindslot_Alert_key = keccak256("Alert()");
    //         bytes32 this_emitter_bindslot_Receive_key = get_Receive_key();
    //         assembly {
    //             mstore(0x40, bindslot(emitter_bindslot_address, emitter_bindslot_Alert_key, this_emitter_bindslot_Receive_key))
    //         }
    //     }
    //     constructor() public {
    //         Receive();
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f416c65727428290000000000000000
        0000000000000000000000000000000000815250600701905060405180910390206003819055506003546020c06002556000600155565b61019c8
        061007f6000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806365410bf114610051578063b5d359
        171461006f578063dd5e12011461009d578063e0b31950146100bb575b600080fd5b6100596100d9565b604051808281526020019150506040518
        0910390f35b61009b6004803603602081101561008557600080fd5b81019080803590602001909291905050506100e3565b005b6100a561011f56
        5b6040518082815260200191505060405180910390f35b6100c3610129565b6040518082815260200191505060405180910390f35b60006003549
        05090565b6100ec81610132565b60006100f6610129565b9050600061010261011f565b9050600061010e6100d9565b90508282600a83c4604052
        50505050565b6000600154905090565b60006020905090565b806000819055505056fea26469706673582212208f925f2f9a51d1d25306139bd2f
        fb1067157d0626424d0197d21443de95509b764736f6c63782c302e362e31312d646576656c6f702e323032302e372e32312b636f6d6d69742e63
        316635663761632e6d6f64005d"
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f416c657274282900000000000000
        000000000000000000000000000000000000815250600701905060405180910390206003819055506003546020c06002556000600155565b610
        19c8061007f6000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806365410bf114610051578063
        b5d359171461006f578063dd5e12011461009d578063e0b31950146100bb575b600080fd5b6100596100d9565b6040518082815260200191505
        060405180910390f35b61009b6004803603602081101561008557600080fd5b81019080803590602001909291905050506100e3565b005b6100
        a561011f565b6040518082815260200191505060405180910390f35b6100c3610129565b6040518082815260200191505060405180910390f35
        b6000600354905090565b6100ec81610132565b60006100f6610129565b9050600061010261011f565b9050600061010e6100d9565b90508282
        600083c460405250505050565b6000600154905090565b60006020905090565b806000819055505056fea264697066735822122001a12630dca
        bf434f3df6934eb07c5b5bcf92c7537589a6efaf8ded2a61fdf7d64736f6c63782c302e362e31312d646576656c6f702e323032302e372e3231
        2b636f6d6d69742e63316635663761632e6d6f64005d"
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
        "608060405234801561001057600080fd5b5061001f61005060201b60201c565b6000801b6000819055506000600160006101000a81548163
        ffffffff021916908363ffffffff16021790555061009c565b60405180807f526563656976655f66756e63286279746573333229000000000
        000000000000081525060150190506040518091039020600381905550600354617530600a6020c1600255565b610258806100ab6000396000
        f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80630eea95011461005c5780634b918fee1461008a578
        06350bf8b0d146100a85780635e69ae7e146100c6578063fa7d84831461010a575b600080fd5b610088600480360360208110156100725760
        0080fd5b8101908080359060200190929190505050610134565b005b610092610173565b6040518082815260200191505060405180910390f
        35b6100b061017d565b6040518082815260200191505060405180910390f35b610108600480360360208110156100dc57600080fd5b810190
        80803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610186565b005b6101126101de565b60405180826
        3ffffffff1663ffffffff16815260200191505060405180910390f35b8060008190555060018060009054906101000a900463ffffffff1601
        600160006101000a81548163ffffffff021916908363ffffffff16021790555050565b6000600354905090565b60008054905090565b60008
        19050600060405180807f416c6572742829000000000000000000000000000000000000000000000000008152506007019050604051809103
        9020905060006101cf610173565b9050808284c260405250505050565b6000600160009054906101000a900463ffffffff1690509056fea26
        469706673582212203cfee692860ba7b0da766398b9f02169bc3b54127d9e342b5ca7233a8b83292f64736f6c63782c302e362e31312d6465
        76656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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

#[test]
fn test_bind_detach() {
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
    // 	bytes32 private Alert_dataslot;
    // 	uint private Alert_status;
    //     bytes32 private Alert_key;

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
    // contract Receiver {
    //     uint data;
    //     address source;
    
    //     uint private HandleAlert_status;
    //     bytes32 private HandleAlert_key;

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
    //     function set_source(address addr) public {
    //         source = addr;
    //     }
    //     function bind_to_alert() public view {
    // 		address source_bindslot_address = address(source);
    // 		bytes32 source_bindslot_Alert_key = keccak256("Alert()");
    //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
    // 		assembly {
    // 			mstore(0x40, bindslot(source_bindslot_address, source_bindslot_Alert_key, this_source_bindslot_HandleAlert_key))
    // 	    }
    //     }
    //     function detach_from_alert() public view {
    // 		bytes32 source_detach_Alert_key = keccak256("Alert()");
    // 		address source_detach_address = address(source);
    //         bytes32 this_source_bindslot_HandleAlert_key = get_HandleAlert_key();
    // 		assembly{
    // 			mstore(0x40, detachslot(source_detach_address, source_detach_Alert_key, this_source_bindslot_HandleAlert_key))
    // 		}
    //     }
    //     constructor() public {
    //         HandleAlert();
    //     }
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
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b61006f565b60405180807f416c657274282900000000000
        000000000000000000000000000000000000000815250600701905060405180910390206002819055506002546000c060015560008055565
        b60f08061007d6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806365410bf11460375780637
        ced953e146053575b600080fd5b603d605b565b6040518082815260200191505060405180910390f35b60596065565b005b6000600254905
        090565b6000606d6087565b905060006077605b565b9050600082600083c46040525050565b6000805490509056fea264697066735822122
        085459ea7f4a172353367eec50d9bc9659f935303529da8b1b704f0e385a3311964736f6c63782c302e362e31312d646576656c6f702e323
        032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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

    let receiver_code = 
        "608060405234801561001057600080fd5b5061001f61002460201b60201c565b610070565b60405180807f48616e646c65416c6572745f6
        6756e632829000000000000000000000000000081525060120190506040518091039020600381905550600354617530600a6000c16002555
        65b6102858061007f6000396000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80630e3b859014610
        05c57806314583309146100665780632de681eb1461007057806334bcebd0146100b45780639981f1bc146100be575b600080fd5b6100646
        100dc565b005b61006e610155565b005b6100b26004803603602081101561008657600080fd5b81019080803573fffffffffffffffffffff
        fffffffffffffffffff1690602001909291905050506101ce565b005b6100bc610212565b005b6100c661021b565b6040518082815260200
        191505060405180910390f35b600060405180807f416c6572742829000000000000000000000000000000000000000000000000008152506
        007019050604051809103902090506000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905060006
        1014761021b565b9050808383c3604052505050565b6000600160009054906101000a900473fffffffffffffffffffffffffffffffffffff
        fff169050600060405180807f416c65727428290000000000000000000000000000000000000000000000000081525060070190506040518
        091039020905060006101c061021b565b9050808284c2604052505050565b80600160006101000a81548173fffffffffffffffffffffffff
        fffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008081905550565b600060035
        490509056fea2646970667358221220bb2082255fce9981e01c4df3acce2f17eef92d963d27a7cc464e97bbb4904d9864736f6c63782c302
        e362e31312d646576656c6f702e323032302e372e32312b636f6d6d69742e63316635663761632e6d6f64005d"
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

    // Give emitter address to receiver.
    // keccak("set_source(address)") = 2de681ebdca726d72c94bf1523fb481dc947bdf132d3b75dffb3671b5bcfb042
    let mut set_source_call_data = "2de681eb".from_hex().unwrap();
    set_source_call_data.extend_from_slice(
        &(vec![0u8; 32 - 20])[..]
    );
    set_source_call_data.extend_from_slice(&emitter_address[..]);
    let set_source_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: set_source_call_data,
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
        ex.transact(&set_source_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Bind slot to signal.
    // keccak256("bind_to_alert()") = 14583309ad14d9f5f5ada6b94129244a6e5c5eb0d21ac966c65d03b8305854a1
    let bind_call_data = "14583309".from_hex().unwrap();
    let bind_tx = Transaction {
        action: Action::Call(receiver_address.clone()),
        value: U256::from(0),
        data: bind_call_data,
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
        ex.transact(&bind_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Emit signal.
    // keccak256("send_alert()") = 7ced953e3a98fed2864b59f525e7909dcb6165ad544dfec26c846abd73b6b8e1
    let emit_call_data = "7ced953e".from_hex().unwrap();
    let emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emit_call_data,
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
        ex.transact(&emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Verify that slottx has been generated.
    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert!(slot_tx_queue.len() == 1);

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
        ex.transact(&detach_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Emit a signal again.
    let emit_call_data = "7ced953e".from_hex().unwrap();
    let emit_tx = Transaction {
        action: Action::Call(emitter_address.clone()),
        value: U256::from(0),
        data: emit_call_data,
        gas: U256::from(1080000),
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
        ex.transact(&emit_tx).unwrap()
    };
    assert!(res.successfully_executed().is_some());

    // Verify that no new slot tx has been created.
    let slot_tx_queue = state
        .get_account_slot_tx_queue(&receiver_address)
        .expect("No db errors pls");
    assert!(slot_tx_queue.len() == 1);
}
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////
