// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    parameters::staking::*,
    storage::{
        Error as StorageError, ErrorKind as StorageErrorKind, StateProof,
        StateRootWithAuxInfo, StorageState, StorageStateTrait,
    },
    bytes::Bytes ,
};
use cfx_types::{Address, H256, U256};
use primitives::{
    Account, CodeInfo, DepositList, EpochId, StorageKey, StorageLayout,
    StorageRoot, VoteStakeList, MERKLE_NULL_NODE,
};

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use primitives::{
    SlotTxQueue, SlotTx, SignalLocation, SlotLocation, SignalInfo,
    SlotInfo,
};
use crate::signal::GLOBAL_SLOT_TX_QUEUE_ADDRESS;
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

mod error;

pub use self::error::{Error, ErrorKind, Result};
use crate::consensus::debug::{ComputeEpochDebugRecord, StateOp};

pub struct StateDb {
    storage: StorageState,
}

impl StateDb {
    const ACCUMULATE_INTEREST_RATE_KEY: &'static [u8] =
        b"accumulate_interest_rate";
    const INTEREST_RATE_KEY: &'static [u8] = b"interest_rate";
    const TOTAL_BANK_TOKENS_KEY: &'static [u8] = b"total_staking_tokens";
    const TOTAL_STORAGE_TOKENS_KEY: &'static [u8] = b"total_storage_tokens";
    const TOTAL_TOKENS_KEY: &'static [u8] = b"total_issued_tokens";

    pub fn new(storage: StorageState) -> Self { StateDb { storage } }

    #[allow(unused)]
    pub fn get_storage_mut(&mut self) -> &mut StorageState { &mut self.storage }

    pub fn get<T>(&self, key: StorageKey) -> Result<Option<T>>
    where T: ::rlp::Decodable {
        let raw = match self.storage.get(key) {
            Ok(maybe_value) => match maybe_value {
                None => return Ok(None),
                Some(raw) => raw,
            },
            Err(e) => {
                return Err(e.into());
            }
        };
        Ok(Some(::rlp::decode::<T>(raw.as_ref())?))
    }

    pub fn get_code(
        &self, address: &Address, code_hash: &H256,
    ) -> Result<Option<CodeInfo>> {
        self.get::<CodeInfo>(StorageKey::new_code_key(address, code_hash))
    }

    pub fn get_deposit_list(
        &self, address: &Address,
    ) -> Result<Option<DepositList>> {
        self.get::<DepositList>(StorageKey::new_deposit_list_key(address))
    }

    pub fn get_vote_list(
        &self, address: &Address,
    ) -> Result<Option<VoteStakeList>> {
        self.get::<VoteStakeList>(StorageKey::new_vote_list_key(address))
    }

    pub fn get_storage_layout(
        &self, address: &Address,
    ) -> Result<Option<StorageLayout>> {
        match self.get_raw(StorageKey::new_storage_root_key(address))? {
            None => Ok(None),
            Some(raw) => Ok(Some(StorageLayout::from_bytes(raw.as_ref())?)),
        }
    }

    pub fn set_storage_layout(
        &mut self, address: &Address, layout: &StorageLayout,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let key = StorageKey::new_storage_root_key(address);
        self.set_raw(key, layout.to_bytes().into_boxed_slice(), debug_record)
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        self.get::<Account>(StorageKey::new_account_key(address))
    }

    pub fn get_storage_root(
        &self, address: &Address,
    ) -> Result<Option<StorageRoot>> {
        let key = StorageKey::new_storage_root_key(address);

        match self.storage.get_node_merkle_all_versions(key)? {
            (None, None, None) => Ok(None),
            (maybe_delta, maybe_intermediate, maybe_snapshot) => {
                Ok(Some(StorageRoot {
                    delta: maybe_delta.unwrap_or(MERKLE_NULL_NODE),
                    intermediate: maybe_intermediate
                        .unwrap_or(MERKLE_NULL_NODE),
                    snapshot: maybe_snapshot.unwrap_or(MERKLE_NULL_NODE),
                }))
            }
        }
    }

    pub fn get_raw(&self, key: StorageKey) -> Result<Option<Box<[u8]>>> {
        let r = Ok(self.storage.get(key)?);
        trace!("get_raw key={:?}, value={:?}", key, r);
        r
    }

    pub fn get_raw_with_proof(
        &self, key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        let r = Ok(self.storage.get_with_proof(key)?);
        trace!("get_raw_with_proof key={:?}, value={:?}", key, r);
        r
    }

    pub fn set<T>(
        &mut self, key: StorageKey, value: &T,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    where
        T: ::rlp::Encodable,
    {
        self.set_raw(key, ::rlp::encode(value).into_boxed_slice(), debug_record)
    }

    pub fn set_raw(
        &mut self, key: StorageKey, value: Box<[u8]>,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        if let Some(record) = debug_record {
            record.state_ops.push(StateOp::StorageLevelOp {
                op_name: "set".into(),
                key: key.to_key_bytes(),
                maybe_value: Some(value.clone().into()),
            })
        }
        match self.storage.set(key, value) {
            Ok(_) => Ok(()),
            Err(StorageError(StorageErrorKind::MPTKeyNotFound, _)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(
        &mut self, key: StorageKey,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        if let Some(record) = debug_record {
            record.state_ops.push(StateOp::StorageLevelOp {
                op_name: "delete".into(),
                key: key.to_key_bytes(),
                maybe_value: None,
            })
        }
        match self.storage.delete(key) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_all(
        &mut self, key_prefix: StorageKey,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>>
    {
        if let Some(record) = debug_record {
            record.state_ops.push(StateOp::StorageLevelOp {
                op_name: "delete_all".into(),
                key: key_prefix.to_key_bytes(),
                maybe_value: None,
            })
        }
        Ok(self.storage.delete_all(key_prefix)?)
    }

    /// This method is only used for genesis block because state root is
    /// required to compute genesis epoch_id. For other blocks there are
    /// deferred execution so the state root computation is merged inside
    /// commit method.
    pub fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        Ok(self.storage.compute_state_root()?)
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
    ) -> Result<StateRootWithAuxInfo> {
        let result = self.compute_state_root();
        self.storage.commit(epoch_id)?;

        result
    }

    pub fn get_annual_interest_rate(&self) -> Result<U256> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::INTEREST_RATE_KEY,
        );
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        Ok(interest_rate_opt.unwrap_or(
            *INITIAL_INTEREST_RATE_PER_BLOCK * U256::from(BLOCKS_PER_YEAR),
        ))
    }

    pub fn get_accumulate_interest_rate(&self) -> Result<U256> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::ACCUMULATE_INTEREST_RATE_KEY,
        );
        let acc_interest_rate_opt = self.get::<U256>(acc_interest_rate_key)?;
        Ok(acc_interest_rate_opt.unwrap_or(*ACCUMULATED_INTEREST_RATE_SCALE))
    }

    pub fn get_total_issued_tokens(&self) -> Result<U256> {
        let total_issued_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_TOKENS_KEY,
        );
        let total_issued_tokens_opt =
            self.get::<U256>(total_issued_tokens_key)?;
        Ok(total_issued_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn get_total_staking_tokens(&self) -> Result<U256> {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_BANK_TOKENS_KEY,
        );
        let total_staking_tokens_opt =
            self.get::<U256>(total_staking_tokens_key)?;
        Ok(total_staking_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn get_total_storage_tokens(&self) -> Result<U256> {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_STORAGE_TOKENS_KEY,
        );
        let total_storage_tokens_opt =
            self.get::<U256>(total_storage_tokens_key)?;
        Ok(total_storage_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn set_annual_interest_rate(
        &mut self, interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::INTEREST_RATE_KEY,
        );
        self.set::<U256>(interest_rate_key, interest_rate, debug_record)
    }

    pub fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::ACCUMULATE_INTEREST_RATE_KEY,
        );
        self.set::<U256>(
            acc_interest_rate_key,
            accumulate_interest_rate,
            debug_record,
        )
    }

    pub fn set_total_issued_tokens(
        &mut self, total_issued_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_issued_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_TOKENS_KEY,
        );
        self.set::<U256>(
            total_issued_tokens_key,
            total_issued_tokens,
            debug_record,
        )
    }

    pub fn set_total_staking_tokens(
        &mut self, total_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_BANK_TOKENS_KEY,
        );
        self.set::<U256>(
            total_staking_tokens_key,
            total_staking_tokens,
            debug_record,
        )
    }

    pub fn set_total_storage_tokens(
        &mut self, total_storage_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_STORAGE_TOKENS_KEY,
        );
        self.set::<U256>(
            total_storage_tokens_key,
            total_storage_tokens,
            debug_record,
        )
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */

    //////////////////////////////////////////////////////
    /* Bind and detach from signals */
    // Bind to a signal.
    pub fn bind_slot_to_signal(
        &mut self, sig_loc: &SignalLocation, slot_loc: &SlotLocation,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Result<()> {
        // Get the signal info from the db and unpack.
        let signal_info = self.get::<SignalInfo>(
            StorageKey::new_signal_key(&sig_loc.address, &sig_loc.signal_key)
        );
        let mut signal_info = match signal_info {
            Ok(s) => match s {
                Some(s) => s,
                None => return Ok(()),
            },
            Err(e) => return Err(e),
        };

        // Get the slot info from the db and unpack.
        let slot_info = self.get::<SlotInfo>(
            StorageKey::new_slot_key(&slot_loc.address, &slot_loc.slot_key)
        );
        let slot_info = match slot_info {
            Ok(s) => match s {
                Some(s) => s,
                None => return Ok(()),
            },
            Err(e) => return Err(e),
        };

        // Push slot info onto signal info.
        // For now we don't deal with the bind list. At the moment it doesn't
        // seem neccessary.
        signal_info.add_to_slot_list(&slot_info);
        self.set::<SignalInfo>(
            StorageKey::new_signal_key(&sig_loc.address, &sig_loc.signal_key),
            &signal_info, debug_record,
        )
    }

    // Detach from a signal
    pub fn detach_slot_from_signal(
        &mut self, sig_loc: &SignalLocation, slot_loc: &SlotLocation,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Result<()> {
        // Get the signal info from the db and unpack.
        let signal_info = self.get::<SignalInfo>(
            StorageKey::new_signal_key(&sig_loc.address, &sig_loc.signal_key)
        );
        let mut signal_info = match signal_info {
            Ok(s) => match s {
                Some(s) => s,
                None => return Ok(()),
            },
            Err(e) => return Err(e),
        };

        // Remove slot from signal info.
        signal_info.remove_from_slot_list(slot_loc);

        // Push changes onto the db.
        self.set::<SignalInfo>(
            StorageKey::new_signal_key(&sig_loc.address, &sig_loc.signal_key),
            &signal_info, debug_record
        )
    }

    //////////////////////////////////////////////////////
    /* Emitting a signal */
    pub fn emit_signal(
        &mut self, sig_loc: &SignalLocation, arg_vector: &Vec::<Bytes>, epoch_height: u64,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Result<()> {
        // Get signal info from db.
        let signal_info = self.get::<SignalInfo>(
            StorageKey::new_signal_key(&sig_loc.address, &sig_loc.signal_key)
        );
        let signal_info = match signal_info {
            Ok(s) => match s {
                Some(s) => s,
                None => return Ok(()),
            },
            Err(e) => return Err(e),
        };
        // For each slot in the list, create a slot transaction and push to global queue.
        let slot_list = signal_info.get_slot_list();
        for s in slot_list {
            let tx = SlotTx::new(s, epoch_height, arg_vector);
            let err = self.enqueue_slot_tx_to_epoch_queue(epoch_height, tx, None);
            if err.is_err() {
                return err;
            }
        }
        Ok(())
    }

    //////////////////////////////////////////////////////
    /* Account slot transaction queues */
    // Get individual account's slot tx queue.
    pub fn get_slot_tx_queue(
        &self, address: &Address,
    ) -> Result<Option<SlotTxQueue>> {
        self.get::<SlotTxQueue>(StorageKey::new_slot_tx_queue_key(address))
    }

    // Enqueue a slot transaction to account's slot tx queue.
    pub fn enqueue_slot_tx(
        &mut self, slot_tx: SlotTx,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Result<()> {
        // Get address from slot tx.
        let address = slot_tx.get_owner().clone();

        // Get and unpack the slot_tx_queue.
        let slot_tx_queue = self.get::<SlotTxQueue>(
            StorageKey::new_slot_tx_queue_key(&address)
        );
        let mut slot_tx_queue = match slot_tx_queue {
            Ok(q) => match q {
                Some(q) => q,
                None => SlotTxQueue::new(),
            },
            Err(e) => return Err(e),
        };
        // Enqueue the new slot transactions.
        slot_tx_queue.enqueue(slot_tx);
        // Push change to db.
        self.set::<SlotTxQueue>(
            StorageKey::new_slot_tx_queue_key(&address), &slot_tx_queue, debug_record
        )
    }

    // Dequeue a slot transaction from an account's slot tx queue.
    pub fn dequeue_slot_tx(
        &mut self, address: &Address,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Option<SlotTx> {
        // Get account queue and unpack.
        let slot_tx_queue = self.get::<SlotTxQueue>(
            StorageKey::new_slot_tx_queue_key(address)
        );
        let mut slot_tx_queue = match slot_tx_queue {
            Ok(q) => match q {
                Some(q) => q,
                None => return None,
            },
            _ => return None,
        };
        // Dequeue slot_tx and push to db.
        let slot_tx = slot_tx_queue.dequeue();
        if slot_tx_queue.is_empty() {
            self.delete(
                StorageKey::new_slot_tx_queue_key(address), debug_record
            ).unwrap();
        } else {
            self.set::<SlotTxQueue>(
                StorageKey::new_slot_tx_queue_key(address), &slot_tx_queue, debug_record
            ).unwrap();
        }
        slot_tx
    }

    //////////////////////////////////////////////////////  
    /* Distribution of slot transactions from global queue to individuals */
    // Drain a particular branch of the global queue and enqueue them into
    // individual account queues.
    pub fn drain_epoch_queue(
        &mut self, epoch_height: u64
    ) -> Result<()> {
        // Dequeue from epoch queue.
        let queue = self.dequeue_epoch_queue_from_global_queue(epoch_height, None);
        let mut queue = match queue {
            Some(q) => q,
            None => return Ok(()),
        };
        // Pop items off the queue and move them where they belong.
        while !queue.is_empty() {
            if let Some(tx) = queue.dequeue() {
                let err = self.enqueue_slot_tx(tx, None);
                if err.is_err() {
                    return err;
                }
            }
        }
        Ok(())
    }

    //////////////////////////////////////////////////////
    /* Global slot transaction queue */
    // Get global slot tx queue for a specific epoch number.
    pub fn get_slot_tx_epoch_queue(
        &self, epoch_height: u64
    ) -> Result<Option<SlotTxQueue>> {
        // Convert epoch height to bytes to form the key.
        let buffer = &epoch_height.to_le_bytes();
        let global_slot_tx_queue_key = StorageKey::new_storage_key(
            &GLOBAL_SLOT_TX_QUEUE_ADDRESS,
            buffer,
        );
        // Retrieve the queue from db.
        self.get::<SlotTxQueue>(global_slot_tx_queue_key)
    }

    // Enqueue a slot transaction to be executed at a future epoch number.
    pub fn enqueue_slot_tx_to_epoch_queue(
        &mut self, epoch_height: u64, slot_tx: SlotTx,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Result<()> {
        // Convert epoch height to bytes to form the key.
        let buffer = &epoch_height.to_le_bytes();
        let global_slot_tx_queue_key = StorageKey::new_storage_key(
            &GLOBAL_SLOT_TX_QUEUE_ADDRESS,
            buffer,
        );
        // Get slot transaction queue and unpack.
        let slot_tx_queue = self.get::<SlotTxQueue>(
            global_slot_tx_queue_key
        );
        let mut slot_tx_queue = match slot_tx_queue {
            Ok(q) => match q {
                Some(q) => q,
                None => SlotTxQueue::new(),
            },
            Err(e) => return Err(e),
        };
        // Enqueue slot transaction and push to db.
        slot_tx_queue.enqueue(slot_tx);
        self.set::<SlotTxQueue>(
            global_slot_tx_queue_key, &slot_tx_queue, debug_record
        )
    }

    // Prune a list of slot transactions indexed by the epoch number.
    pub fn dequeue_epoch_queue_from_global_queue(
        &mut self, epoch_height: u64,
        debug_record: Option<&mut ComputeEpochDebugRecord>
    ) -> Option<SlotTxQueue> {
        // Convert epoch height to bytes to create the key.
        let buffer = &epoch_height.to_le_bytes();
        let global_slot_tx_queue_key = StorageKey::new_storage_key(
            &GLOBAL_SLOT_TX_QUEUE_ADDRESS,
            buffer,
        );
        // Get and unpack the slot tx queue.
        let slot_tx_queue = self.get::<SlotTxQueue>(
            global_slot_tx_queue_key
        );
        let slot_tx_queue = match slot_tx_queue {
            Ok(q) => q,
            _ => return None,
        };
        // Delete the queue from db and return the list.
        self.delete(global_slot_tx_queue_key, debug_record).unwrap();
        slot_tx_queue
    }
    
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}
