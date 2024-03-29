// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod prefetcher;

use self::account_entry::{AccountEntry, AccountState};
use crate::{
    bytes::Bytes,
    consensus::debug::ComputeEpochDebugRecord,
    executive::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    hash::KECCAK_EMPTY,
    parameters::staking::*,
    statedb::{ErrorKind as DbErrorKind, Result as DbResult, StateDb},
    storage::StateRootWithAuxInfo,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use primitives::{Account, EpochId, StorageKey, StorageLayout, StorageValue};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

#[cfg(test)]
mod account_entry_tests;
#[cfg(test)]
mod state_tests;

mod account_entry;
mod substate;

pub use self::{account_entry::OverlayAccount, substate::Substate};
use crate::evm::Spec;
use parking_lot::{MappedRwLockWriteGuard, RwLock, RwLockWriteGuard};

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
#[cfg(test)]
mod signal_tests;

use primitives::{
    SlotTxQueue, SlotTx, SignalInfo, SlotInfo, SignalLocation, SlotLocation,
    SlotTxAddressList,
};
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
enum RequireCache {
    None,
    CodeSize,
    Code,
    DepositList,
    VoteStakeList,
    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    SlotTxQueue,
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}

/// Mode of dealing with null accounts.
#[derive(PartialEq)]
pub enum CleanupMode<'a> {
    /// Create accounts which would be null.
    ForceCreate,
    /// Don't delete null accounts upon touching, but also don't create them.
    NoEmpty,
    /// Mark all touched accounts.
    /// TODO: We have not implemented the correct behavior of TrackTouched for
    /// internal Contracts.
    TrackTouched(&'a mut HashSet<Address>),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum CollateralCheckResult {
    ExceedStorageLimit { limit: U256, required: U256 },
    NotEnoughBalance { required: U256, got: U256 },
    Valid,
}

#[derive(Copy, Clone, Debug)]
struct StakingState {
    // This is the total number of CFX issued.
    total_issued_tokens: U256,
    // This is the total number of CFX used as staking.
    total_staking_tokens: U256,
    // This is the total number of CFX used as collateral.
    total_storage_tokens: U256,
    // This is the interest rate per block.
    interest_rate_per_block: U256,
    // This is the accumulated interest rate.
    accumulate_interest_rate: U256,
}

pub struct State {
    db: StateDb,

    dirty_accounts_to_commit: Vec<(Address, AccountEntry)>,
    cache: RwLock<HashMap<Address, AccountEntry>>,
    staking_state_checkpoints: RwLock<Vec<StakingState>>,
    checkpoints: RwLock<Vec<HashMap<Address, Option<AccountEntry>>>>,
    account_start_nonce: U256,
    contract_start_nonce: U256,
    staking_state: StakingState,
    // This is the total number of blocks executed so far. It is the same as
    // the `number` entry in EVM Environment.
    block_number: u64,
    vm: VmFactory,

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // Keep track of the changes to the global slot tx queue.
    // As a refresher, the changes are stored as a mapping between epoch number
    // and slot transaction queue. This mapping of changes are also stored
    // in checkpoints along with staking state, account info, and slot tx accounts.
    global_slot_tx_queue_cache_checkpoints: RwLock<Vec<HashMap<u64, SlotTxQueue>>>,
    global_slot_tx_queue_cache: RwLock<HashMap<u64, SlotTxQueue>>,

    // Keep track of the changes to the list of accounts with slot tx ready to be handled.
    // This list is also stored in checkpoints.
    ready_slot_tx_addresses_cache_checkpoints: RwLock<Vec<SlotTxAddressList>>,
    ready_slot_tx_addresses_cache: RwLock<Option<SlotTxAddressList>>,
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}

impl State {
    pub fn new(
        db: StateDb, vm: VmFactory, spec: &Spec, block_number: u64,
    ) -> Self {
        let annual_interest_rate =
            db.get_annual_interest_rate().expect("no db error");
        let accumulate_interest_rate =
            db.get_accumulate_interest_rate().expect("no db error");
        let total_issued_tokens =
            db.get_total_issued_tokens().expect("No db error");
        let total_staking_tokens =
            db.get_total_staking_tokens().expect("No db error");
        let total_storage_tokens =
            db.get_total_storage_tokens().expect("No db error");
        /*
        let account_start_nonce = (block_number
            * ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT as u64)
            .into();
        */
        let account_start_nonce = U256::zero();
        let contract_start_nonce = if spec.no_empty {
            U256::one()
        } else {
            U256::zero()
        };
        State {
            db,
            cache: Default::default(),
            staking_state_checkpoints: Default::default(),
            checkpoints: Default::default(),
            account_start_nonce,
            contract_start_nonce,
            staking_state: StakingState {
                total_issued_tokens,
                total_staking_tokens,
                total_storage_tokens,
                interest_rate_per_block: annual_interest_rate
                    / U256::from(BLOCKS_PER_YEAR),
                accumulate_interest_rate,
            },
            block_number,
            vm,
            dirty_accounts_to_commit: Default::default(),
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            global_slot_tx_queue_cache_checkpoints: Default::default(),
            global_slot_tx_queue_cache: Default::default(),
            ready_slot_tx_addresses_cache_checkpoints: Default::default(),
            ready_slot_tx_addresses_cache: Default::default(),
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
        }
    }

    pub fn contract_start_nonce(&self) -> U256 { self.contract_start_nonce }

    /// Increase block number and calculate the current secondary reward.
    pub fn increase_block_number(&mut self) -> U256 {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */

        // TODO: The below assertion fires. Not sure if this is imporant.
        // TODO: Investigate into the importance of checkpoints. Is the current
        // TODO: checkpoint implementation correct? is it important?

        // assert!(self.global_slot_tx_queue_cache.get_mut().is_empty());

        /* Signal and Slots end */
        //////////////////////////////////////////////////////////////////////
        self.block_number += 1;
        //self.account_start_nonce +=
        //    ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT.into();
        self.staking_state.accumulate_interest_rate =
            self.staking_state.accumulate_interest_rate
                * (*INTEREST_RATE_PER_BLOCK_SCALE
                    + self.staking_state.interest_rate_per_block)
                / *INTEREST_RATE_PER_BLOCK_SCALE;
        let secondary_reward = self.staking_state.total_storage_tokens
            * self.staking_state.interest_rate_per_block
            / *INTEREST_RATE_PER_BLOCK_SCALE;
        // TODO: the interest from tokens other than storage and staking should
        // send to public fund.
        secondary_reward
    }

    /// Maintain `total_issued_tokens`.
    pub fn add_total_issued(&mut self, v: U256) {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.staking_state.total_issued_tokens += v;
    }

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    pub fn subtract_total_issued(&mut self, v: U256) {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.staking_state.total_issued_tokens -= v;
    }

    /// Get a VM factory that can execute on this state.
    pub fn vm_factory(&self) -> VmFactory { self.vm.clone() }

    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index.
    pub fn checkpoint(&mut self) -> usize {
        self.staking_state_checkpoints
            .get_mut()
            .push(self.staking_state.clone());
        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */
        self.global_slot_tx_queue_cache_checkpoints
            .get_mut()
            .push(self.global_slot_tx_queue_cache.read().clone());
        self.check_ready_slot_tx_addresses_cache(true)
            .expect("Failed to check ready slot tx addresses cache");
        self.ready_slot_tx_addresses_cache_checkpoints
            .get_mut()
            .push(self.ready_slot_tx_addresses_cache.read().as_ref().unwrap().clone());
        /* Signal and Slots end */
        //////////////////////////////////////////////////////////////////////
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(HashMap::new());
        index
    }

    pub fn checkout_collateral_for_storage(
        &mut self, addr: &Address,
    ) -> DbResult<CollateralCheckResult> {
        let (inc, sub) =
            self.ensure_cached(addr, RequireCache::None, |acc| {
                acc.map_or((0, 0), |account| {
                    account.get_uncleared_storage_entries()
                })
            })?;
        if inc > 0 || sub > 0 {
            self.require_exists(addr, false)?
                .reset_uncleared_storage_entries();
        }

        if sub > 0 {
            let delta = U256::from(sub) * *COLLATERAL_PER_STORAGE_KEY;
            assert!(self.exists(addr)?);
            self.sub_collateral_for_storage(addr, &delta)?;
        }
        if inc > 0 {
            let delta = U256::from(inc) * *COLLATERAL_PER_STORAGE_KEY;
            if self.is_contract(addr) {
                let sponsor_balance =
                    self.sponsor_balance_for_collateral(addr)?;
                // sponsor_balance is not enough to cover storage incremental.
                if delta > sponsor_balance {
                    return Ok(CollateralCheckResult::NotEnoughBalance {
                        required: delta,
                        got: sponsor_balance,
                    });
                }
            } else {
                let balance = self.balance(addr).expect("no db error");
                // balance is not enough to cover storage incremental.
                if delta > balance {
                    return Ok(CollateralCheckResult::NotEnoughBalance {
                        required: delta,
                        got: balance,
                    });
                }
            }
            self.add_collateral_for_storage(addr, &delta)?;
        }
        Ok(CollateralCheckResult::Valid)
    }

    // This function only returns valid or db error
    pub fn checkout_ownership_changed(
        &mut self, substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult> {
        let mut collateral_for_storage_sub = HashMap::new();
        let mut collateral_for_storage_inc = HashMap::new();
        if let Some(checkpoint) = self.checkpoints.get_mut().last() {
            for address in checkpoint.keys() {
                if let Some(ref mut maybe_acc) = self
                    .cache
                    .get_mut()
                    .get_mut(address)
                    .filter(|x| x.is_dirty())
                {
                    if let Some(ref mut acc) = maybe_acc.account.as_mut() {
                        let ownership_delta =
                            acc.commit_ownership_change(&self.db);
                        for (addr, (inc, sub)) in ownership_delta {
                            if inc > 0 {
                                *collateral_for_storage_inc
                                    .entry(addr)
                                    .or_insert(0) += inc;
                            }
                            if sub > 0 {
                                *collateral_for_storage_sub
                                    .entry(addr)
                                    .or_insert(0) += sub;
                            }
                        }
                    }
                }
            }
        }
        for (addr, sub) in &collateral_for_storage_sub {
            self.require_exists(&addr, false)?
                .add_unrefunded_storage_entries(*sub);
            *substate.storage_released.entry(*addr).or_insert(0) +=
                sub * BYTES_PER_STORAGE_KEY;
        }
        for (addr, inc) in &collateral_for_storage_inc {
            self.require_exists(&addr, false)?
                .add_unpaid_storage_entries(*inc);
            *substate.storage_collateralized.entry(*addr).or_insert(0) +=
                inc * BYTES_PER_STORAGE_KEY;
        }
        Ok(CollateralCheckResult::Valid)
    }

    pub fn check_collateral_for_storage_finally(
        &mut self, storage_owner: &Address, storage_limit: &U256,
        substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult>
    {
        self.checkout_ownership_changed(substate)?;

        let touched_addresses =
            if let Some(checkpoint) = self.checkpoints.get_mut().last() {
                checkpoint.keys().cloned().collect()
            } else {
                HashSet::new()
            };
        // No new addresses added to checkpoint in this for-loop.
        for address in touched_addresses.iter() {
            match self.checkout_collateral_for_storage(address)? {
                CollateralCheckResult::Valid => {}
                res => return Ok(res),
            }
        }

        let collateral_for_storage =
            self.collateral_for_storage(storage_owner)?;
        if collateral_for_storage > *storage_limit {
            Ok(CollateralCheckResult::ExceedStorageLimit {
                limit: *storage_limit,
                required: collateral_for_storage,
            })
        } else {
            Ok(CollateralCheckResult::Valid)
        }
    }

    /// Merge last checkpoint with previous.
    /// Caller should make sure the function
    /// `check_collateral_for_storage()` was called before calling
    /// this function.
    pub fn discard_checkpoint(&mut self) {
        // merge with previous checkpoint
        let last = self.checkpoints.get_mut().pop();
        if let Some(mut checkpoint) = last {
            self.staking_state_checkpoints.get_mut().pop();
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            self.global_slot_tx_queue_cache_checkpoints.get_mut().pop();
            self.ready_slot_tx_addresses_cache_checkpoints.get_mut().pop();
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
            if let Some(ref mut prev) = self.checkpoints.get_mut().last_mut() {
                if prev.is_empty() {
                    **prev = checkpoint;
                } else {
                    for (k, v) in checkpoint.drain() {
                        prev.entry(k).or_insert(v);
                    }
                }
            }
        }
    }

    /// Revert to the last checkpoint and discard it.
    pub fn revert_to_checkpoint(&mut self) {
        if let Some(mut checkpoint) = self.checkpoints.get_mut().pop() {
            self.staking_state = self
                .staking_state_checkpoints
                .get_mut()
                .pop()
                .expect("staking_state_checkpoint should exist");
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            let tx_checkpoint = self.global_slot_tx_queue_cache_checkpoints
                                    .get_mut()
                                    .pop()
                                    .expect("global slot tx queue cache checkpoint should exist");
            let tx_checkpoint = RwLock::new(tx_checkpoint);
            self.global_slot_tx_queue_cache = tx_checkpoint;

            let slot_tx_accounts_checkpoint = self.ready_slot_tx_addresses_cache_checkpoints
                                    .get_mut()
                                    .pop()
                                    .expect("ready slot tx accounts checkpoint should exist");
            let slot_tx_accounts_checkpoint = RwLock::new(Some(slot_tx_accounts_checkpoint));
            self.ready_slot_tx_addresses_cache = slot_tx_accounts_checkpoint;

            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
            for (k, v) in checkpoint.drain() {
                match v {
                    Some(v) => match self.cache.get_mut().entry(k) {
                        Entry::Occupied(mut e) => {
                            e.get_mut().overwrite_with(v);
                        }
                        Entry::Vacant(e) => {
                            e.insert(v);
                        }
                    },
                    None => {
                        if let Entry::Occupied(e) =
                            self.cache.get_mut().entry(k)
                        {
                            if e.get().is_dirty() {
                                e.remove();
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn new_contract_with_admin(
        &mut self, contract: &Address, admin: &Address, balance: U256,
        nonce: U256,
    ) -> DbResult<()>
    {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(
                OverlayAccount::new_contract_with_admin(
                    contract, balance, nonce, admin,
                ),
            )),
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn new_contract(
        &mut self, contract: &Address, balance: U256, nonce: U256,
    ) -> DbResult<()> {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(OverlayAccount::new_contract(
                contract, balance, nonce,
            ))),
        );
        Ok(())
    }

    pub fn balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.balance())
        })
    }

    // TODO: first check the type bits of the address.
    pub fn is_contract(&self, address: &Address) -> bool {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| acc.is_contract())
        })
        .unwrap_or(false)
    }

    fn maybe_address(address: &Address) -> Option<Address> {
        if address.is_zero() {
            None
        } else {
            Some(*address)
        }
    }

    pub fn sponsor_for_gas(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |acc| {
                Self::maybe_address(&acc.sponsor_info().sponsor_for_gas)
            })
        })
    }

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |acc| {
                Self::maybe_address(&acc.sponsor_info().sponsor_for_collateral)
            })
        })
    }

    pub fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()>
    {
        if *sponsor != self.sponsor_for_gas(address)?.unwrap_or_default()
            || *sponsor_balance != self.sponsor_balance_for_gas(address)?
        {
            self.require_exists(address, false).map(|mut x| {
                x.set_sponsor_for_gas(sponsor, sponsor_balance, upper_bound)
            })
        } else {
            Ok(())
        }
    }

    pub fn set_sponsor_for_collateral(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
    ) -> DbResult<()> {
        if *sponsor != self.sponsor_for_collateral(address)?.unwrap_or_default()
            || *sponsor_balance
                != self.sponsor_balance_for_collateral(address)?
        {
            self.require_exists(address, false).map(|mut x| {
                x.set_sponsor_for_collateral(sponsor, sponsor_balance)
            })
        } else {
            Ok(())
        }
    }

    pub fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| acc.sponsor_info().sponsor_gas_bound)
        })
    }

    pub fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_gas
            })
        })
    }

    pub fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_collateral
            })
        })
    }

    pub fn set_admin(
        &mut self, requester: &Address, contract_address: &Address,
        admin: &Address,
    ) -> DbResult<()>
    {
        if self.ensure_cached(contract_address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| {
                acc.is_contract()
                    && acc.admin() == requester
                    && acc.admin() != admin
            })
        })? {
            self.require_exists(&contract_address, false)?
                .set_admin(requester, admin);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .add_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_sponsor_balance_for_collateral(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .add_sponsor_balance_for_collateral(by);
        }
        Ok(())
    }

    pub fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        match self.ensure_cached(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            RequireCache::None,
            |acc| {
                acc.map_or(Ok(false), |acc| {
                    acc.check_commission_privilege(
                        &self.db,
                        contract_address,
                        user,
                    )
                })
            },
        ) {
            Ok(Ok(bool)) => Ok(bool),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e),
        }
    }

    pub fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        info!("add_commission_privilege contract_address: {:?}, contract_owner: {:?}, user: {:?}", contract_address, contract_owner, user);

        let mut account = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            false,
        )?;
        Ok(account.add_commission_privilege(
            contract_address,
            contract_owner,
            user,
        ))
    }

    pub fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        let mut account = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            false,
        )?;
        Ok(account.remove_commission_privilege(
            contract_address,
            contract_owner,
            user,
        ))
    }

    pub fn nonce(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.nonce())
        })
    }

    pub fn code_hash(&self, address: &Address) -> DbResult<Option<H256>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.and_then(|acc| Some(acc.code_hash()))
        })
    }

    pub fn code_size(&self, address: &Address) -> DbResult<Option<usize>> {
        self.ensure_cached(address, RequireCache::CodeSize, |acc| {
            acc.and_then(|acc| acc.code_size())
        })
    }

    pub fn code_owner(&self, address: &Address) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code_owner())
        })
    }

    pub fn code(&self, address: &Address) -> DbResult<Option<Arc<Bytes>>> {
        self.ensure_cached(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code())
        })
    }

    pub fn staking_balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.staking_balance())
        })
    }

    pub fn collateral_for_storage(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| {
                *account.collateral_for_storage()
            })
        })
    }

    pub fn admin(&self, address: &Address) -> DbResult<Address> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(Address::zero(), |acc| *acc.admin())
        })
    }

    pub fn withdrawable_staking_balance(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::VoteStakeList, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.withdrawable_staking_balance(self.block_number)
            })
        })
    }

    pub fn deposit_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_cached(address, RequireCache::DepositList, |acc| {
            acc.map_or(0, |acc| acc.deposit_list().map_or(0, |l| l.len()))
        })
    }

    pub fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_cached(address, RequireCache::VoteStakeList, |acc| {
            acc.map_or(0, |acc| acc.vote_stake_list().map_or(0, |l| l.len()))
        })
    }

    pub fn inc_nonce(&mut self, address: &Address) -> DbResult<()> {
        self.require_or_new_user_account(address)
            .map(|mut x| x.inc_nonce())
    }

    pub fn set_nonce(
        &mut self, address: &Address, nonce: &U256,
    ) -> DbResult<()> {
        self.require_or_new_user_account(address)
            .map(|mut x| x.set_nonce(nonce))
    }

    pub fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?.sub_balance(by);
        }

        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            if self.exists(address)? {
                set.insert(*address);
            }
        }
        Ok(())
    }

    pub fn add_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        let exists = self.exists(address)?;
        if !exists && !address.is_user_account_address() {
            // Sending to non-existent non user account address is
            // not allowed.
            //
            // There are checks to forbid it at transact level.
            //
            // The logic here is intended for incorrect miner coin-base. In this
            // case, the mining reward get lost.
            warn!(
                "add_balance: address does not already exist and is not an user account. {:?}",
                address
            );
            return Ok(());
        }
        if !by.is_zero()
            || (cleanup_mode == CleanupMode::ForceCreate && !exists)
        {
            self.require_or_new_user_account(address)?.add_balance(by);
        }

        if let CleanupMode::TrackTouched(set) = cleanup_mode {
            if exists {
                set.insert(*address);
            }
        }
        Ok(())
    }

    /// Caller should make sure that staking_balance for this account is
    /// sufficient enough.
    pub fn add_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .add_collateral_for_storage(by);
            self.staking_state.total_storage_tokens += *by;
        }
        Ok(())
    }

    pub fn sub_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_collateral_for_storage(by);
            self.staking_state.total_storage_tokens -= *by;
        }
        Ok(())
    }

    pub fn deposit(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            {
                let mut account = self.require_exists(address, false)?;
                account.cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    &self.db,
                )?;
                account.deposit(
                    *amount,
                    self.staking_state.accumulate_interest_rate,
                    self.block_number,
                );
            }
            self.staking_state.total_staking_tokens += *amount;
        }
        Ok(())
    }

    pub fn withdraw(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            let interest;
            {
                let mut account = self.require_exists(address, false)?;
                account.cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    &self.db,
                )?;
                interest = account.withdraw(
                    *amount,
                    self.staking_state.accumulate_interest_rate,
                );
            }
            // the interest will be put in balance.
            self.staking_state.total_issued_tokens += interest;
            self.staking_state.total_staking_tokens -= *amount;
        }
        Ok(())
    }

    pub fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            let mut account = self.require_exists(address, false)?;
            account.cache_staking_info(
                false, /* cache_deposit_list */
                true,  /* cache_vote_list */
                &self.db,
            )?;
            account.vote_lock(*amount, unlock_block_number);
        }
        Ok(())
    }

    pub fn remove_expired_vote_stake_info(
        &mut self, address: &Address,
    ) -> DbResult<()> {
        let mut account = self.require_exists(address, false)?;
        account.cache_staking_info(
            false, /* cache_deposit_list */
            true,  /* cache_vote_list */
            &self.db,
        )?;
        account.remove_expired_vote_stake_info(self.block_number);
        Ok(())
    }

    pub fn annual_interest_rate(&self) -> U256 {
        self.staking_state.interest_rate_per_block * U256::from(BLOCKS_PER_YEAR)
    }

    pub fn set_annual_interest_rate(&mut self, annual_interest_rate: U256) {
        self.staking_state.interest_rate_per_block =
            annual_interest_rate / U256::from(BLOCKS_PER_YEAR);
    }

    pub fn accumulate_interest_rate(&self) -> &U256 {
        &self.staking_state.accumulate_interest_rate
    }

    pub fn block_number(&self) -> u64 { self.block_number }

    pub fn total_issued_tokens(&self) -> &U256 {
        &self.staking_state.total_issued_tokens
    }

    pub fn total_staking_tokens(&self) -> &U256 {
        &self.staking_state.total_staking_tokens
    }

    pub fn total_storage_tokens(&self) -> &U256 {
        &self.staking_state.total_storage_tokens
    }

    #[allow(dead_code)]
    fn touch(&mut self, address: &Address) -> DbResult<()> {
        drop(self.require_exists(address, false)?);
        Ok(())
    }

    fn needs_update(require: RequireCache, account: &OverlayAccount) -> bool {
        trace!("update_account_cache account={:?}", account);
        match require {
            RequireCache::None => false,
            RequireCache::Code | RequireCache::CodeSize => !account.is_cached(),
            RequireCache::DepositList => account.deposit_list().is_none(),
            RequireCache::VoteStakeList => account.vote_stake_list().is_none(),
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            RequireCache::SlotTxQueue => account.slot_tx_queue().is_none(),
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
        }
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount, db: &StateDb,
    ) -> bool {
        match require {
            RequireCache::None => true,
            RequireCache::Code | RequireCache::CodeSize => {
                account.cache_code(db).is_some()
            }
            RequireCache::DepositList => account
                .cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    db,
                )
                .is_ok(),
            RequireCache::VoteStakeList => account
                .cache_staking_info(
                    false, /* cache_deposit_list */
                    true,  /* cache_vote_list */
                    db,
                )
                .is_ok(),
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            RequireCache::SlotTxQueue => account
                .cache_slot_tx_queue(db)
                .is_ok(),
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
        }
    }

    fn commit_staking_state(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        self.db.set_annual_interest_rate(
            &(self.staking_state.interest_rate_per_block
                * U256::from(BLOCKS_PER_YEAR)),
            debug_record.as_deref_mut(),
        )?;
        self.db.set_accumulate_interest_rate(
            &self.staking_state.accumulate_interest_rate,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_issued_tokens(
            &self.staking_state.total_issued_tokens,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_staking_tokens(
            &self.staking_state.total_staking_tokens,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_storage_tokens(
            &self.staking_state.total_storage_tokens,
            debug_record,
        )?;
        Ok(())
    }

    /// Assume that only contract with zero `collateral_for_storage` will be
    /// killed.
    fn recycle_storage(
        &mut self, killed_addresses: Vec<Address>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        for address in killed_addresses {
            self.db.delete(
                StorageKey::new_account_key(&address),
                debug_record.as_deref_mut(),
            )?;
            let storages_opt = self.db.delete_all(
                StorageKey::new_storage_root_key(&address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete_all(
                StorageKey::new_code_root_key(&address),
                debug_record.as_deref_mut(),
            )?;
            if let Some(storage_key_value) = storages_opt {
                for (key, value) in storage_key_value {
                    if let StorageKey::StorageKey { .. } =
                        StorageKey::from_delta_mpt_key(&key[..])
                    {
                        let storage_value =
                            rlp::decode::<StorageValue>(value.as_ref())?;
                        assert!(self
                            .exists(&storage_value.owner)
                            .expect("no db error"));
                        self.sub_collateral_for_storage(
                            &storage_value.owner,
                            &COLLATERAL_PER_STORAGE_KEY,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn precommit_make_dirty_accounts_list(&mut self) {
        if self.dirty_accounts_to_commit.is_empty() {
            let mut sorted_dirty_accounts = self
                .cache
                .get_mut()
                .drain()
                .filter_map(|(address, entry)| {
                    if entry.is_dirty() {
                        Some((address, entry))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            sorted_dirty_accounts.sort_by(|a, b| a.0.cmp(&b.0));
            self.dirty_accounts_to_commit = sorted_dirty_accounts;
        }
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        debug!("Commit epoch[{}]", epoch_id);
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());

        self.precommit_make_dirty_accounts_list();
        self.commit_staking_state(debug_record.as_deref_mut())?;

        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */
        assert!(self.global_slot_tx_queue_cache_checkpoints.get_mut().is_empty());
        self.commit_global_slot_tx_queue(debug_record.as_deref_mut())?;

        assert!(self.ready_slot_tx_addresses_cache_checkpoints.get_mut().is_empty());
        self.commit_ready_slot_tx_addresses(debug_record.as_deref_mut())?;
        /* Signal and Slots end */
        //////////////////////////////////////////////////////////////////////

        let mut killed_addresses = Vec::new();
        for (address, entry) in self.dirty_accounts_to_commit.iter_mut() {
            entry.state = AccountState::Committed;
            match &mut entry.account {
                None => killed_addresses.push(*address),
                Some(account) => {
                    account
                        .commit(&mut self.db, debug_record.as_deref_mut())?;
                    self.db.set::<Account>(
                        StorageKey::new_account_key(address),
                        &account.as_account(),
                        debug_record.as_deref_mut(),
                    )?;
                }
            }
        }
        self.recycle_storage(killed_addresses, debug_record)?;
        Ok(self.db.commit(epoch_id)?)
    }

    pub fn commit_and_notify(
        &mut self, epoch_id: EpochId, txpool: &SharedTransactionPool,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        let result = self.commit(epoch_id, debug_record)?;

        debug!("Notify epoch[{}]", epoch_id);

        let mut accounts_for_txpool = vec![];
        for (_address, entry) in &self.dirty_accounts_to_commit {
            if let Some(account) = &entry.account {
                accounts_for_txpool.push(account.as_account());
            }
        }
        {
            // TODO: use channel to deliver the message.
            let txpool_clone = txpool.clone();
            std::thread::Builder::new()
                .name("txpool_update_state".into())
                .spawn(move || {
                    txpool_clone.notify_modified_accounts(accounts_for_txpool);
                })
                .expect("can not notify tx pool to start state");
        }

        Ok(result)
    }

    pub fn init_code(
        &mut self, address: &Address, code: Bytes, owner: Address,
    ) -> DbResult<()> {
        self.require_exists(address, false)?.init_code(code, owner);
        Ok(())
    }

    pub fn transfer_balance(
        &mut self, from: &Address, to: &Address, by: &U256,
        mut cleanup_mode: CleanupMode,
    ) -> DbResult<()>
    {
        self.sub_balance(from, by, &mut cleanup_mode)?;
        self.add_balance(to, by, cleanup_mode)?;
        Ok(())
    }

    pub fn kill_account(&mut self, address: &Address) {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            address,
            AccountEntry::new_dirty(None),
        )
    }

    /// Return whether or not the address exists.
    pub fn try_load(&self, address: &Address) -> bool {
        if let Ok(true) =
            self.ensure_cached(address, RequireCache::None, |maybe| {
                maybe.is_some()
            })
        {
            // Try to load the code, but don't fail if there is no code.
            self.ensure_cached(address, RequireCache::Code, |_| ()).ok();
            true
        } else {
            false
        }
    }

    pub fn exists(&self, address: &Address) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::None, |acc| acc.is_some())
    }

    pub fn exists_and_not_null(&self, address: &Address) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| !acc.is_null())
        })
    }

    pub fn exists_and_has_code_or_nonce(
        &self, address: &Address,
    ) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::CodeSize, |acc| {
            acc.map_or(false, |acc| {
                acc.code_hash() != KECCAK_EMPTY
                    || *acc.nonce() != self.account_start_nonce
            })
        })
    }

    pub fn kill_garbage(
        &mut self, touched: &HashSet<Address>, remove_empty_touched: bool,
        min_balance: &Option<U256>, kill_contracts: bool,
    ) -> DbResult<()>
    {
        // TODO: consider both balance and staking_balance
        let to_kill: HashSet<_> = {
            self.cache
                .get_mut()
                .iter()
                .filter_map(|(address, ref entry)| {
                    if touched.contains(address)
                        && ((remove_empty_touched
                            && entry.exists_and_is_null())
                            || (min_balance.map_or(false, |ref balance| {
                                entry.account.as_ref().map_or(false, |acc| {
                                    (acc.is_basic() || kill_contracts)
                                        && acc.balance() < balance
                                        && entry
                                            .old_balance
                                            .as_ref()
                                            .map_or(false, |b| {
                                                acc.balance() < b
                                            })
                                })
                            })))
                    {
                        Some(address.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };
        for address in to_kill {
            self.kill_account(&address);
        }

        Ok(())
    }

    pub fn storage_at(
        &self, address: &Address, key: &Vec<u8>,
    ) -> DbResult<H256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(H256::zero(), |account| {
                account.storage_at(&self.db, key).unwrap_or(H256::zero())
            })
        })
    }

    #[cfg(test)]
    pub fn original_storage_at(
        &self, address: &Address, key: &Vec<u8>,
    ) -> DbResult<H256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(H256::zero(), |account| {
                account
                    .original_storage_at(&self.db, key)
                    .unwrap_or(H256::zero())
            })
        })
    }

    /// Get the value of storage at a specific checkpoint.
    /// TODO: Remove this function since it is not used outside.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &Address, key: &Vec<u8>,
    ) -> DbResult<Option<H256>> {
        #[derive(Debug)]
        enum ReturnKind {
            OriginalAt,
            SameAsNext,
        }

        let kind = {
            let checkpoints = self.checkpoints.read();

            if start_checkpoint_index >= checkpoints.len() {
                return Ok(None);
            }

            let mut kind = None;

            for checkpoint in checkpoints.iter().skip(start_checkpoint_index) {
                match checkpoint.get(address) {
                    Some(Some(AccountEntry {
                        account: Some(ref account),
                        ..
                    })) => {
                        if let Some(value) = account.cached_storage_at(key) {
                            return Ok(Some(value));
                        } else if account.is_newly_created_contract() {
                            return Ok(Some(H256::zero()));
                        } else {
                            kind = Some(ReturnKind::OriginalAt);
                            break;
                        }
                    }
                    Some(Some(AccountEntry { account: None, .. })) => {
                        return Ok(Some(H256::zero()));
                    }
                    Some(None) => {
                        kind = Some(ReturnKind::OriginalAt);
                        break;
                    }
                    // This key does not have a checkpoint entry.
                    None => {
                        kind = Some(ReturnKind::SameAsNext);
                    }
                }
            }

            kind.expect("start_checkpoint_index is checked to be below checkpoints_len; for loop above must have been executed at least once; it will either early return, or set the kind value to Some; qed")
        };

        match kind {
            ReturnKind::SameAsNext => Ok(Some(self.storage_at(address, key)?)),
            ReturnKind::OriginalAt => {
                Ok(Some(self.original_storage_at(address, key)?))
            }
        }
    }

    pub fn set_storage(
        &mut self, address: &Address, key: Vec<u8>, value: H256, owner: Address,
    ) -> DbResult<()> {
        if self.storage_at(address, &key)? != value {
            self.require_exists(address, false)?
                .set_storage(key, value, owner)
        }
        Ok(())
    }

    pub fn set_storage_layout(
        &mut self, address: &Address, layout: StorageLayout,
    ) -> DbResult<()> {
        self.require_exists(address, false)?
            .set_storage_layout(layout);
        Ok(())
    }

    fn update_cache(
        cache: &mut HashMap<Address, AccountEntry>,
        checkpoints: &mut Vec<HashMap<Address, Option<AccountEntry>>>,
        address: &Address, account: AccountEntry,
    )
    {
        let is_dirty = account.is_dirty();
        let old_value = cache.insert(*address, account);
        if is_dirty {
            if let Some(ref mut checkpoint) = checkpoints.last_mut() {
                checkpoint.entry(*address).or_insert(old_value);
            }
        }
    }

    fn insert_cache_if_fresh_account(
        cache: &mut HashMap<Address, AccountEntry>, address: &Address,
        maybe_account: Option<OverlayAccount>,
    ) -> bool
    {
        if !cache.contains_key(address) {
            cache.insert(*address, AccountEntry::new_clean(maybe_account));
            true
        } else {
            false
        }
    }

    fn ensure_cached<F, U>(
        &self, address: &Address, require: RequireCache, f: F,
    ) -> DbResult<U>
    where F: Fn(Option<&OverlayAccount>) -> U {
        let needs_update =
            if let Some(maybe_acc) = self.cache.read().get(address) {
                if let Some(account) = &maybe_acc.account {
                    Self::needs_update(require, account)
                } else {
                    false
                }
            } else {
                false
            };

        if needs_update {
            if let Some(maybe_acc) = self.cache.write().get_mut(address) {
                if let Some(account) = &mut maybe_acc.account {
                    if Self::update_account_cache(require, account, &self.db) {
                        return Ok(f(Some(account)));
                    } else {
                        return Err(DbErrorKind::IncompleteDatabase(
                            account.address().clone(),
                        )
                        .into());
                    }
                }
            }
        }

        let maybe_acc = self
            .db
            .get_account(address)?
            .map(|acc| OverlayAccount::new(address, acc));
        let cache = &mut *self.cache.write();
        Self::insert_cache_if_fresh_account(cache, address, maybe_acc);

        let account = cache.get_mut(address).unwrap();
        if let Some(maybe_acc) = &mut account.account {
            if !Self::update_account_cache(require, maybe_acc, &self.db) {
                return Err(DbErrorKind::IncompleteDatabase(
                    maybe_acc.address().clone(),
                )
                .into());
            }
        }

        Ok(f(cache
            .get(address)
            .and_then(|entry| entry.account.as_ref())))
    }

    fn require_exists(
        &self, address: &Address, require_code: bool,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        fn no_account_is_an_error(
            address: &Address,
        ) -> DbResult<OverlayAccount> {
            bail!(DbErrorKind::IncompleteDatabase(*address));
        }
        self.require_or_set(address, require_code, no_account_is_an_error)
    }

    fn require_or_new_user_account(
        &self, address: &Address,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        self.require_or_set(address, false, |address| {
            if address.is_user_account_address() {
                Ok(OverlayAccount::new_basic(
                    address,
                    U256::zero(),
                    self.account_start_nonce.into(),
                ))
            } else {
                unreachable!(
                    "address does not already exist and is not an user account. {:?}",
                    address
                )
            }
        })
    }

    fn require_or_set<F>(
        &self, address: &Address, require_code: bool, default: F,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>>
    where F: FnOnce(&Address) -> DbResult<OverlayAccount> {
        let mut cache;
        if !self.cache.read().contains_key(address) {
            let account = self
                .db
                .get_account(address)?
                .map(|acc| OverlayAccount::new(address, acc));
            cache = self.cache.write();
            Self::insert_cache_if_fresh_account(&mut *cache, address, account);
        } else {
            cache = self.cache.write();
        };

        // Save the value before modification into the checkpoint.
        if let Some(ref mut checkpoint) = self.checkpoints.write().last_mut() {
            checkpoint.entry(*address).or_insert_with(|| {
                cache.get(address).map(AccountEntry::clone_dirty)
            });
        }

        let entry = (*cache)
            .get_mut(address)
            .expect("entry known to exist in the cache");

        // Set the dirty flag.
        entry.state = AccountState::Dirty;

        if entry.account.is_none() {
            entry.account = Some(default(address)?);
        }

        if require_code {
            if !Self::update_account_cache(
                RequireCache::Code,
                entry
                    .account
                    .as_mut()
                    .expect("Required account must exist."),
                &self.db,
            ) {
                bail!(DbErrorKind::IncompleteDatabase(*address));
            }
        }

        Ok(RwLockWriteGuard::map(cache, |c| {
            c.get_mut(address)
                .expect("Entry known to exist in the cache.")
                .account
                .as_mut()
                .expect("Required account must exist.")
        }))
    }

    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.staking_state.interest_rate_per_block =
            self.db.get_annual_interest_rate().expect("no db error")
                / U256::from(BLOCKS_PER_YEAR);
        self.staking_state.accumulate_interest_rate =
            self.db.get_accumulate_interest_rate().expect("no db error");
        self.staking_state.total_issued_tokens =
            self.db.get_total_issued_tokens().expect("No db error");
        self.staking_state.total_staking_tokens =
            self.db.get_total_staking_tokens().expect("No db error");
        self.staking_state.total_storage_tokens =
            self.db.get_total_storage_tokens().expect("No db error");

        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */
        assert!(self.global_slot_tx_queue_cache_checkpoints.get_mut().is_empty());
        self.global_slot_tx_queue_cache.get_mut().clear();

        assert!(self.ready_slot_tx_addresses_cache_checkpoints.get_mut().is_empty());
        self.ready_slot_tx_addresses_cache = RwLock::new(None);
        /* Signal and Slots end */
        //////////////////////////////////////////////////////////////////////
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */

    // This section provides an API to be called by context.rs in the executive directory.
    // All operations done here are first done on cache, then commiting to the StateDb in
    // the commit functions found under State as well as in OverlayAccount.

    // Mentioned below that error handling should be rethought. I think this would be a better
    // way to handle errors. One other thing, I feel like it would be important to check if
    // an instance of a signal already exists. Not sure if we want to override it and potentially
    // lose the list of listeners. I left the code below as is because otherwise context doesn't compile.
    // But see if this implementation makes more sense or not.

    // Create a new signal definition.
    // If the signal already exists do nothing.
    pub fn create_signal(
        &mut self, signal_address: &Address,
        signal_key: &Vec<u8>
    ) -> DbResult<bool> {
        // Make sure account is cached.
        let empty_sig = self.signal_at(signal_address, signal_key)?;
        if !empty_sig.is_none() {
            return Ok(false);
        }
        // Create new signal instance.
        let sig_info = SignalInfo::new(
            signal_address,
            signal_key,
        );
        self.require_exists(signal_address, false)?
            .set_signal(sig_info);
        Ok(true)
    }

    // Create a new slot definition.
    pub fn create_slot(
        &mut self,         
        slot_address: &Address, slot_key: &Vec<u8>, 
        method_hash: &H256, gas_sponsor: &Address,
        gas_limit: &U256, gas_ratio: &U256,
        blk: &bool, sigroles: &Vec<u8>, sigmethods: &Vec<u8>,
    ) -> DbResult<bool> {
        // Make sure account is cached.
        let empty_slot = self.slot_at(slot_address, slot_key)?;
        if !empty_slot.is_none() {
            // skip creation
            return Ok(true);
        }
        // Create new slot instance.
        let slot_info = SlotInfo::new(
            slot_address, 
            slot_key, 
            method_hash,
            gas_sponsor,
            gas_limit, 
            gas_ratio,
            blk,
            sigroles,
            sigmethods,
        );
        self.require_exists(slot_address, false)?
            .set_slot(slot_info);
        Ok(true)
    }

    // Delete a signal.
    pub fn delete_signal(
        &mut self, location: &SignalLocation,
    ) -> DbResult<()> {
        // Make sure account is cached.
        let sig = self.signal_at(location.address(), location.signal_key())?;
        if sig.is_none() {
            return Ok(());
        }
        // Clean up every bind list.
        for slot in sig.unwrap().slot_list() {
            let slot_info = self.slot_at(slot.location().address(), slot.location().slot_key()).unwrap();
            if slot_info.is_none() {
                continue;
            }
            let mut slot_info = slot_info.unwrap();
            slot_info.remove_from_bind_list(location);
            self.require_exists(slot.location().address(), false)?
                .set_slot(slot_info);
        }
        // Delete the signal.
        self.require_exists(location.address(), false)?
            .delete_signal(location);
        Ok(())
    }

    // Delete a slot. Note that this is not reachable with opcode currently. 
    // This also cascades all the listening-to relationship
    pub fn delete_slot(
        &mut self, location: &SlotLocation,
    ) -> DbResult<()> {
        // Make sure account is cached.
        let slot = self.slot_at(location.address(), location.slot_key())?;
        if slot.is_none() {
            return Ok(());
        }
        // Clean up every bind list.
        for sig_loc in slot.unwrap().bind_list() {
            let sig = self.signal_at(sig_loc.address(), sig_loc.signal_key()).unwrap();
            if sig.is_none() {
                continue;
            }
            let mut sig = sig.unwrap();
            sig.remove_from_slot_list(location);
            self.require_exists(sig_loc.address(), false)?
                .set_signal(sig);
        }
        // Delete the signal.
        self.require_exists(location.address(), false)?
            .delete_slot(location);
        Ok(())
    }

    // Get signal info from the cache.
    pub fn signal_at(
        &self, address: &Address, key: &Vec<u8>,
    ) -> DbResult<Option<SignalInfo>> {
        let loc = SignalLocation::new(address, key);
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |account| {
                // in case the signal is deleted but not yet committed, return None
                if account.is_signal_deleted(&loc) {
                    None
                } else {
                    account.signal_at(&self.db, &loc)
                }
            })
        })
    }

    // Get slot info from the cache.
    pub fn slot_at(
        &self, address: &Address, key: &Vec<u8>,
    ) -> DbResult<Option<SlotInfo>> {
        let loc = SlotLocation::new(address, key);
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |account| {
                // in case the slot is deleted but not yet committed, return None
                if account.is_slot_deleted(&loc) {
                    None
                } else {
                    account.slot_at(&self.db, &loc)
            }})
        })
    }

    // Bind a slot to a signal.
    // Incomplete database error is returned if either the signal or slot cannot
    // be retrieved from the database.
    // Error is also returned if signal and slots don't match in argument count.
    // TODO: Figure out if we should throw an error if argument counts between the signal
    // and slots don't match or not. If they don't should an error be thrown?
    pub fn bind_slot_to_signal(
        &mut self, sig_loc: &SignalLocation, slot_loc: &SlotLocation
    ) -> DbResult<()> {
        // Get signal info, make sure it exists.
        let _sig_info = self.signal_at(sig_loc.address(), sig_loc.signal_key());
        let _sig_info = match _sig_info {
            Ok(Some(s)) => s,
            _ => {
                return Err(DbErrorKind::IncompleteDatabase(
                    sig_loc.address().clone(),
                )
                .into());
            }
        };

        // Get slot info, make sure it exists.
        let slot_info = self.slot_at(slot_loc.address(), slot_loc.slot_key());
        let slot_info = match slot_info {
            Ok(Some(s)) => s,
            _ => {
                return Err(DbErrorKind::IncompleteDatabase(
                    slot_loc.address().clone(),
                )
                .into());
            }
        };

        // Signal account.
        self.require_exists(sig_loc.address(), false)?
            .add_to_slot_list(&self.db, sig_loc, &slot_info);
        // Slot account.
        self.require_exists(&slot_loc.address(), false)?
            .add_to_bind_list(&self.db, slot_loc, sig_loc);
        Ok(())
    }

    // Detach a slot from a signal.
    pub fn detach_slot_from_signal(
        &self, sig_loc: &SignalLocation, slot_loc: &SlotLocation
    ) -> DbResult<U256> {
        // Get signal info, make sure it exists.
        let sig_info = self.signal_at(sig_loc.address(), sig_loc.signal_key())?;
        if sig_info.is_none() {
            return Err(DbErrorKind::IncompleteDatabase(sig_loc.address().clone()).into());
        }

        // Get slot info, make sure it exists.
        let slot_info = self.slot_at(slot_loc.address(), slot_loc.slot_key())?;
        if slot_info.is_none() {
            return Err(DbErrorKind::IncompleteDatabase(slot_loc.address().clone()).into());
        }

        // Signal account.
        self.require_exists(sig_loc.address(), false)?
            .remove_from_slot_list(&self.db, sig_loc, slot_loc);
        // Slot account.
        self.require_exists(&slot_loc.address(), false)?
            .remove_from_bind_list(&self.db, slot_loc, sig_loc);

        let slot_info = self.slot_at(slot_loc.address(), slot_loc.slot_key())
                            .expect("slot should exist at this point")
                            .unwrap();
        if slot_info.bind_list().len() == 0 {
            self.require_exists(&slot_loc.address(), false)?
                .delete_slot(&slot_loc);
        }

        Ok(U256::from(slot_info.bind_list().len())) 
    }

    // Emit a signal.
    pub fn emit_signal_and_queue_slot_tx(
        &mut self, 
        sig_loc: &SignalLocation, current_epoch_height: u64, 
        signal_delay: u64, raw_data: &Bytes,
        handler_addr: &Vec<u8>,
    ) -> DbResult<()> {
        let mut handler_in_address: Vec<Address> = Vec::new();
        if !handler_addr.clone().is_empty() {
            let mut i = 12;
            let mut handler_slice: [u8; 20] = [0u8; 20];
            while i < handler_addr.clone().len() && (i + 19) < handler_addr.clone().len(){
                let mut j = i;
                while j < i + 20 {
                    handler_slice[j-i] = handler_addr.clone()[j];
                    j+=1;
                }
                handler_in_address.push(Address::from(handler_slice));
                i += 32;
            }
        }
        // Get signal info.
        let sig_info = self.signal_at(sig_loc.address(), sig_loc.signal_key()).unwrap();
        if sig_info.is_none() {
            return Err(DbErrorKind::IncompleteDatabase(sig_loc.address().clone()).into());
        }
        // Create and queue slot transactions. If the delay is not 0, then the slot
        // transaction is queued on the global queue. If it is 0, we queue it directly
        // to the individual account queues + add address to the ready slot tx address list.
        let target_epoch_height = current_epoch_height + signal_delay;
        if signal_delay == 0 {
            for slot in sig_info.unwrap().slot_list() {
                let tx = SlotTx::new(
                    slot, 
                    &target_epoch_height, 
                    raw_data,
                );
                if handler_in_address.contains(&tx.address().clone()) || handler_in_address.is_empty() {
                    let contract_address = tx.address().clone();
                    self.ensure_cached(&contract_address, RequireCache::SlotTxQueue, |_acc| {})?;
                    self.require_exists(&contract_address, false)?
                        .enqueue_slot_tx(tx);
                    self.mark_address_with_ready_slot_tx(&contract_address)?;
                }
            }
        }
        else {
            for slot in sig_info.unwrap().slot_list() {
                let tx = SlotTx::new(
                    slot, 
                    &target_epoch_height, 
                    raw_data,
                );
                if handler_in_address.contains(&tx.address().clone()) || handler_in_address.is_empty(){
                    self.enqueue_slot_tx_to_global_queue(tx)?;
                }
            }
        }
        Ok(())
    }

    // Discard current cached addresses, and read from the Db.
    pub fn cache_ready_slot_tx_addresses(&mut self) -> DbResult<()> {
        let mut new_list = SlotTxAddressList::new();
        let mut cache = self.ready_slot_tx_addresses_cache.write();
        // Always read from the state db
        if let Some(addresses) = self.db.get_addresses_with_ready_slot_tx()? {
            new_list = addresses.clone();
        }
        *cache = Some(new_list);

        Ok(())
    }

    // Check if the address list is cached; cache from db if it is not and as requested.
    pub fn check_ready_slot_tx_addresses_cache(&mut self, do_update : bool) -> DbResult<bool> {
        let cached : bool;
        {
            // cached set to false if the list is None
            cached = !(self.ready_slot_tx_addresses_cache.read().is_none());
        }
        // Update the cache if cache is empty + as requested
        if !cached && do_update {
            self.cache_ready_slot_tx_addresses()?;
        }

        Ok(cached)
    }

    // Function to read the cached address list.
    // If the list is not set, return the newest list from db.
    pub fn get_cached_addresses_with_ready_slot_tx(
        &mut self
    ) -> DbResult<SlotTxAddressList> {
        self.check_ready_slot_tx_addresses_cache(true)?;
        let addresses = self.ready_slot_tx_addresses_cache.read().as_ref().unwrap().clone();
        Ok(addresses)
    }

    // Add a list of addresses to the ready slot tx account list.
    pub fn mark_addresses_with_ready_slot_tx(
        &mut self, addresses: Vec<Address>
    ) -> DbResult<()> {
        self.check_ready_slot_tx_addresses_cache(true)?;

        let mut cache = self.ready_slot_tx_addresses_cache.write();
        let new_list = (*cache).clone();
        let mut new_list = new_list.unwrap();
        new_list.append(&addresses);
        *cache = Some(new_list);

        Ok(())
    }

    // Add an account to the ready slot tx account list.
    pub fn mark_address_with_ready_slot_tx(
        &mut self, address: &Address
    ) -> DbResult<()> {
        self.check_ready_slot_tx_addresses_cache(true)?;

        let mut cache = self.ready_slot_tx_addresses_cache.write();
        let new_list = (*cache).clone();
        let mut new_list = new_list.unwrap();
        new_list.add(address);
        *cache = Some(new_list);

        Ok(())
    }

    // Remove an account from the ready slot tx account list.
    pub fn remove_address_with_ready_slot_tx(
        &mut self, address: &Address
    ) -> DbResult<()> {
        self.check_ready_slot_tx_addresses_cache(true)?;

        let mut cache = self.ready_slot_tx_addresses_cache.write();
        let new_list = (*cache).clone();
        let mut new_list = new_list.unwrap();
        if !new_list.is_empty() {
            new_list.remove(&address);
        }
        *cache = Some(new_list);

        Ok(())
    }

    // Bring the global slot queue to cache and changes.
    pub fn cache_global_slot_tx_queue(
        &mut self, epoch_height: u64,
    ) -> DbResult<()> {
        // Found in cache already.
        let cache_read = self.global_slot_tx_queue_cache.read();
        if let Some(_global_queue) = cache_read.get(&epoch_height) {
            return Ok(());
        }
        drop(cache_read);
        // If in db load it in, otherwise create new queue in cache.
        let mut cache_write = self.global_slot_tx_queue_cache.write();
        if let Some(global_queue) = self.db.get_global_slot_tx_queue(epoch_height)? {
            cache_write.insert(epoch_height, global_queue.clone());
        }
        else {
            cache_write.insert(epoch_height, SlotTxQueue::new());
        }
        Ok(())
    }

    // Queue a slot transaction to the queue.
    pub fn enqueue_slot_tx_to_global_queue(
        &mut self, slot_tx: SlotTx
    ) -> DbResult<()> {
        let epoch_height = slot_tx.epoch_height();
        // Cache global_slot_tx_queue.
        self.cache_global_slot_tx_queue(epoch_height)?;
        let mut cache = self.global_slot_tx_queue_cache.write();

        // Perform queueing.
        let mut global_queue = cache.get(&epoch_height).unwrap().clone();
        global_queue.enqueue(slot_tx);
        cache.insert(epoch_height, global_queue);
        Ok(())
    }

    // Prune a slot transaction queue off the global queue and push them
    // into individual account slot transaction queues.
    // This function should be used at the start of every epoch. Meaning
    // it should be used by the consensus executor.
    pub fn drain_global_slot_tx_queue(
        &mut self, epoch_height: u64,
    ) -> DbResult<()> {
        // Cache global queue.
        self.cache_global_slot_tx_queue(epoch_height)?;
        let mut ready_addresses = Vec::new();
        {
            let mut cache = self.global_slot_tx_queue_cache.write();

            // Dequeue and distribute to individual accounts.
            if let Some(global_queue) = cache.get(&epoch_height) {
                let mut global_queue = global_queue.clone();

                while !global_queue.is_empty() {
                    // unwrap is okay to use here because queue is not empty
                    let slot_tx = global_queue.dequeue().unwrap();
                    let address = slot_tx.address().clone();
                    self.ensure_cached(&address, RequireCache::SlotTxQueue, |_acc| {})?;
                    self.require_exists(&address, false)?
                        .enqueue_slot_tx(slot_tx);
                    // add the address to the ready list
                    ready_addresses.push(address);
                }
                assert!(global_queue.is_empty());
                cache.insert(epoch_height, global_queue);
            }
        }
        self.mark_addresses_with_ready_slot_tx(ready_addresses)?;
        Ok(())
    }

    // Commit ready slot tx accounts changes to the state db and clear the cache.
    pub fn commit_ready_slot_tx_addresses(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        let cached = self.check_ready_slot_tx_addresses_cache(false)?;
        if cached {
            let mut cache = self.ready_slot_tx_addresses_cache.write();
            let addresses = (*cache).as_ref();
            // If address list is not empty, commit it. Otherwise delete it from db.
            if !addresses.unwrap().is_empty() {
                self.db.set_addresses_with_ready_slot_tx(
                    &addresses.unwrap(),
                    debug_record.as_deref_mut()
                )?;
            } else {
                self.db.delete_addresses_with_ready_slot_tx(
                    debug_record.as_deref_mut()
                )?;
            }
            *cache = None;
        }
        Ok(())
    }

    // Commit global queue changes to the state db.
    pub fn commit_global_slot_tx_queue(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        for (k, queue) in self.global_slot_tx_queue_cache.write().drain() {
            if queue.is_empty() {
                self.db.delete_global_slot_tx_queue(
                    k,
                    debug_record.as_deref_mut()
                )?;
            }
            else {
                self.db.set_global_slot_tx_queue(
                    k,
                    &queue,
                    debug_record.as_deref_mut()
                )?;
            }
        }
        Ok(())
    }

    // Dequeue a slot transaction from an account.
    pub fn dequeue_slot_tx_from_account(
        &mut self, address: &Address,
    ) -> DbResult<Option<SlotTx>> {
        self.ensure_cached(address, RequireCache::SlotTxQueue, |_acc| {})?;
        let result = self.require_exists(address, false)?
            .dequeue_slot_tx();
        if self.require_exists(address, false)?
            .is_slot_tx_queue_empty()
        {
            self.remove_address_with_ready_slot_tx(address)?;
        }
        Ok(result)
    }

    // Get a copy of the full slot transaction queue from an account.
    pub fn get_account_slot_tx_queue(
        &self, address: &Address,
    ) -> DbResult<SlotTxQueue> {
        self.ensure_cached(address, RequireCache::SlotTxQueue, |acc| {
            acc.map_or(SlotTxQueue::new(), |acc| acc.get_copy_of_slot_tx_queue())
        })
    }

    // Check if a particular account's slot transaction queue is empty.
    pub fn is_account_slot_tx_queue_empty(
        &self, address: &Address,
    ) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::SlotTxQueue, |acc| {
            acc.map_or(true, |acc| acc.is_slot_tx_queue_empty())
        })
    }

    // check whitelist by searching roles and function methods
    // return true: current call can pass
    // return false: current call should be reverted
    pub fn can_call(
        &self, address: &Address,
        caller_address: &Address,
        method_id: &Vec<u8>,
    ) -> DbResult<bool> {
        let queue = self.ensure_cached(address, RequireCache::SlotTxQueue, |acc| {
            acc.map_or(SlotTxQueue::new(), |acc| acc.get_copy_of_slot_tx_queue())
        });
        let mut roles: Vec<Address> = Vec::new();
        let mut mthds: Vec<H256> = Vec::new();
        let mut is_locking: bool = false;
        for tx in queue.unwrap().getqueue().iter() {
            if *tx.clone().blk() {
                is_locking = true;
                if !tx.clone().sigroles().is_empty() {
                    roles.append(&mut tx.clone().sigroles().clone());
                }
                if !tx.clone().sigmethods().is_empty() {
                    mthds.append(&mut tx.clone().sigmethods().clone());
                }
            }
        }
        if is_locking {
            if roles.clone().is_empty() {
                Ok(false)
            } else {
                if let Some(_) = roles.clone().iter().find(|&x| x == caller_address) {
                    for i in mthds.clone().iter() {
                        let method: [u8; 32] = i.to_fixed_bytes();
                        if method_id[0..4] == method[0..4] {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }else{
                    Ok(false)
                }
            }
        } else {
            Ok(true)
        }
    }
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}
