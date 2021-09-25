// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;

#[cfg(test)]
mod test_treap;

mod account_cache;
mod garbage_collector;
mod nonce_pool;
mod transaction_pool_inner;

extern crate rand;

pub use self::impls::TreapMap;
use crate::{
    block_data_manager::BlockDataManager,
    consensus::BestInformation,
    machine::Machine,
    parameters::block::DEFAULT_TARGET_BLOCK_GAS_LIMIT,
    statedb::{Result as StateDbResult, StateDb},
    storage::{Result as StorageResult, StateIndex, StorageManagerTrait},
    verification::VerificationConfig,
};
use account_cache::AccountCache;
use cfx_types::{Address, H256, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Lock, Meter, MeterTimer,
    RwLockExtensions,
};
use parking_lot::{Mutex, MutexGuard, RwLock};
use primitives::{Account, SignedTransaction, TransactionWithSignature};
use std::{
    cmp::{max, min},
    collections::hash_map::HashMap,
    mem,
    ops::DerefMut,
    sync::Arc,
};
use transaction_pool_inner::TransactionPoolInner;

/////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use primitives::{Transaction, Action, SlotTx, SlotTxQueue};
/* Signal and Slots end */
/////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref TX_POOL_DEFERRED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_deferred_txs");
    static ref TX_POOL_UNPACKED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_unpacked_txs");
    static ref TX_POOL_READY_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_ready_accounts");
    static ref INSERT_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_tps");
    static ref INSERT_TXS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_tps");
    static ref INSERT_TXS_SUCCESS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_success_tps");
    static ref INSERT_TXS_FAILURE_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_failure_tps");
    static ref TX_POOL_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::insert_new_tx");
    static ref TX_POOL_VERIFY_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::verify");
    static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::get_state");
    static ref INSERT_TXS_QUOTA_LOCK: Lock =
        Lock::register("txpool_insert_txs_quota_lock");
    static ref INSERT_TXS_ENQUEUE_LOCK: Lock =
        Lock::register("txpool_insert_txs_enqueue_lock");
    static ref PACK_TRANSACTION_LOCK: Lock =
        Lock::register("txpool_pack_transactions");
    static ref NOTIFY_BEST_INFO_LOCK: Lock =
        Lock::register("txpool_notify_best_info");
    static ref NOTIFY_MODIFIED_LOCK: Lock =
        Lock::register("txpool_notify_modified_info");
}

// FIXME: obviously the max tx gas limit follows the max block gas limit.
// FIXME: and we can scale it by some factor which matches the expiry condition
// FIXME: (according to the formular).
pub const DEFAULT_MAX_TRANSACTION_GAS_LIMIT: u64 = 100_000_000;

pub struct TxPoolConfig {
    pub capacity: usize,
    pub min_tx_price: u64,
    pub max_tx_gas: u64,
    pub tx_weight_scaling: u64,
    pub tx_weight_exp: u8,
    pub target_block_gas_limit: u64,
}

impl MallocSizeOf for TxPoolConfig {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        TxPoolConfig {
            capacity: 500_000,
            min_tx_price: 1,
            max_tx_gas: DEFAULT_MAX_TRANSACTION_GAS_LIMIT,
            // TODO: Set a proper default scaling since tx pool uses u128 as
            // weight.
            tx_weight_scaling: 1,
            tx_weight_exp: 1,
            target_block_gas_limit: DEFAULT_TARGET_BLOCK_GAS_LIMIT,
        }
    }
}

pub struct TransactionPool {
    config: TxPoolConfig,
    verification_config: VerificationConfig,
    inner: RwLock<TransactionPoolInner>,
    to_propagate_trans: Arc<RwLock<HashMap<H256, Arc<SignedTransaction>>>>,
    pub data_man: Arc<BlockDataManager>,
    best_executed_state: Mutex<Arc<StateDb>>,
    consensus_best_info: Mutex<Arc<BestInformation>>,
    set_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    recycle_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // As the stateDb here is best_executed instead of the newest,
    // added this vector to keep track of packed slot tx to avoid duplications
    packed_slot_tx: RwLock<Vec<SlotTx>>,
    // Local cacheing of slot tx queue.
    // This is set after global slot tx queue is drained in consensus executor.
    slot_tx_map: RwLock<HashMap<Address,SlotTxQueue>>,
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
    machine: Arc<Machine>,
}

impl MallocSizeOf for TransactionPool {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let inner_size = self.inner.read().size_of(ops);
        let to_propagate_trans_size =
            self.to_propagate_trans.read().size_of(ops);
        let consensus_best_info_size =
            self.consensus_best_info.lock().size_of(ops);
        let set_tx_requests_size = self.set_tx_requests.lock().size_of(ops);
        let recycle_tx_requests_size =
            self.recycle_tx_requests.lock().size_of(ops);
        self.config.size_of(ops)
            + inner_size
            + to_propagate_trans_size
            + self.data_man.size_of(ops)
            + consensus_best_info_size
            + set_tx_requests_size
            + recycle_tx_requests_size
        // Does not count size_of machine or packed slot tx list
    }
}

pub type SharedTransactionPool = Arc<TransactionPool>;

impl TransactionPool {
    pub fn new(
        config: TxPoolConfig, verification_config: VerificationConfig,
        data_man: Arc<BlockDataManager>, machine: Arc<Machine>,
    ) -> Self
    {
        let genesis_hash = data_man.true_genesis.hash();
        let inner = TransactionPoolInner::new(
            config.capacity,
            config.tx_weight_scaling,
            config.tx_weight_exp,
        );
        TransactionPool {
            config,
            verification_config,
            inner: RwLock::new(inner),
            to_propagate_trans: Arc::new(RwLock::new(HashMap::new())),
            data_man: data_man.clone(),
            best_executed_state: Mutex::new(Arc::new(StateDb::new(
                data_man
                    .storage_manager
                    .get_state_no_commit(
                        StateIndex::new_for_readonly(
                            &genesis_hash,
                            &data_man.true_genesis_state_root(),
                        ),
                        /* try_open = */ false,
                    )
                    // Safe because we don't expect any error at program start.
                    .expect(&concat!(file!(), ":", line!(), ":", column!()))
                    // Safe because true genesis state is available at program
                    // start.
                    .expect(&concat!(file!(), ":", line!(), ":", column!())),
            ))),
            consensus_best_info: Mutex::new(Arc::new(Default::default())),
            set_tx_requests: Mutex::new(Default::default()),
            recycle_tx_requests: Mutex::new(Default::default()),
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            packed_slot_tx:  RwLock::new(Vec::new()),
            slot_tx_map: RwLock::new(HashMap::new()),
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
            machine,
        }
    }

    pub fn machine(&self) -> Arc<Machine> { self.machine.clone() }

    pub fn get_transaction(
        &self, tx_hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        self.inner.read().get(tx_hash)
    }

    pub fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        self.inner.read().check_tx_packed_in_deferred_pool(tx_hash)
    }

    pub fn get_local_account_info(&self, address: &Address) -> (U256, U256) {
        self.inner
            .read()
            .get_local_nonce_and_balance(address)
            .unwrap_or((0.into(), 0.into()))
    }

    pub fn get_state_account_info(
        &self, address: &Address,
    ) -> StateDbResult<(U256, U256)> {
        let mut account_cache = self.get_best_state_account_cache();
        self.inner
            .read()
            .get_nonce_and_balance_from_storage(address, &mut account_cache)
    }

    /// Try to insert `transactions` into transaction pool.
    ///
    /// If some tx is already in our tx_cache, it will be ignored and will not
    /// be added to returned `passed_transactions`. If some tx invalid or
    /// cannot be inserted to the tx pool, it will be included in the returned
    /// `failure` and will not be propagated.
    pub fn insert_new_transactions(
        &self, mut transactions: Vec<TransactionWithSignature>,
    ) -> (Vec<Arc<SignedTransaction>>, HashMap<H256, String>) {
        INSERT_TPS.mark(1);
        INSERT_TXS_TPS.mark(transactions.len());
        let _timer = MeterTimer::time_func(TX_POOL_INSERT_TIMER.as_ref());

        let mut passed_transactions = Vec::new();
        let mut failure = HashMap::new();

        // filter out invalid transactions.
        let mut index = 0;
        while let Some(tx) = transactions.get(index) {
            match self.verify_transaction_tx_pool(
                tx,
                /* basic_check = */ true,
                &self.consensus_best_info.lock(),
            ) {
                Ok(_) => index += 1,
                Err(e) => {
                    let removed = transactions.swap_remove(index);
                    debug!("failed to insert tx into pool (validation failed), hash = {:?}, error = {:?}", removed.hash, e);
                    failure.insert(removed.hash, e);
                }
            }
        }

        // ensure the pool has enough quota to insert new transactions.
        let quota = self
            .inner
            .write_with_metric(&INSERT_TXS_QUOTA_LOCK)
            .remaining_quota();
        if quota < transactions.len() {
            for tx in transactions.split_off(quota) {
                trace!("failed to insert tx into pool (quota not enough), hash = {:?}", tx.hash);
                failure.insert(tx.hash, "txpool is full".into());
            }
        }

        if transactions.is_empty() {
            INSERT_TXS_SUCCESS_TPS.mark(passed_transactions.len());
            INSERT_TXS_FAILURE_TPS.mark(failure.len());
            return (passed_transactions, failure);
        }

        // Recover public key and insert into pool with readiness check.
        // Note, the workload of recovering public key is very heavy, especially
        // in case of high TPS (e.g. > 8000). So, it's better to recover public
        // key after basic verification.
        match self.data_man.recover_unsigned_tx(&transactions) {
            Ok(signed_trans) => {
                let mut account_cache = self.get_best_state_account_cache();
                let mut inner =
                    self.inner.write_with_metric(&INSERT_TXS_ENQUEUE_LOCK);
                let mut to_prop = self.to_propagate_trans.write();

                for tx in signed_trans {
                    if let Err(e) = self.add_transaction_with_readiness_check(
                        &mut *inner,
                        &mut account_cache,
                        tx.clone(),
                        false,
                        false,
                    ) {
                        debug!(
                            "tx {:?} fails to be inserted to pool, err={:?}",
                            &tx.hash, e
                        );
                        failure.insert(tx.hash(), e);
                        continue;
                    }
                    passed_transactions.push(tx.clone());
                    if !to_prop.contains_key(&tx.hash) {
                        to_prop.insert(tx.hash, tx);
                    }
                }
            }
            Err(e) => {
                for tx in transactions {
                    failure.insert(tx.hash(), format!("{:?}", e).into());
                }
            }
        }

        TX_POOL_DEFERRED_GAUGE.update(self.total_deferred());
        TX_POOL_UNPACKED_GAUGE.update(self.total_unpacked());
        TX_POOL_READY_GAUGE.update(self.total_ready_accounts());

        INSERT_TXS_SUCCESS_TPS.mark(passed_transactions.len());
        INSERT_TXS_FAILURE_TPS.mark(failure.len());

        (passed_transactions, failure)
    }

    /// verify transactions based on the rules that have nothing to do with
    /// readiness
    fn verify_transaction_tx_pool(
        &self, transaction: &TransactionWithSignature, basic_check: bool,
        current_best_info: &MutexGuard<Arc<BestInformation>>,
    ) -> Result<(), String>
    {
        let _timer = MeterTimer::time_func(TX_POOL_VERIFY_TIMER.as_ref());
        let (chain_id, best_height) = {
            (
                current_best_info.best_chain_id(),
                current_best_info.best_epoch_number,
            )
        };

        if basic_check {
            if let Err(e) = self
                .verification_config
                .verify_transaction_common(transaction, chain_id)
            {
                warn!("Transaction {:?} discarded due to not passing basic verification.", transaction.hash());
                return Err(format!("{:?}", e));
            }
        }

        // If it is zero, it might be possible that it is not initialized
        // TODO: figure out when we should active txpool.
        // TODO: Ideally txpool should only be initialized after Normal phase.
        if best_height == 0 {
            warn!("verify transaction while best info isn't initialized");
        } else {
            if VerificationConfig::check_transaction_epoch_bound(
                transaction,
                best_height,
                self.verification_config.transaction_epoch_bound,
            ) < 0
            {
                // Check the epoch height is in bound. Because this is such a
                // loose bound, we can check it here as if it
                // will not change at all during its life time.
                warn!(
                    "Transaction discarded due to epoch height out of the bound: \
                    best height {} tx epoch height {}",
                    best_height, transaction.epoch_height);
                return Err(format!(
                    "transaction epoch height {} is out side the range of the current \
                    pivot height ({}) bound, only {} drift allowed!",
                    transaction.epoch_height, best_height,
                    self.verification_config.transaction_epoch_bound));
            }
        }

        // check transaction gas limit
        if transaction.gas > self.config.max_tx_gas.into() {
            warn!(
                "Transaction discarded due to above gas limit: {} > {}",
                transaction.gas, self.config.max_tx_gas
            );
            return Err(format!(
                "transaction gas {} exceeds the maximum value {}",
                transaction.gas, self.config.max_tx_gas
            ));
        }

        // check transaction gas price
        if transaction.gas_price < self.config.min_tx_price.into() {
            trace!("Transaction {} discarded due to below minimal gas price: price {}", transaction.hash(), transaction.gas_price);
            return Err(format!(
                "transaction gas price {} less than the minimum value {}",
                transaction.gas_price, self.config.min_tx_price
            ));
        }

        Ok(())
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn add_transaction_with_readiness_check(
        &self, inner: &mut TransactionPoolInner,
        account_cache: &mut AccountCache, transaction: Arc<SignedTransaction>,
        packed: bool, force: bool,
    ) -> Result<(), String>
    {
        inner.insert_transaction_with_readiness_check(
            account_cache,
            transaction,
            packed,
            force,
        )
    }

    pub fn get_to_be_propagated_transactions(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        let mut to_prop = self.to_propagate_trans.write();
        let mut res = HashMap::new();
        mem::swap(&mut *to_prop, &mut res);
        res
    }

    pub fn set_to_be_propagated_transactions(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        let mut to_prop = self.to_propagate_trans.write();
        to_prop.extend(transactions);
    }

    pub fn remove_to_be_propagated_transactions(&self, tx_hash: &H256) {
        self.to_propagate_trans.write().remove(tx_hash);
    }

    // If a tx is failed executed due to invalid nonce or if its enclosing block
    // becomes orphan due to era transition. This function should be invoked
    // to recycle it
    pub fn recycle_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        if transactions.is_empty() {
            // Fast return. Also used to for bench mode.
            return;
        }

        let mut recycle_req_buffer = self.recycle_tx_requests.lock();
        for tx in transactions {
            recycle_req_buffer.push(tx);
        }
    }

    pub fn set_tx_packed(&self, transactions: &Vec<Arc<SignedTransaction>>) {
        if transactions.is_empty() {
            // Fast return. Also used to for bench mode.
            return;
        }
        let mut tx_req_buffer = self.set_tx_requests.lock();
        for tx in transactions {
            tx_req_buffer.push(tx.clone());
        }
    }

    pub fn pack_transactions<'a>(
        &self, num_txs: usize, block_gas_limit: U256, block_size_limit: usize,
        mut best_epoch_height: u64, slot_tx_address_list: Option<Vec<Address>>,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut inner = self.inner.write_with_metric(&PACK_TRANSACTION_LOCK);
        best_epoch_height += 1;
        let transaction_epoch_bound =
            self.verification_config.transaction_epoch_bound;
        let height_lower_bound = if best_epoch_height > transaction_epoch_bound
        {
            best_epoch_height - transaction_epoch_bound
        } else {
            0
        };
        let height_upper_bound = best_epoch_height + transaction_epoch_bound;
        inner.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
            height_lower_bound,
            height_upper_bound,
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            slot_tx_address_list,
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
        )
    }

    pub fn notify_modified_accounts(
        &self, accounts_from_execution: Vec<Account>,
    ) {
        let mut inner = self.inner.write_with_metric(&NOTIFY_MODIFIED_LOCK);
        inner.notify_modified_accounts(accounts_from_execution)
    }

    pub fn clear_tx_pool(&self) {
        let mut inner = self.inner.write();
        inner.clear()
    }

    pub fn total_deferred(&self) -> usize {
        let inner = self.inner.read();
        inner.total_deferred()
    }

    pub fn total_ready_accounts(&self) -> usize {
        let inner = self.inner.read();
        inner.total_ready_accounts()
    }

    pub fn total_received(&self) -> usize {
        let inner = self.inner.read();
        inner.total_received()
    }

    pub fn total_unpacked(&self) -> usize {
        let inner = self.inner.read();
        inner.total_unpacked()
    }

    /// stats retrieves the length of ready and deferred pool.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let inner = self.inner.read();
        (
            inner.total_ready_accounts(),
            inner.total_deferred(),
            inner.total_received(),
            inner.total_unpacked(),
        )
    }

    /// content retrieves the ready and deferred transactions.
    pub fn content(
        &self,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let inner = self.inner.read();
        inner.content()
    }

    pub fn notify_new_best_info(
        &self, best_info: Arc<BestInformation>,
    ) -> StateDbResult<()> {
        let mut set_tx_buffer = self.set_tx_requests.lock();
        let mut recycle_tx_buffer = self.recycle_tx_requests.lock();
        let mut consensus_best_info = self.consensus_best_info.lock();
        *consensus_best_info = best_info;

        let mut account_cache = self.get_best_state_account_cache();
        let mut inner = self.inner.write_with_metric(&NOTIFY_BEST_INFO_LOCK);
        let inner = inner.deref_mut();

        while let Some(tx) = set_tx_buffer.pop() {
            self.add_transaction_with_readiness_check(
                inner,
                &mut account_cache,
                tx,
                true,
                false,
            )
            .ok();
        }

        while let Some(tx) = recycle_tx_buffer.pop() {
            debug!(
                "should not trigger recycle transaction, nonce = {}, sender = {:?}, \
                account nonce = {}, hash = {:?} .",
                &tx.nonce, &tx.sender,
                &account_cache.get_account_mut(&tx.sender)?
                    .map_or(0.into(), |x| x.nonce), tx.hash);
            if let Err(e) = self.verify_transaction_tx_pool(
                &tx,
                /* basic_check = */ false,
                &consensus_best_info,
            ) {
                warn!(
                    "Recycled transaction {:?} discarded due to not passing verification {}.",
                    tx.hash(), e
                );
            }
            self.add_transaction_with_readiness_check(
                inner,
                &mut account_cache,
                tx,
                false,
                true,
            )
            .ok();
        }

        Ok(())
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // Stupid hard coded constants!
    const TX_TO_SLOT_TX_RATIO: usize = 5;
    const TX_TO_SLOT_TX_GAS_RATIO: usize = 3;
    const TX_TO_SLOT_TX_SIZE_RATIO: usize = 3;

    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////

    pub fn get_best_info_with_packed_transactions(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> (Arc<BestInformation>, U256, Vec<Arc<SignedTransaction>>)
    {
        let consensus_best_info = self.consensus_best_info.lock();

        let parent_block_gas_limit = self
            .data_man
            .block_by_hash(
                &consensus_best_info.best_block_hash,
                /* update_cache = */ true,
            )
            // The parent block must exists.
            .expect(&concat!(file!(), ":", line!(), ":", column!()))
            .block_header
            .gas_limit()
            .clone();

        let gas_limit_divisor = self.machine.params().gas_limit_bound_divisor;
        let min_gas_limit = self.machine.params().min_gas_limit;
        assert!(parent_block_gas_limit >= min_gas_limit);
        let gas_lower = max(
            parent_block_gas_limit - parent_block_gas_limit / gas_limit_divisor
                + 1,
            min_gas_limit,
        );
        let gas_upper = parent_block_gas_limit
            + parent_block_gas_limit / gas_limit_divisor
            - 1;

        let target_gas_limit = self.config.target_block_gas_limit.into();
        let self_gas_limit = min(max(target_gas_limit, gas_lower), gas_upper);

        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */
        // Get the slot transaction ready list from best executed state.
        let storage = (&*self.best_executed_state.lock()).clone();
        let slot_tx_address_list : Option<Vec<Address>> = match storage
            .get_addresses_with_ready_slot_tx()
            .expect("Db error when pulling ready list??") {
                Some(l) => Some(l.get_all()),
                None => None,
            };

        // Pack regular transactions.
        let transactions_from_pool = self.pack_transactions(
            num_txs,
            self_gas_limit.clone(),
            block_size_limit.clone(),
            consensus_best_info.best_epoch_number,
            slot_tx_address_list.clone(),
        );

        // This is where slot transactions are packed into the transaction bunch.
        // This is not even close to an optimal implementation. We don't calculate the gas usage
        // of the slot transactions. Instead, we just enforce that the number of slot transactions
        // to be 0.25 times the number of regular transactions. This is pretty stupid.

        // Calculate average gas price from regular transactions
        let mut d: u64 = 0;
        let mut n: u64 = 0;
        for t in &transactions_from_pool {
            n = n + t.gas_price.low_u64();
            d = d + 1;
        }
        let mut gas_price_average = 0;
        if d != 0 {
            gas_price_average = n/d;
        }

        // Create a pool of slot transactions. The gas price for each one is also set.
        let slot_tx_limit: usize;
        if transactions_from_pool.len() < Self::TX_TO_SLOT_TX_RATIO {
            slot_tx_limit = 1;
        }else{
            slot_tx_limit = transactions_from_pool.len() / Self::TX_TO_SLOT_TX_RATIO;
        }

        let slot_tx_pool = self.get_list_of_slot_tx(
            slot_tx_limit,
            self_gas_limit.clone(),
            block_size_limit.clone(),
            slot_tx_address_list,
            U256::from(gas_price_average)
        );

        // /////////////////////////////////////////////////////////
        // // Test purposes...
        // // Inserts an empty slot tx to be packed into the block. Trying to see if the tests still pass.
        // let slot_info = SlotInfo::new(
        //     &Address::zero(), &Vec::new(), &Address::zero(), &U256::zero(), &U256::zero(), &U256::zero(), &U256::zero(),
        // );
        // let slot = Slot::new(&slot_info);
        // let slot_tx = SlotTx::new(&slot, &0, &Vec::new());

        // slot_tx_pool.push(
        //     Arc::new(
        //         Transaction::create_signed_tx_with_slot_tx(
        //             Transaction {
        //                 nonce: U256::zero(),
        //                 gas_price: U256::zero(),
        //                 gas: U256::zero(),
        //                 action: Action::Create,
        //                 value: U256::zero(),
        //                 storage_limit: U256::zero(),
        //                 epoch_height: 0,
        //                 chain_id: 0,
        //                 data: Vec::new(),
        //                 slot_tx: Some(slot_tx),
        //             }
        //         )
        //     )
        // );
        /////////////////////////////////////////////////////////

        /* Signal and Slots end */
        //////////////////////////////////////////////////////////////////////

        let transactions = [
            additional_transactions.as_slice(),
            transactions_from_pool.as_slice(),
            //////////////////////////////////////////////////////////////////////
            /* Signal and Slots begin */
            slot_tx_pool.as_slice(),
            /* Signal and Slots end */
            //////////////////////////////////////////////////////////////////////
        ]
        .concat();

        (consensus_best_info.clone(), self_gas_limit, transactions)
    }

    pub fn set_best_executed_epoch(
        &self, best_executed_epoch: StateIndex,
    ) -> StorageResult<()> {
        let best_executed_state = Arc::new(StateDb::new(
            self.data_man
                .storage_manager
                .get_state_no_commit(
                    best_executed_epoch,
                    /* try_open = */ false,
                )?
                // Safe because the state is guaranteed to be available.
                .unwrap(),
        ));
        *self.best_executed_state.lock() = best_executed_state;
        //////////////////////////////////////////////////////////////////////
        /* Signal and Slots begin */
        // clear packed slot tx list every time epoch is updated
        *self.packed_slot_tx.write() = Vec::new();
        *self.slot_tx_map.write() = HashMap::new();
        /* Signal and Slots end */
        /////////////////////////////////////////////////////////////////////

        Ok(())
    }

    fn get_best_state_account_cache(&self) -> AccountCache {
        let _timer = MeterTimer::time_func(TX_POOL_GET_STATE_TIMER.as_ref());
        AccountCache::new((&*self.best_executed_state.lock()).clone())
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    pub fn update_slot_tx_map(&self, addr: Address, queue: SlotTxQueue) {
        let mut test = self.slot_tx_map.write();
        test.insert(addr, queue);
    }

    pub fn is_packed(&self, tx: &SlotTx) -> bool{
        let packed_slot_tx_buffer = self.packed_slot_tx.read().clone();
        // do not queue duplicated transaction
        for packed_slot_tx in &packed_slot_tx_buffer {
            if packed_slot_tx.is_duplicated(tx) {
                // already packed, skip
                return true;
            }
        }
        false
    }

    pub fn set_packed(&self, tx: &SlotTx) {
        self.packed_slot_tx.write().push(tx.clone());
    }

    fn get_list_of_slot_tx(
        &self, num_tx: usize,
        block_gas_limit: U256,
        block_size_limit: usize,
        address_list: Option<Vec<Address>>,
        average_gas_price: U256
    ) -> Vec<Arc<SignedTransaction>> {
        // List of slot transactions packed.
        let mut slot_tx_list: Vec<Arc<SignedTransaction>> = Vec::new();
        let mut cnt: usize = 0;

        if address_list.is_none() {
            return slot_tx_list;
        }

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        for addr in address_list.unwrap() {
            // Check if we are packing too many transactions.
            if cnt == num_tx {
                break;
            }
            // Get the slot tx queue at the addr
            let slot_tx_map = self.slot_tx_map.read();
            let queue =
                match slot_tx_map.get(&addr) {
                    Some(queue) => queue,
                    None => {continue;},
                };
            let size = queue.len();

            // Pack all slot tx that are not packed before.
            for idx in 0..size
            {
                let mut tx = queue.peek(idx).unwrap().clone();
                // skip if gas is not set yet
                if tx.gas().is_zero() {
                    continue;
                }

                // Set gas price.
                tx.calculate_and_set_gas_price(&average_gas_price);

                // Save gas limit.
                let tx_gas_limit = tx.gas_limit().clone();

                // Create the signed tx.
                let signed_tx = Transaction::create_signed_tx_with_slot_tx(
                    Transaction {
                        nonce: U256::zero(),
                        gas_price: U256::zero(),
                        gas: U256::zero(),
                        action: Action::SlotTx,
                        value: U256::zero(),
                        storage_limit: U256::zero(),
                        epoch_height: 0,
                        chain_id: 0,
                        data: Vec::new(),
                        slot_tx: Some(tx.clone()),
                    }
                );

                // Establish the limits for packing.
                let tx_size = signed_tx.rlp_size();
                let eff_block_gas_limit = block_gas_limit/Self::TX_TO_SLOT_TX_GAS_RATIO;
                let eff_block_size_limit = block_size_limit/Self::TX_TO_SLOT_TX_SIZE_RATIO;

                // See if we can pack, if not, skip.
                if eff_block_gas_limit - total_tx_gas_limit < tx_gas_limit
                    || eff_block_size_limit - total_tx_size < tx_size
                {
                    continue;
                }

                // Pack it.
                slot_tx_list.push(
                    Arc::new(signed_tx)
                );

                total_tx_gas_limit = total_tx_gas_limit + tx_gas_limit;
                total_tx_size = total_tx_size + tx_size;
                cnt = cnt + 1;
            }

        }
        slot_tx_list
    }

    /* Signal and Slots end */
    /////////////////////////////////////////////////////////////////////
}

// TODO: add unit test for get_list_of_slot_tx
