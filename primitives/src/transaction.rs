// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, hash::keccak};
use cfx_types::{Address, BigEndianHash, H160, H256, U256};
use keylib::{
    self, public_to_address, recover, verify_public, Public, Secret, Signature,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::{self, Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use std::{error, fmt, ops::Deref};
use unexpected::OutOfBounds;

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use crate::{SlotTx};
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

/// Fake address for unsigned transactions.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// Shorter id for transactions in compact blocks
// TODO should be u48
pub type TxShortId = u64;

pub type TxPropagateId = u32;

// FIXME: Most errors here are bounded for TransactionPool and intended for rpc,
// FIXME: however these are unused, they are not errors for transaction itself.
// FIXME: Transaction verification and consensus related error can be separated.
#[derive(Debug, PartialEq, Clone)]
/// Errors concerning transaction processing.
pub enum TransactionError {
    /// Transaction is already imported to the queue
    AlreadyImported,
    /// Chain id in the transaction doesn't match the chain id of the network.
    ChainIdMismatch { expected: u64, got: u64 },
    /// Epoch height out of bound.
    EpochHeightOutOfBound {
        block_height: u64,
        set: u64,
        transaction_epoch_bound: u64,
    },
    /// The gas paid for transaction is lower than base gas.
    NotEnoughBaseGas {
        /// Absolute minimum gas required.
        required: U256,
        /// Gas provided.
        got: U256,
    },
    /// Transaction is not valid anymore (state already has higher nonce)
    Stale,
    /// Transaction has too low fee
    /// (there is already a transaction with the same sender-nonce but higher
    /// gas price)
    TooCheapToReplace,
    /// Transaction was not imported to the queue because limit has been
    /// reached.
    LimitReached,
    /// Transaction's gas price is below threshold.
    InsufficientGasPrice {
        /// Minimal expected gas price
        minimal: U256,
        /// Transaction gas price
        got: U256,
    },
    /// Transaction's gas is below currently set minimal gas requirement.
    InsufficientGas {
        /// Minimal expected gas
        minimal: U256,
        /// Transaction gas
        got: U256,
    },
    /// Sender doesn't have enough funds to pay for this transaction
    InsufficientBalance {
        /// Senders balance
        balance: U256,
        /// Transaction cost
        cost: U256,
    },
    /// Transactions gas is higher then current gas limit
    GasLimitExceeded {
        /// Current gas limit
        limit: U256,
        /// Declared transaction gas
        got: U256,
    },
    /// Transaction's gas limit (aka gas) is invalid.
    InvalidGasLimit(OutOfBounds<U256>),
    /// Signature error
    InvalidSignature(String),
    /// Transaction too big
    TooBig,
    /// Invalid RLP encoding
    InvalidRlp(String),
}

impl From<keylib::Error> for TransactionError {
    fn from(err: keylib::Error) -> Self {
        TransactionError::InvalidSignature(format!("{}", err))
    }
}

impl From<rlp::DecoderError> for TransactionError {
    fn from(err: rlp::DecoderError) -> Self {
        TransactionError::InvalidRlp(format!("{}", err))
    }
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TransactionError::*;
        let msg = match *self {
            AlreadyImported => "Already imported".into(),
            ChainIdMismatch { expected, got } => {
                format!("Chain id mismatch, expected {}, got {}", expected, got)
            }
            EpochHeightOutOfBound {
                block_height,
                set,
                transaction_epoch_bound,
            } => format!(
                "EpochHeight out of bound:\
                 block_height {}, transaction epoch_height {}, transaction_epoch_bound {}",
                block_height, set, transaction_epoch_bound
            ),
            NotEnoughBaseGas { got, required } => format!(
                "Transaction gas {} less than intrinsic gas {}",
                got, required
            ),
            Stale => "No longer valid".into(),
            TooCheapToReplace => "Gas price too low to replace".into(),
            LimitReached => "Transaction limit reached".into(),
            InsufficientGasPrice { minimal, got } => format!(
                "Insufficient gas price. Min={}, Given={}",
                minimal, got
            ),
            InsufficientGas { minimal, got } => {
                format!("Insufficient gas. Min={}, Given={}", minimal, got)
            }
            InsufficientBalance { balance, cost } => format!(
                "Insufficient balance for transaction. Balance={}, Cost={}",
                balance, cost
            ),
            GasLimitExceeded { limit, got } => {
                format!("Gas limit exceeded. Limit={}, Given={}", limit, got)
            }
            InvalidGasLimit(ref err) => format!("Invalid gas limit. {}", err),
            InvalidSignature(ref err) => {
                format!("Transaction has invalid signature: {}.", err)
            }
            TooBig => "Transaction too big".into(),
            InvalidRlp(ref err) => {
                format!("Transaction has invalid RLP structure: {}.", err)
            }
        };

        f.write_fmt(format_args!("Transaction error ({})", msg))
    }
}

impl error::Error for TransactionError {
    fn description(&self) -> &str { "Transaction error" }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Create creates new contract.
    Create,
    /// Calls contract at given address.
    /// In the case of a transfer, this is the receiver's address.'
    Call(Address),

    /////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // Don't want to get mixed up with the other actions!
    SlotTx,
    /* Signal and Slots end */
    /////////////////////////////////////////////////////////////////////
}

impl Default for Action {
    fn default() -> Action { Action::Create }
}

impl Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            Ok(Action::Create)
        } else {
            Ok(Action::Call(rlp.as_val()?))
            //TODO: need to decode Action::SlotTx?
        }
    }
}

impl Encodable for Action {
    fn rlp_append(&self, stream: &mut RlpStream) {
        match *self {
            Action::Create => stream.append_internal(&""),
            Action::Call(ref address) => stream.append_internal(address),
            Action::SlotTx => stream.append_internal(&""),
        };
    }
}

/// The parameters needed to determine the chain_id based on epoch_number.
#[derive(Clone, Debug, Eq, RlpEncodable, RlpDecodable, PartialEq)]
pub struct ChainIdParams {
    /// Preconfigured chain_id.
    pub chain_id: u64,
}

impl ChainIdParams {
    /// The function return the chain_id with given parameters
    pub fn get_chain_id(&self, _epoch_number: u64) -> u64 { self.chain_id }
}

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

// This is the hackiest implementation yet. To keep changes to a minimum, we add slot transaction as a
// field in the SignedTransaction struct. This way, a lot of the implementation doesn't have to be
// changed...
// Ideally, we would embody both regular and slot transactions in a trait or an enum, but this would
// require a lot more effort. For research purposes this should do.

/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct Transaction {
    /// Nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Gas paid up front for transaction execution.
    pub gas: U256,
    /// Action, can be either call or contract create.
    pub action: Action,
    /// Transferred value.
    pub value: U256,
    /// Maximum storage increasement in this execution.
    pub storage_limit: U256,
    /// The epoch height of the transaction. A transaction
    /// can only be packed between the epochs of [epoch_height -
    /// TRANSACTION_EPOCH_BOUND, epoch_height + TRANSACTION_EPOCH_BOUND]
    pub epoch_height: u64,
    /// The chain id of the transaction
    pub chain_id: u64,
    /// Transaction data.
    pub data: Bytes,

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // If this is some then this transaction is a slot tx.
    pub slot_tx: Option<SlotTx>,
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? == 9 {
            Ok(Transaction {
                nonce: rlp.val_at(0)?,
                gas_price: rlp.val_at(1)?,
                gas: rlp.val_at(2)?,
                action: rlp.val_at(3)?,
                value: rlp.val_at(4)?,
                storage_limit: rlp.val_at(5)?,
                epoch_height: rlp.val_at(6)?,
                chain_id: rlp.val_at(7)?,
                data: rlp.val_at(8)?,
                slot_tx: None,
            })
        } else {
            Ok(Transaction {
                nonce: rlp.val_at(0)?,
                gas_price: rlp.val_at(1)?,
                gas: rlp.val_at(2)?,
                action: rlp.val_at(3)?,
                value: rlp.val_at(4)?,
                storage_limit: rlp.val_at(5)?,
                epoch_height: rlp.val_at(6)?,
                chain_id: rlp.val_at(7)?,
                data: rlp.val_at(8)?,
                slot_tx: rlp.val_at(9)?,
            })
        }

    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.slot_tx.is_none() {
            s
                .begin_list(9)
                .append(&self.nonce)
                .append(&self.gas_price)
                .append(&self.gas)
                .append(&self.action)
                .append(&self.value)
                .append(&self.storage_limit)
                .append(&self.epoch_height)
                .append(&self.chain_id)
                .append(&self.data);
        } else {
            s
                .begin_list(10)
                .append(&self.nonce)
                .append(&self.gas_price)
                .append(&self.gas)
                .append(&self.action)
                .append(&self.value)
                .append(&self.storage_limit)
                .append(&self.epoch_height)
                .append(&self.chain_id)
                .append(&self.data)
                .append(&self.slot_tx);
        }}
}

impl Transaction {
    pub fn hash(&self) -> H256 {
        let mut s = RlpStream::new();
        s.append(self);
        keccak(s.as_raw())
    }

    pub fn sign(self, secret: &Secret) -> SignedTransaction {
        let sig = ::keylib::sign(secret, &self.hash())
            .expect("data is valid and context has signing capabilities; qed");
        let tx_with_sig = self.with_signature(sig);
        let public = tx_with_sig
            .recover_public()
            .expect("secret is valid so it's recoverable");
        SignedTransaction::new(public, tx_with_sig)
    }

    /// Specify the sender; this won't survive the serialize/deserialize
    /// process, but can be cloned.
    pub fn fake_sign(self, from: Address) -> SignedTransaction {
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: self,
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            }
            .compute_hash(),
            sender: from,
            public: None,
        }
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: Signature) -> TransactionWithSignature {
        TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: self,
                r: sig.r().into(),
                s: sig.s().into(),
                v: sig.v(),
            },
            hash: H256::zero(),
            rlp_size: None,
        }
        .compute_hash()
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    pub fn create_signed_tx_with_slot_tx(self) -> SignedTransaction {
        assert!(self.slot_tx.is_some());
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: self.clone(),
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            }
            .compute_hash(),
            sender: self.slot_tx.unwrap().address().clone(),
            public: None,
        }
    }

    pub fn is_slot_tx(&self) -> bool {
        self.slot_tx.is_some()
    }

    pub fn action(&self) -> Action {
        self.action.clone()
    }

    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}

impl MallocSizeOf for Transaction {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.data.size_of(ops)
    }
}

/// Signed transaction information without verified signature.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    RlpEncodable,
    RlpDecodable,
    Serialize,
    Deserialize,
)]
pub struct TransactionWithSignatureSerializePart {
    /// Plain Transaction.
    pub unsigned: Transaction,
    /// The V field of the signature; helps describe which half of the curve
    /// our point falls in.
    pub v: u8,
    /// The R field of the signature; helps describe the point on the curve.
    pub r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    pub s: U256,
}

impl Deref for TransactionWithSignatureSerializePart {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target { &self.unsigned }
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionWithSignature {
    /// Serialize part.
    pub transaction: TransactionWithSignatureSerializePart,
    /// Hash of the transaction
    #[serde(skip)]
    pub hash: H256,
    /// The transaction size when serialized in rlp
    #[serde(skip)]
    pub rlp_size: Option<usize>,
}

impl Deref for TransactionWithSignature {
    type Target = TransactionWithSignatureSerializePart;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

impl Decodable for TransactionWithSignature {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let hash = keccak(d.as_raw());
        let rlp_size = Some(d.as_raw().len());
        // Check item count of TransactionWithSignatureSerializePart
        if d.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let transaction = d.as_val()?;
        Ok(TransactionWithSignature {
            transaction,
            hash,
            rlp_size,
        })
    }
}

impl Encodable for TransactionWithSignature {
    fn rlp_append(&self, s: &mut RlpStream) { s.append(&self.transaction); }
}

impl TransactionWithSignature {
    pub fn new_unsigned(tx: Transaction) -> Self {
        TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: tx,
                s: 0.into(),
                r: 0.into(),
                v: 0,
            },
            hash: Default::default(),
            rlp_size: None,
        }
    }

    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> TransactionWithSignature {
        let hash = keccak(&*self.rlp_bytes());
        self.hash = hash;
        self
    }

    /// Checks whether signature is empty.
    pub fn is_unsigned(&self) -> bool { self.r.is_zero() && self.s.is_zero() }

    /// Construct a signature object from the sig.
    pub fn signature(&self) -> Signature {
        let r: H256 = BigEndianHash::from_uint(&self.r);
        let s: H256 = BigEndianHash::from_uint(&self.s);
        Signature::from_rsv(&r, &s, self.v)
    }

    /// Checks whether the signature has a low 's' value.
    pub fn check_low_s(&self) -> Result<(), keylib::Error> {
        if !self.signature().is_low_s() {
            Err(keylib::Error::InvalidSignature)
        } else {
            Ok(())
        }
    }

    pub fn hash(&self) -> H256 { self.hash }

    /// Recovers the public key of the sender.
    pub fn recover_public(&self) -> Result<Public, keylib::Error> {
        Ok(recover(&self.signature(), &self.unsigned.hash())?)
    }

    pub fn rlp_size(&self) -> usize {
        self.rlp_size.unwrap_or_else(|| self.rlp_bytes().len())
    }
}

impl MallocSizeOf for TransactionWithSignature {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.unsigned.size_of(ops)
    }
}

/// A signed transaction with successfully recovered `sender`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: TransactionWithSignature,
    pub sender: Address,
    pub public: Option<Public>,
}

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.transaction);
        s.append(&self.sender);
        s.append(&self.public);
    }
}

impl Decodable for SignedTransaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(SignedTransaction {
            transaction: rlp.val_at(0)?,
            sender: rlp.val_at(1)?,
            public: rlp.val_at(2)?,
        })
    }
}

impl Deref for SignedTransaction {
    type Target = TransactionWithSignature;

    fn deref(&self) -> &Self::Target {&self.transaction}
}

impl From<SignedTransaction> for TransactionWithSignature {
    fn from(tx: SignedTransaction) -> Self { tx.transaction }
}

impl SignedTransaction {
    /// Try to verify transaction and recover sender.
    pub fn new(public: Public, transaction: TransactionWithSignature) -> Self {
        if transaction.is_unsigned() {
            SignedTransaction {
                transaction,
                sender: UNSIGNED_SENDER,
                public: None,
            }
        } else {
            let sender = public_to_address(&public);
            SignedTransaction {
                transaction,
                sender,
                public: Some(public),
            }
        }
    }

    pub fn new_unsigned(transaction: TransactionWithSignature) -> Self {
        SignedTransaction {
            transaction,
            sender: UNSIGNED_SENDER,
            public: None,
        }
    }

    pub fn set_public(&mut self, public: Public) {
        self.sender = public_to_address(&public);
        self.public = Some(public);
    }

    /// Returns transaction sender.
    pub fn sender(&self) -> Address { self.sender }

    pub fn nonce(&self) -> U256 { self.transaction.nonce }

    /// Checks if signature is empty.
    pub fn is_unsigned(&self) -> bool { self.transaction.is_unsigned() }

    pub fn hash(&self) -> H256 { self.transaction.hash() }

    pub fn gas(&self) -> &U256 { &self.transaction.gas }

    pub fn gas_price(&self) -> &U256 { &self.transaction.gas_price }

    pub fn gas_limit(&self) -> &U256 { &self.transaction.gas }

    pub fn rlp_size(&self) -> usize { self.transaction.rlp_size() }

    pub fn public(&self) -> &Option<Public> { &self.public }

    pub fn verify_public(&self, skip: bool) -> Result<bool, keylib::Error> {
        if self.public.is_none() {
            return Ok(false);
        }

        if !skip {
            let public = self.public.unwrap();
            Ok(verify_public(
                &public,
                &self.signature(),
                &self.unsigned.hash(),
            )?)
        } else {
            Ok(true)
        }
    }

    //////////////////////////////////////////////////////////////////////
    /* Signal and Slots begin */
    // Get the target address of a CALL action. Return None if the action
    // is CREATE or SLOTTX.
    pub fn call_address(&self) -> Option<Address> {
        match self.transaction.transaction.unsigned.action() {
            Action::Call(address) => Some(address),
            _ => None,
        }
    }

    pub fn is_slot_tx(&self) -> bool {
        // pretty ugly code...
        self.transaction.transaction.unsigned.is_slot_tx()
    }
    /* Signal and Slots end */
    //////////////////////////////////////////////////////////////////////
}

impl MallocSizeOf for SignedTransaction {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.transaction.size_of(ops)
    }
}

// Note: should bypass any signature verification on slot transaction created with
// create_signed_tx_with_slot_tx() or errors will be thrown
#[cfg(test)]
mod tests {
    use rlp::{Rlp, RlpStream, };
    use crate::transaction::{Action, Transaction, };
    use cfx_types::{Address, U256, H256, address_util::AddressUtil};
    use keylib::{
        self, public_to_address, Random, Generator,
    };
    use crate::{SlotTx, SlotInfo, Slot, };
    #[test]
    fn test_encode_decode_normal_transaction() {
        let tx = Transaction {
            nonce: U256::zero(),
            gas_price: U256::one(),
            gas: U256::from(21000),
            action: Action::Create,
            value: U256::from(100),
            storage_limit: U256::zero(),
            epoch_height: 0 as u64,
            chain_id: 10 as u64,
            data: b"".to_vec(),
            slot_tx: None,
        };
        let mut raw = RlpStream::new();
        raw.append(&tx);

        let tx : Transaction = Rlp::new(&raw.as_raw()).as_val().unwrap();
        assert_eq!(tx.nonce, U256::zero());
        assert_eq!(tx.gas_price, U256::one());
        assert!(tx.slot_tx.is_none());
    }

    fn get_slot_tx(gas_sponsor : &Address) -> SlotTx {
        let mut contract_address = gas_sponsor.clone();
        contract_address.set_contract_type_bits();
        let key = vec![0x31u8, 0x32u8, 0x33u8];
        let target_epoch_height : u64 = 0;
        let raw_data = vec![0x01u8, 0x02u8, 0x03u8];
        let method_hash = H256::zero();
        let gas_limit = U256::from(1000);
        let gas_ratio = U256::from(120);
        let slot_info = SlotInfo::new(
            &contract_address,
            &key,
            &method_hash,
            gas_sponsor,
            &gas_limit,
            &gas_ratio,
        );
        let slot = Slot::new(&slot_info);
        let slot_tx = SlotTx::new(
            &slot, &target_epoch_height, &raw_data,
        );
        slot_tx
    }

    #[test]
    fn test_encode_decode_slot_transaction() {
        let keypair = Random.generate().unwrap();
        let address = public_to_address(&keypair.public());
        let slot_tx = get_slot_tx(&address);
        let tx = Transaction {
            nonce: U256::zero(),
            gas_price: U256::one(),
            gas: U256::from(21000),
            action: Action::Create,
            value: U256::from(100),
            storage_limit: U256::zero(),
            epoch_height: 0 as u64,
            chain_id: 10 as u64,
            data: b"".to_vec(),
            slot_tx: Some(slot_tx.clone()),
        };
        let mut raw = RlpStream::new();
        raw.append(&tx);

        let tx : Transaction = Rlp::new(&raw.as_raw()).as_val().unwrap();
        assert_eq!(tx.nonce, U256::zero());
        assert_eq!(tx.gas_price, U256::one());
        assert!(tx.slot_tx.is_some());
        assert_eq!(tx.slot_tx.unwrap(), slot_tx);
    }


    #[test]
    // Note: this test case signs the slot transaction with a valid key pair.
    // This should not happen as slot transactions are not signed,
    // this is only tested for encoding/decoding correctness.
    fn test_recover_public_signed_slot_transaction() {
        let keypair = Random.generate().unwrap();
        let address = public_to_address(&keypair.public());
        let slot_tx = get_slot_tx(&address);
        let t = Transaction {
            action: Action::SlotTx,
            value: U256::from(18),
            data: b"".to_vec(),
            gas: U256::from(100_000),
            gas_price: U256::one(),
            storage_limit: U256::zero(),
            epoch_height: 0,
            chain_id: 0,
            nonce: U256::zero(),
            slot_tx: Some(slot_tx),
        }
        .sign(keypair.secret());
        let sender = t.sender();

        let public_key = t.recover_public().unwrap();
        assert_eq!(public_to_address(&public_key), sender);
    }

    #[test]
    fn test_recover_public_signed_normal_transaction() {
        let keypair = Random.generate().unwrap();
        let t = Transaction {
            action: Action::Create,
            value: U256::from(18),
            data: b"".to_vec(),
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

        let public_key = t.recover_public().unwrap();
        assert_eq!(public_to_address(&public_key), sender);
    }
}
