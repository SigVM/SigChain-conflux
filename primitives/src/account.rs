// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, hash::KECCAK_EMPTY};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{
    RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper,
};

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */
use crate::signal::SlotTx;
/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

use std::ops::{Deref, DerefMut};

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct DepositInfo {
    /// This is the number of tokens in this deposit.
    pub amount: U256,
    /// This is the timestamp when this deposit happened, measured in the
    /// number of past blocks. It will be used to calculate
    /// the service charge.
    pub deposit_time: u64,
    /// This is the accumulated interest rate when this deposit happened.
    pub accumulated_interest_rate: U256,
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct VoteStakeInfo {
    /// This is the number of tokens should be locked before
    /// `unlock_block_number`.
    pub amount: U256,
    /// This is the timestamp when the vote right will be invalid, measured in
    /// the number of past blocks.
    pub unlock_block_number: u64,
}

#[derive(
    Clone,
    Debug,
    Default,
    RlpDecodableWrapper,
    RlpEncodableWrapper,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
pub struct DepositList(pub Vec<DepositInfo>);

impl Deref for DepositList {
    type Target = Vec<DepositInfo>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for DepositList {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(
    Clone,
    Debug,
    Default,
    RlpDecodableWrapper,
    RlpEncodableWrapper,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
pub struct VoteStakeList(pub Vec<VoteStakeInfo>);

impl Deref for VoteStakeList {
    type Target = Vec<VoteStakeInfo>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for VoteStakeList {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

//////////////////////////////////////////////////////////////////////
/* Signal and Slots begin */

// RLP supported queue. Implemented using a vector.
#[derive(
    Clone,
    Debug,
    Default,
    RlpDecodableWrapper,
    RlpEncodableWrapper,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
pub struct SlotTxQueue {
    list: Vec<SlotTx>,
}

impl SlotTxQueue {
    pub fn new() -> Self {
        let new = SlotTxQueue {
            list: Vec::new(),
        };
        new
    }

    pub fn enqueue(&mut self, slot_tx: SlotTx) {
        self.list.push(slot_tx);
    }

    pub fn dequeue(&mut self) -> Option<SlotTx> {
        if self.list.is_empty() {
            return None;
        }
        Some(self.list.remove(0))
    }

    pub fn peek(&self, idx: usize) -> Option<&SlotTx> {
        if idx < self.list.len() {
            return self.list.get(idx);
        }
        None
    }

    pub fn update(&mut self, idx: usize, updated: SlotTx) -> Option<&SlotTx> {
    if let Some(elem) = self.list.get_mut(idx) {
        *elem = updated;
        return Some(elem);
    }
    None
}

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    RlpDecodableWrapper,
    RlpEncodableWrapper,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
pub struct SlotTxAddressList {
    addresses: Vec<Address>,
}

impl SlotTxAddressList {
    pub fn new() -> Self {
        let new = SlotTxAddressList {
            addresses: Vec::new(),
        };
        new
    }

    pub fn get_list(&self) -> &Vec<Address> {
        &self.addresses
    }

    pub fn add(&mut self, address: &Address) {
        if !self.contains(&address) {
            self.addresses.push(address.clone());
        }
    }

    pub fn append(&mut self, addresses: &Vec<Address>) {
        for address in addresses {
            self.add(&address);
        }
    }

    pub fn merge(&mut self, mut address_list: SlotTxAddressList) {
        self.append(address_list.get_list());
    }

    pub fn contains(&mut self, address: &Address) -> bool {
        self.addresses.contains(address)
    }

    pub fn remove(&mut self, address: &Address) {
        // Will panic if the address doesn't exit
        let index = self.addresses.iter().position(|x| x == address).unwrap();
        self.addresses.remove(index);
    }

    pub fn get_all(self) -> Vec<Address> {
        self.addresses.clone()
    }

    pub fn clear(&mut self) {
        self.addresses.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }
}


/* Signal and Slots end */
//////////////////////////////////////////////////////////////////////

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct CodeInfo {
    pub code: Bytes,
    pub owner: Address,
}

#[derive(
    Clone,
    Debug,
    RlpDecodable,
    RlpEncodable,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Default,
)]
pub struct SponsorInfo {
    /// This is the address of the sponsor for gas cost of the contract.
    pub sponsor_for_gas: Address,
    /// This is the address of the sponsor for collateral of the contract.
    pub sponsor_for_collateral: Address,
    /// This is the upper bound of sponsor gas cost per tx.
    pub sponsor_gas_bound: U256,
    /// This is the amount of tokens sponsor for gas cost to the contract.
    pub sponsor_balance_for_gas: U256,
    /// This is the amount of tokens sponsor for collateral to the contract.
    pub sponsor_balance_for_collateral: U256,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,
    /// This is the number of tokens used in staking.
    pub staking_balance: U256,
    /// This is the number of tokens used as collateral for storage, which will
    /// be returned to balance if the storage is released.
    pub collateral_for_storage: U256,
    /// This is the accumulated interest return.
    pub accumulated_interest_return: U256,
    /// This is the address of the administrator of the contract.
    pub admin: Address,
    /// This is the sponsor information of the contract.
    pub sponsor_info: SponsorInfo,
}

impl Account {
    pub fn new_empty_with_balance(
        address: &Address, balance: &U256, nonce: &U256,
    ) -> Account {
        Self {
            address: *address,
            balance: *balance,
            nonce: *nonce,
            code_hash: KECCAK_EMPTY,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            admin: Address::zero(),
            sponsor_info: Default::default(),
        }
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !(rlp.item_count()? == 6 || rlp.item_count()? == 9) {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let address: Address = rlp.val_at(0)?;
        if address.is_user_account_address() {
            if rlp.item_count()? != 6 {
                return Err(DecoderError::RlpIncorrectListLen);
            }
            Ok(Self {
                address,
                balance: rlp.val_at(1)?,
                nonce: rlp.val_at(2)?,
                code_hash: KECCAK_EMPTY,
                staking_balance: rlp.val_at(3)?,
                collateral_for_storage: rlp.val_at(4)?,
                accumulated_interest_return: rlp.val_at(5)?,
                admin: Address::zero(),
                sponsor_info: Default::default(),
            })
        } else if address.is_contract_address() {
            if rlp.item_count()? != 9 {
                return Err(DecoderError::RlpIncorrectListLen);
            }
            Ok(Self {
                address,
                balance: rlp.val_at(1)?,
                nonce: rlp.val_at(2)?,
                code_hash: rlp.val_at(3)?,
                staking_balance: rlp.val_at(4)?,
                collateral_for_storage: rlp.val_at(5)?,
                accumulated_interest_return: rlp.val_at(6)?,
                admin: rlp.val_at(7)?,
                sponsor_info: rlp.val_at(8)?,
            })
        } else {
            panic!("other types of address are not supported yet.");
        }
    }
}

impl Encodable for Account {
    fn rlp_append(&self, stream: &mut RlpStream) {
        if self.address.is_user_account_address() {
            stream
                .begin_list(6)
                .append(&self.address)
                .append(&self.balance)
                .append(&self.nonce)
                .append(&self.staking_balance)
                .append(&self.collateral_for_storage)
                .append(&self.accumulated_interest_return);
        } else if self.address.is_contract_address() {
            stream
                .begin_list(9)
                .append(&self.address)
                .append(&self.balance)
                .append(&self.nonce)
                .append(&self.code_hash)
                .append(&self.staking_balance)
                .append(&self.collateral_for_storage)
                .append(&self.accumulated_interest_return)
                .append(&self.admin)
                .append(&self.sponsor_info);
        } else {
            panic!("other types of address are not supported yet.");
        }
    }
}
