#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::vec::Vec;
use codec::{Encode, Decode};
use sp_core::U256;

#[cfg(feature = "enable_serde")]
use serde::{Serialize, Deserialize};

use xcm::v0::{NetworkId};
use cumulus_primitives::{ParaId};
use xcm_adapter::{ PHAXCurrencyId as XCurrencyId };

#[derive(Encode, Decode)]
pub struct Transfer<AccountId, Balance> {
	pub dest: AccountId,
	pub amount: Balance,
	pub sequence: u64,
}

#[derive(Encode, Decode)]
pub struct TransferData<AccountId, Balance> {
	pub data: Transfer<AccountId, Balance>,
	pub signature: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct TransferToken<AccountId, Balance> {
	pub token_id: Vec<u8>,
	pub dest: AccountId,
	pub amount: Balance,
	pub sequence: u64,
}

#[derive(Encode, Decode)]
pub struct TransferTokenData<AccountId, Balance> {
	pub data: TransferToken<AccountId, Balance>,
	pub signature: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct TransferXToken<AccountId, Balance> {
	pub x_currency_id: XCurrencyId,
	pub para_id: ParaId,
	pub dest_network: NetworkId,
	pub dest: AccountId,
	pub amount: Balance,
	pub sequence: u64,
}

#[derive(Encode, Decode)]
pub struct TransferXTokenData<AccountId, Balance> {
	pub data: TransferXToken<AccountId, Balance>,
	pub signature: Vec<u8>,
}

#[derive(Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "enable_serde", derive(Serialize, Deserialize))]
pub enum WorkerMessagePayload {
	Heartbeat {
		block_num: u32,
		claim_online: bool,
		claim_compute: bool,
	},
}

#[derive(Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "enable_serde", derive(Serialize, Deserialize))]
pub struct WorkerMessage {
	pub payload: WorkerMessagePayload,
	pub sequence: u64,
}

#[derive(Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "enable_serde", derive(Serialize, Deserialize))]
pub struct SignedWorkerMessage {
	pub data: WorkerMessage,
	pub signature: Vec<u8>,
}

pub trait SignedDataType<T> {
	fn raw_data(&self) -> Vec<u8>;
	fn signature(&self) -> T;
}

impl<AccountId: Encode, Balance: Encode> SignedDataType<Vec<u8>> for TransferData<AccountId, Balance> {
	fn raw_data(&self) -> Vec<u8> {
		Encode::encode(&self.data)
	}
	fn signature(&self) -> Vec<u8> {
		self.signature.clone()
	}
}

impl<AccountId: Encode, Balance: Encode> SignedDataType<Vec<u8>> for TransferTokenData<AccountId, Balance> {
	fn raw_data(&self) -> Vec<u8> {
		Encode::encode(&self.data)
	}

	fn signature(&self) -> Vec<u8> {
		self.signature.clone()
	}
}

impl<AccountId: Encode, Balance: Encode> SignedDataType<Vec<u8>> for TransferXTokenData<AccountId, Balance> {
	fn raw_data(&self) -> Vec<u8> {
		Encode::encode(&self.data)
	}

	fn signature(&self) -> Vec<u8> {
		self.signature.clone()
	}
}

impl SignedDataType<Vec<u8>> for SignedWorkerMessage {
	fn raw_data(&self) -> Vec<u8> {
		Encode::encode(&self.data)
	}
	fn signature(&self) -> Vec<u8> {
		self.signature.clone()
	}
}

// Types used in storage

#[derive(Encode, Decode, PartialEq, Eq, Debug)]
pub enum WorkerStateEnum<BlockNumber> {
	Empty,
	Free,
	Gatekeeper,
	MiningPending,
	Mining(BlockNumber),
	MiningStopping,
}

impl<BlockNumber> Default for WorkerStateEnum<BlockNumber> {
	fn default() -> Self {
		WorkerStateEnum::Empty
	}
}

#[derive(Encode, Decode, Default)]
pub struct WorkerInfo<BlockNumber> {
	// identity
	pub machine_id: Vec<u8>,
	pub pubkey: Vec<u8>,
	pub last_updated: u64,
	// mining
	pub state: WorkerStateEnum<BlockNumber>,
	// preformance
	pub score: Option<Score>,
}

#[derive(Encode, Decode, Default)]
pub struct StashInfo<AccountId: Default> {
	pub controller: AccountId,
	pub payout_prefs: PayoutPrefs::<AccountId>,
}

#[derive(Encode, Decode, Default)]
pub struct PayoutPrefs<AccountId: Default> {
	pub commission: u32,
	pub target: AccountId,
}

#[derive(Encode, Decode, Default, Clone)]
pub struct Score {
	pub overall_score: u32,
	pub features: Vec<u32>
}

type MachineId = [u8; 16];
type WorkerPublicKey = [u8; 33];
#[derive(Encode, Decode)]
pub struct PRuntimeInfo {
	pub version: u8,
	pub machine_id: MachineId,
	pub pubkey: WorkerPublicKey,
	pub features: Vec<u32>
}

#[derive(Encode, Decode, Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockRewardInfo {
	pub seed: U256,
	pub online_target: U256,
	pub compute_target: U256,
}

#[derive(Encode, Decode, Debug, Default)]
pub struct RoundInfo<BlockNumber> {
	pub round: u32,
	pub start_block: BlockNumber,
}

#[derive(Encode, Decode, Debug, Default, Clone, PartialEq, Eq)]
pub struct RoundStats {
	pub round: u32,
	pub online_workers: u32,
	pub compute_workers: u32,
	/// The targeted online reward in fraction (base: 100_000)
	pub frac_target_online_reward: u32,
	pub total_power: u32,
}

#[derive(Encode, Decode, Debug, Default, Clone, PartialEq, Eq)]
pub struct MinerStatsDelta {
	pub num_worker: i32,
	pub num_power: i32,
}
