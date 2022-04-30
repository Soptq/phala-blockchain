use std::collections::BTreeMap;
use std::string::String;

use anyhow::Result;
use parity_scale_codec::{Decode, Encode};
use phala_mq::MessageOrigin;
use std::convert::TryFrom;
use bitcoin::bech32::ToBase32;
use hmac::Mac;
use sp_core::hashing;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

use super::{TransactionError, TransactionResult};
use crate::contracts;
use crate::contracts::{AccountId, NativeContext};

extern crate runtime as chain;

use phala_types::messaging::{P2FACommand};

type Command = P2FACommand;

const DIGITS: usize = 6;
const SKEW: u8 = 1;
const DURATION_SECONDS: u64 = 30;

#[derive(Encode, Decode, Debug, Clone)]
pub enum Status {
    Initialized,
    Verified,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct UserTOTP {
    secret: Vec<u8>,
    status: Status,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct P2FA {
    data: BTreeMap<AccountId, UserTOTP>
}

#[derive(Encode, Decode, Debug)]
pub enum Error {
    // InvalidRequest,
    NoRecord,
    NotAuthorized,
    Unimplemented,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum Request {
    GetBase32Secret { account: AccountId },
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum Response {
    GetBase32Secret { data: String },
    Error(String),
}

impl P2FA {
    pub fn new() -> Self {
        P2FA {
            data: BTreeMap::new(),
        }
    }

    pub fn base32_secret(secret: &Vec<u8>) -> String {
        base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            secret,
        )
    }

    pub fn rand_secret(account: AccountId) -> Vec<u8> {
        let hash_block = hashing::blake2_128(&context.block.block_number.to_be_bytes());
        let hash_account = hashing::blake2_128(&account.to_base32());

        let secret = hash_block ^ hash_account;
        secret
    }

    fn hash<D>(mut digest: D, data: &[u8]) -> Vec<u8>
        where
            D: hmac::Mac,
    {
        digest.update(data);
        digest.finalize().into_bytes().to_vec()
    }

    /// Will sign the given timestamp
    pub fn sign(secret: Vec<u8>, time: u64) -> Vec<u8> {
        Self::hash(
            HmacSha1::new_from_slice(secret.as_ref()).unwrap(),
            (time / DURATION_SECONDS).to_be_bytes().as_ref()
        )
    }

    /// Will generate a token according to the provided timestamp in seconds
    pub fn generate(secret: Vec<u8>, time: u64) -> String {
        let result: &[u8] = &Self::sign(secret, time);
        let offset = (result.last().unwrap() & 15) as usize;
        let result = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!(
            "{1:00$}",
            DIGITS,
            result % (10 as u32).pow(DIGITS as u32)
        )
    }

    /// Will check if token is valid by current time, accounting [skew](struct.TOTP.html#structfield.skew)
    pub fn check(token: &str, secret: Vec<u8>, time: u64) -> bool {
        let basestep = time / DURATION_SECONDS - (SKEW as u64);
        for i in 0..SKEW * 2 + 1 {
            let step_time = (basestep + (i as u64)) * (DURATION_SECONDS as u64);

            if constant_time_eq(Self::generate(secret.clone(), step_time).as_bytes(), token.as_bytes()) {
                return true;
            }
        }
        false
    }
}

impl contracts::NativeContract for P2FA {
    type Cmd = Command;
    type QReq = Request;
    type QResp = Result<Response, Error>;

    fn handle_command(
        &mut self,
        origin: MessageOrigin,
        cmd: Command,
        context: &mut NativeContext,
    ) -> TransactionResult {
        match cmd {
            Command::InitBinding {} => {
                let sender = origin.account()?;
                let initialized_user_totp = UserTOTP {
                    secret: Self::rand_secret(),
                    status: Status::Initialized,
                };
                if let Some(user_totp) = self.data.get_mut(&sender) {
                    *user_totp = initialized_user_totp;
                } else {
                    self.data.insert(
                        sender.clone(),
                        initialized_user_totp,
                    );
                };

                Ok(Default::default())
            }

            Command::VerifyBinding { token: String } => {
                let sender = origin.account()?;

                if let Some(user_totp) = self.data.get_mut(&sender) {
                    if user_totp.status != Status::Initialized {
                        return Err(TransactionError::BadCommand);
                    };

                    if Self::check(token, user_totp.secret.clone(), context.block.now_ms) {
                        user_totp.status = Status::Verified;
                        Ok(Default::default())
                    } else {
                        Err(TransactionError::BadInput)
                    }
                } else {
                    return Err(TransactionError::BadOrigin);
                }

                Ok(Default::default())
            }

            Command::unbind{ token: String } => {
                let sender = origin.account()?;

                if !self.data.contains_key(&sender) {
                    return Err(TransactionError::BadOrigin);
                }

                let user_totp = self.data.get(&sender).ok_or(Error::NoRecord)?;
                if Self::check(token, user_totp.secret.clone(), context.block.now_ms) {
                    self.data.remove(&sender);
                    Ok(Default::default())
                } else {
                    Err(TransactionError::BadInput)
                }

                Ok(Default::default())
            }
        }
    }

    fn handle_query(
        &self,
        origin: Option<&chain::AccountId>,
        req: Request,
        _: &mut contracts::QueryContext,
    ) -> Result<Response, Error> {
        match req {
            Request::GetBase32Secret { account } => {
                if origin != Some(&account) {
                    return Err(Error::NotAuthorized);
                }
                let user_totp = self.data.get(&account).ok_or(Error::NoRecord)?;
                let data = Self::base32_secret(&user_totp.secret.clone());
                Ok(Response::GetBase32Secret { data })
            }
        }
    }

    fn snapshot(&self) -> Self {
        // TODO: this is really heavy, fix it or port me to wasm contract.
        self.clone()
    }
}