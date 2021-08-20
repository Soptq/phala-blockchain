use anyhow::Result;
use core::marker::PhantomData;
use log::{error, info};
use std::time::Duration;

use crate::chain_client::fetch_mq_ingress_seq;
use subxt::Signer;

use super::{chain_client::update_signer_nonce, runtimes, PrClient, SrSigner, XtClient};

/// Hold everything needed to sync some egress messages back to the blockchain
pub struct MsgSync<'a> {
    /// Subxt client
    client: &'a XtClient,
    /// pRuntime client
    pr: &'a PrClient,
    /// SR25519 signer with a nonce
    signer: &'a mut SrSigner,
    /// True if the nonce is ever updated from the blockchain during the lifetiem of MsgSync
    nonce_updated: bool,
}

impl<'a> MsgSync<'a> {
    /// Creates a new MsgSync object
    pub fn new(client: &'a XtClient, pr: &'a PrClient, signer: &'a mut SrSigner) -> Self {
        Self {
            client,
            pr,
            signer,
            nonce_updated: false,
        }
    }

    pub async fn maybe_sync_mq_egress(&mut self) -> Result<()> {
        // Send the query
        let messages = self.pr.get_egress_messages(()).await?.decode_messages()?;

        // No pending message. We are done.
        if messages.is_empty() {
            return Ok(());
        }

        self.maybe_update_signer_nonce().await?;

        let period = crate::extra::period();
        if period > 0 {
            let cur_block = crate::get_block_at(self.client, None).await?.0;
            let number = cur_block.block.header.number as u64;
            let phase = number % period;
            crate::extra::set_phase(phase);

            {
                let era = sp_runtime::generic::Era::Mortal(period, phase);
                info!(
                    "update era: block={}, period={}, phase={}, birth={}, death={}",
                    number,
                    period,
                    phase,
                    era.birth(number),
                    era.death(number)
                );
            }
        }

        for (sender, messages) in messages {
            if messages.is_empty() {
                continue;
            }
            let min_seq = fetch_mq_ingress_seq(self.client, sender.clone()).await?;

            for message in messages {
                if message.sequence < min_seq {
                    info!("{} has been submitted. Skipping...", message.sequence);
                    continue;
                }
                let msg_info = format!(
                    "sender={:?} seq={} dest={} nonce={:?}",
                    sender,
                    message.sequence,
                    String::from_utf8_lossy(&message.message.destination.path()[..]),
                    self.signer.nonce()
                );
                info!("Submitting message: {}", msg_info);
                let extrinsic = self
                    .client
                    .create_signed(
                        runtimes::phala_mq::SyncOffchainMessageCall {
                            _runtime: PhantomData,
                            message,
                        },
                        self.signer,
                    )
                    .await;
                self.signer.increment_nonce();
                match extrinsic {
                    Ok(extrinsic) => {
                        let client = self.client.clone();
                        tokio::spawn(async move {
                            const TIMEOUT: u64 = 120;
                            let fut = client.submit_extrinsic(extrinsic);
                            let result =
                                tokio::time::timeout(Duration::from_secs(TIMEOUT), fut).await;
                            match result {
                                Err(_) => {
                                    error!("Submit message timed out: {}", msg_info);
                                }
                                Ok(Err(err)) => {
                                    error!("Error submitting message {}: {:?}", msg_info, err);
                                }
                                Ok(Ok(hash)) => {
                                    info!("Message submited: {} xt-hash={:?}", msg_info, hash);
                                }
                            }
                        });
                    }
                    Err(err) => {
                        panic!("Failed to sign the call: {:?}", err);
                    }
                }
            }
        }
        Ok(())
    }

    /// Updates the nonce if it's not updated.
    ///
    /// The nonce will only be updated once during the lifetime of MsgSync struct.
    async fn maybe_update_signer_nonce(&mut self) -> Result<()> {
        if !self.nonce_updated {
            update_signer_nonce(self.client, self.signer).await?;
            self.nonce_updated = true;
        }
        Ok(())
    }
}
