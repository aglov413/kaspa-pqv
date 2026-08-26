//! An SLH-DSA vault: one key, one script, one address.

use anyhow::{Context, Result};
use kaspa_addresses::{Address, Prefix};
use kaspa_txscript::pay_to_script_hash_script;
use slh_script::witness::BlobPlan;
use slh_script::{build_vault_script, PublicKey};

use crate::keygen::{keypair_from_xi, Keypair};

/// Outputs a vault spend commits to: destination plus change.
///
/// Kaspa script has no loops, so the binding digest is unrolled to one exact
/// output count and a different count is a different script and therefore a
/// different address. It is a property of the vault, not a spend-time choice.
///
/// Change returns to the vault's own address, which is possible here and was
/// not under LMS — a stateful vault has to send change to the *next* leaf,
/// because the current one is burned.
pub const CANONICAL_OUTPUT_COUNT: usize = 2;

/// A vault, identified by its SLH-DSA public key.
#[derive(Clone, Debug)]
pub struct SlhVault {
    pub public_key: PublicKey,
    /// How the signature is cut into witness blobs.
    ///
    /// Part of the address: the redeem script contains one slice sequence per
    /// blob, so changing this changes the script hash. Frozen at
    /// [`BlobPlan::default`] and pinned by the derivation vector.
    pub plan: BlobPlan,
}

impl SlhVault {
    /// Build a vault and its signing key from a derived seed.
    ///
    /// The secret is returned separately and should be held only for as long as
    /// a signature takes. Unlike LMS there is no state attached to it, so
    /// dropping and re-deriving it is free.
    pub fn from_xi(xi: &[u8; 32]) -> Result<(Self, Keypair)> {
        let keypair = keypair_from_xi(xi)?;
        Ok((Self { public_key: keypair.public, plan: BlobPlan::default() }, keypair))
    }

    /// The redeem script.
    ///
    /// Reconstructs the binding digest from introspection and requires an
    /// SLH-DSA signature over it, so the signature commits to this
    /// transaction's outpoint and outputs. The spender chooses nothing the
    /// digest does not cover.
    pub fn redeem_script(&self) -> Result<Vec<u8>> {
        self.redeem_script_for_shape(CANONICAL_OUTPUT_COUNT)
    }

    /// The redeem script for a non-canonical output count. A different count is
    /// a different address, so this is a vault-creation decision.
    pub fn redeem_script_for_shape(&self, output_count: usize) -> Result<Vec<u8>> {
        Ok(build_vault_script(&self.public_key, &self.plan, output_count)
            .context("emitting the vault script")?
            .script)
    }

    /// The vault's P2SH address.
    ///
    /// Indistinguishable on-chain from any other pay-to-script-hash address;
    /// the "this is a vault" marker lives in the wallet's records, not in the
    /// address.
    pub fn address(&self, prefix: Prefix) -> Result<Address> {
        let spk = pay_to_script_hash_script(&self.redeem_script()?);
        kaspa_txscript::extract_script_pub_key_address(&spk, prefix)
            .map_err(|e| anyhow::anyhow!("address extraction failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vault_has_exactly_one_address() {
        let (vault, _) = SlhVault::from_xi(&[0x21; 32]).unwrap();
        let a = vault.address(Prefix::Testnet).unwrap();
        let b = vault.address(Prefix::Testnet).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.prefix, Prefix::Testnet);
    }

    /// Everything the address depends on, asserted to actually change it.
    /// Each of these silently moving an address is a way to lose coins.
    #[test]
    fn the_address_depends_on_the_key_the_shape_and_the_blob_plan() {
        let (vault, _) = SlhVault::from_xi(&[0x21; 32]).unwrap();
        let base = vault.redeem_script().unwrap();

        let (other, _) = SlhVault::from_xi(&[0x22; 32]).unwrap();
        assert_ne!(other.redeem_script().unwrap(), base, "key must change the script");

        assert_ne!(
            vault.redeem_script_for_shape(3).unwrap(),
            base,
            "output count must change the script"
        );

        let repacked = SlhVault { plan: BlobPlan::new(5).unwrap(), ..vault.clone() };
        assert_ne!(
            repacked.redeem_script().unwrap(),
            base,
            "the blob plan is part of the address and must change the script"
        );
    }

    /// Mainnet and testnet addresses differ only by prefix, so a mistyped
    /// network sends coins somewhere unrecoverable rather than failing.
    #[test]
    fn network_prefix_is_carried_through() {
        let (vault, _) = SlhVault::from_xi(&[0x21; 32]).unwrap();
        let tn = vault.address(Prefix::Testnet).unwrap();
        let mn = vault.address(Prefix::Mainnet).unwrap();
        assert_ne!(tn.to_string(), mn.to_string());
        assert_eq!(tn.payload, mn.payload, "same script, different prefix");
    }
}
