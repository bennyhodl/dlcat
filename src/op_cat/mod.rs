pub mod sigops;
use crate::build_cat_taproot_leafs;
use crate::utils::create_nums_key;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{
    OP_CAT, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROT, OP_SHA256, OP_SWAP,
    OP_TOALTSTACK,
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut};
use dlc::OracleInfo;
use dlc_messages::contract_msgs::ContractDescriptor;
use sigops::{
    compute_signature_from_components, get_sigmsg_components, grind_transaction, GrindField,
    BIP0340_CHALLENGE_TAG, G_X, TAPSIGHASH_TAG,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxCommitmentSpec {
    pub(crate) epoch: bool,
    pub(crate) control: bool,
    pub(crate) version: bool,
    pub(crate) lock_time: bool,
    pub(crate) prevouts: bool,
    pub(crate) prev_amounts: bool,
    pub(crate) prev_sciptpubkeys: bool,
    pub(crate) sequences: bool,
    pub(crate) outputs: bool,
    pub(crate) spend_type: bool,
    pub(crate) annex: bool,
    pub(crate) single_output: bool,
    pub(crate) scriptpath: bool,
}

impl Default for TxCommitmentSpec {
    fn default() -> Self {
        Self {
            epoch: true,
            control: true,
            version: true,
            lock_time: true,
            prevouts: true,
            prev_amounts: true,
            prev_sciptpubkeys: true,
            sequences: true,
            outputs: true,
            spend_type: true,
            annex: true,
            single_output: true,
            scriptpath: true,
        }
    }
}

pub(crate) fn create_cat_spending_tx(
    outpoint: OutPoint,
    prev_output: TxOut,
    payout_spk: ScriptBuf,
    outcomes: ContractDescriptor,
    oracle_infos: &[OracleInfo],
) -> anyhow::Result<Transaction> {
    let mut collateral_txin = TxIn {
        previous_output: outpoint,
        ..Default::default()
    };
    let output = TxOut {
        script_pubkey: payout_spk,
        value: prev_output.value - 10_000, // minus 10k sats for fees
    };

    let txn = Transaction {
        lock_time: LockTime::ZERO,
        version: 2,
        input: vec![collateral_txin.clone()],
        output: vec![output.clone()],
    };

    let tx_commitment_spec = TxCommitmentSpec {
        outputs: false,
        ..Default::default()
    };

    let enforce_payout_spk = op_cat_dlc_payout(&[output.clone()]);

    let leaf_hash = TapLeafHash::from_script(&enforce_payout_spk, LeafVersion::TapScript);
    let contract_components =
        grind_transaction(txn, GrindField::LockTime, &[prev_output.clone()], leaf_hash)?;

    let mut txn = contract_components.transaction;
    let witness_components = get_sigmsg_components(
        &tx_commitment_spec,
        &txn,
        0,
        &[prev_output.clone()],
        None,
        leaf_hash,
        TapSighashType::Default,
    )?;

    for component in witness_components.iter() {
        log::debug!(
            "pushing component <0x{}> into the witness",
            hex::encode(component)
        );
        collateral_txin.witness.push(component.as_slice());
    }
    let computed_signature =
        compute_signature_from_components(&contract_components.signature_components)?;

    let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
    collateral_txin.witness.push(mangled_signature);

    // Build the taproot tree of outcomes
    let spend_info = build_cat_taproot_leafs(
        outcomes,
        output.script_pubkey.clone(),
        create_nums_key(),
        oracle_infos,
    ); // todo use this later, for now no DLC part

    // let secp = Secp256k1::new();
    // let builder = TaprootBuilder::new()
    //     .add_leaf(0, enforce_payout_spk.clone())
    //     .unwrap()
    //     .finalize(&secp, create_nums_key())
    //     .unwrap();

    collateral_txin
        .witness
        .push(enforce_payout_spk.clone().to_bytes());

    collateral_txin.witness.push(
        spend_info
            .control_block(&(enforce_payout_spk.clone(), LeafVersion::TapScript))
            .expect("control block should work")
            .serialize(),
    );
    txn.input.first_mut().unwrap().witness = collateral_txin.witness.clone();

    Ok(txn)
}

pub(crate) struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

pub(crate) fn op_cat_dlc_payout(outputs: &[TxOut]) -> ScriptBuf {
    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys and pre_amounts,
    // followed by the output amount, then the script pubkey,
    // followed by the fee amount, then the fee-paying scriptpubkey
    // and finally the mangled signature

    let mut buffer = Vec::new();
    for o in outputs {
        o.consensus_encode(&mut buffer).unwrap();
    }
    let output_hash_bytes = sha256::Hash::hash(&buffer);

    builder = builder
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_slice(output_hash_bytes.into_32())
        .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT); // epoch
    builder = add_signature_construction_and_check(builder);
    builder.into_script()
}

/// Assumes that the builder has the sigmsg on the stack, and the pre-computed mangled signature on top of the alt stack.
/// will construct the tagged hash and the signature and do the verification
/// Call this after you've CAT'd the epoch onto the sigmsg
pub(crate) fn add_signature_construction_and_check(builder: Builder) -> Builder {
    builder
        .push_slice(*TAPSIGHASH_TAG) // push tag
        .push_opcode(OP_SHA256) // hash tag
        .push_opcode(OP_DUP) // dup hash
        .push_opcode(OP_ROT) // move the sighash to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256) // tagged hash of the sighash
        .push_slice(*BIP0340_CHALLENGE_TAG) // push tag
        .push_opcode(OP_SHA256)
        .push_opcode(OP_DUP)
        .push_opcode(OP_ROT) // bring challenge to the top of the stack
        .push_slice(*G_X) // G is used for the pubkey and K
        .push_opcode(OP_DUP)
        .push_opcode(OP_DUP)
        .push_opcode(OP_TOALTSTACK) // we'll need a copy of G later to be our R value in the signature
        .push_opcode(OP_ROT) // bring the challenge to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT) // cat the two tags, R, P, and M values together
        .push_opcode(OP_SHA256) // hash the whole thing to get the s value for the signature
        .push_opcode(OP_FROMALTSTACK) // bring G back from the alt stack to use as the R value in the signature
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT) // cat the R value with the s value for a complete signature
        .push_opcode(OP_FROMALTSTACK) // grab the pre-computed signature minus the last byte from the alt stack
        .push_opcode(OP_DUP) // we'll need a second copy later to do the actual signature verification
        .push_slice([0x00u8]) // add the last byte of the signature, which should match what we computed. NOTE ⚠️: push_int(0) will not work here because it will push OP_FALSE, but we want an actual 0 byte
        .push_opcode(OP_CAT)
        .push_opcode(OP_ROT) // bring the script-computed signature to the top of the stack
        .push_opcode(OP_EQUALVERIFY) // check that the script-computed and pre-computed signatures match
        .push_int(0x01) // we need the last byte of the signature to be 0x01 because our k value is 1 (because K is G)
        .push_opcode(OP_CAT)
        .push_slice(*G_X) // push G again. TODO: DUP this from before and stick it in the alt stack or something
        .push_opcode(OP_CHECKSIG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{create_address, one_bit_contract_descriptor};
    use bitcoin::consensus::serialize;
    use bitcoin::Address;
    use std::str::FromStr;

    #[test]
    fn test_cat_create_address() {
        let bitcoind_address =
            Address::from_str("tb1qe65apqqe3zq7qzaw45zjr4d7fenqdymhr3gums").unwrap();

        let contract_address = create_address(bitcoind_address.payload.script_pubkey(), 100_000);
        println!("{}", contract_address);

        let outpoint = OutPoint::from_str(
            "2efc5d63872c24a2f1e2f67b7f89e2ba33e8d218242964e07fbaf210970225b1:1",
        )
        .unwrap();
        let prev_output = TxOut {
            script_pubkey: contract_address.payload.script_pubkey(),
            value: 100_000,
        };
        let spending_tx = create_cat_spending_tx(
            outpoint,
            prev_output,
            bitcoind_address.payload.script_pubkey(),
            one_bit_contract_descriptor(),
            &[],
        )
        .unwrap();

        println!("{}", hex::encode(serialize(&spending_tx).to_vec()));
    }
}
