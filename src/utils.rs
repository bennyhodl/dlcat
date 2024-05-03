use crate::cat_bs::{
    compute_signature_from_components, enforce_payout, get_sigmsg_components, grind_transaction,
    GrindField, TxCommitmentSpec,
};
use crate::dlcat::build_taproot_leafs;
use anyhow::anyhow;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::rand::rngs::OsRng;
use dlc::secp256k1_zkp::{KeyPair, Message, Secp256k1, SecretKey};
use dlc_messages::contract_msgs::{ContractDescriptor, ContractOutcome, EnumeratedContractDescriptor};
use dlc_messages::oracle_msgs::{
    EnumEventDescriptor, EventDescriptor, OracleAnnouncement, OracleAttestation, OracleEvent,
};
use lightning::util::ser::Writeable;
use log::debug;
use secp256kfun::marker::{EvenY, NonZero, Public};
use secp256kfun::{Point, G};

pub fn create_dummy_announcement() -> (OracleAnnouncement, OracleAttestation) {
    let secp = Secp256k1::new();
    let key = KeyPair::new(&secp, &mut OsRng);
    let oracle_nonce_key = SecretKey::new(&mut OsRng);
    let (oracle_nonce_pubkey, _) = oracle_nonce_key.x_only_public_key(&secp);
    let event_descriptor = EventDescriptor::EnumEvent(EnumEventDescriptor {
        outcomes: vec!["Yes".to_string(), "No".to_string()],
    });
    let oracle_event = OracleEvent {
        oracle_nonces: vec![oracle_nonce_pubkey],
        event_id: "dummy".to_string(),
        event_maturity_epoch: 0,
        event_descriptor,
    };
    oracle_event.validate().unwrap();

    // create signature
    let mut data = Vec::new();
    oracle_event.write(&mut data).unwrap();
    let msg = Message::from_hashed_data::<sha256::Hash>(&data);
    let announcement_signature = secp.sign_schnorr_no_aux_rand(&msg, &key);

    let ann = OracleAnnouncement {
        oracle_event,
        oracle_public_key: key.x_only_public_key().0,
        announcement_signature,
    };
    ann.validate(&secp).unwrap();

    let outcome = "Yes".to_string();
    let msg = Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes());

    let sig = dlc::secp_utils::schnorrsig_sign_with_nonce(
        &secp,
        &msg,
        &key,
        &oracle_nonce_key.secret_bytes(),
    );

    let att = OracleAttestation {
        oracle_public_key: key.x_only_public_key().0,
        signatures: vec![sig],
        outcomes: vec!["Yes".to_string()],
    };

    (ann, att)
}

pub fn one_bit_contract_descriptor() -> ContractDescriptor {
    let yes = ContractOutcome {
        outcome: "Yes".into(),
        offer_payout: 100_000
    };

    let no = ContractOutcome {
        outcome: "No".to_string(),
        offer_payout: 100_000
    };

    let enum_descriptor = EnumeratedContractDescriptor {
        payouts: vec![yes, no]
    };

    ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor)
}

pub(crate) fn create_spending_tx(
    outpoint: OutPoint,
    prev_output: TxOut,
    payout_spk: ScriptBuf,
    // outcomes: ContractDescriptor,
) -> anyhow::Result<Transaction> {
    let mut vault_txin = TxIn {
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
        input: vec![vault_txin.clone()],
        output: vec![output.clone()],
    };

    let tx_commitment_spec = TxCommitmentSpec {
        prev_sciptpubkeys: false,
        prev_amounts: false,
        outputs: false,
        ..Default::default()
    };

    let enforce_payout_spk = enforce_payout(output.script_pubkey.clone(), output.value);

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
        debug!(
            "pushing component <0x{}> into the witness",
            hex::encode(component)
        );
        vault_txin.witness.push(component.as_slice());
    }
    let computed_signature =
        compute_signature_from_components(&contract_components.signature_components)?;

    let mut amount_buffer = Vec::new();
    prev_output.value.consensus_encode(&mut amount_buffer)?;
    vault_txin.witness.push(amount_buffer.as_slice());
    let mut scriptpubkey_buffer = Vec::new();
    output
        .script_pubkey
        .consensus_encode(&mut scriptpubkey_buffer)?;
    vault_txin.witness.push(scriptpubkey_buffer.as_slice());

    let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
    vault_txin.witness.push(mangled_signature);

    vault_txin.witness.push(enforce_payout_spk.clone().to_bytes());

    // let spend_info = build_taproot_leafs(outcomes, create_nums_key()); todo use this later, for now no DLC part

    let secp = Secp256k1::new();
    let builder = TaprootBuilder::new()
        .add_leaf(0, enforce_payout_spk.clone())
        .unwrap()
        .finalize(&secp, create_nums_key())
        .unwrap();

    vault_txin.witness.push(
        builder
            .control_block(&(enforce_payout_spk.clone(), LeafVersion::TapScript))
            .expect("control block should work")
            .serialize(),
    );
    txn.input.first_mut().unwrap().witness = vault_txin.witness.clone();

    Ok(txn)
}

pub fn create_address(payout_spk: ScriptBuf, amount: u64) -> Address {
    let enforce_payout_spk = enforce_payout(payout_spk, amount - 10_000);

    let secp = Secp256k1::new();
    let builder = TaprootBuilder::new()
        .add_leaf(0, enforce_payout_spk)
        .unwrap()
        .finalize(&secp, create_nums_key())
        .unwrap();

    Address::p2tr_tweaked(builder.output_key(), Network::Signet)
}

pub fn create_nums_key() -> XOnlyPublicKey {
    // hash G into a NUMS point
    let hash = sha256::Hash::hash(G.to_bytes_uncompressed().as_slice());
    let point: Point<EvenY, Public, NonZero> = Point::from_xonly_bytes(hash.into_32()).unwrap();
    XOnlyPublicKey::from_slice(point.to_xonly_bytes().as_slice()).unwrap()
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bitcoin::consensus::serialize;
    use super::*;

    #[test]
    fn test_create_address() {
        let bitcoind_address = Address::from_str("tb1qe65apqqe3zq7qzaw45zjr4d7fenqdymhr3gums").unwrap();

        let contract_address = create_address(bitcoind_address.payload.script_pubkey(), 100_000);
        println!("{}", contract_address);

        let outpoint = OutPoint::from_str("e6396705587c869865c364028742bba129bc3d9c32309d818c382e75004b806a:0").unwrap();
        let output = TxOut {
            script_pubkey: contract_address.payload.script_pubkey(),
            value: 100_000,
        };
        let spending_tx = create_spending_tx(outpoint,output, bitcoind_address.payload.script_pubkey()).unwrap();

        println!("{}", hex::encode(serialize(&spending_tx).to_vec()));

    }
}
