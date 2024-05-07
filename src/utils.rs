use crate::op_cat::op_cat_dlc_payout;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Network, ScriptBuf};
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::rand::rngs::OsRng;
use dlc::secp256k1_zkp::{KeyPair, Message, Secp256k1, SecretKey};
use dlc_messages::contract_msgs::{
    ContractDescriptor, ContractOutcome, EnumeratedContractDescriptor,
};
use dlc_messages::oracle_msgs::{
    EnumEventDescriptor, EventDescriptor, OracleAnnouncement, OracleAttestation, OracleEvent,
};
use lightning::util::ser::Writeable;
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
        offer_payout: 100_000,
    };

    let no = ContractOutcome {
        outcome: "No".to_string(),
        offer_payout: 100_000,
    };

    let enum_descriptor = EnumeratedContractDescriptor {
        payouts: vec![yes, no],
    };

    ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor)
}

pub fn create_address(payout_spk: ScriptBuf, amount: u64) -> Address {
    let enforce_payout_spk = op_cat_dlc_payout(payout_spk, amount - 10_000);

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
