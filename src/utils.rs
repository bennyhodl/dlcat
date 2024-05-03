use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::rand::rngs::OsRng;
use dlc::secp256k1_zkp::{KeyPair, Message, Secp256k1, SecretKey};
use dlc_messages::oracle_msgs::{
    EnumEventDescriptor, EventDescriptor, OracleAnnouncement, OracleAttestation, OracleEvent,
};
use lightning::util::ser::Writeable;

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
