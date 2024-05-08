use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Prevouts;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::Secp256k1;
use dlc::OracleInfo;
use dlc_messages::contract_msgs::{ContractDescriptor, ContractInfo};
use dlc_messages::oracle_msgs::OracleAttestation;
use lightning::util::ser::Writeable;

use crate::build_ctv_taproot_leafs;
use crate::utils::signatures_to_secret;

pub fn calc_ctv_hash(outputs: &[TxOut]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.extend(2_i32.to_le_bytes()); // version
    buffer.extend(0_i32.to_le_bytes()); // locktime
    buffer.extend(1_u32.to_le_bytes()); // inupts len

    let seq = sha256::Hash::hash(&Sequence::default().0.to_le_bytes());
    buffer.extend(seq.into_32()); // sequences

    let outputs_len = outputs.len() as u32;
    buffer.extend(outputs_len.to_le_bytes()); // outputs len

    let mut output_bytes: Vec<u8> = Vec::new();
    for o in outputs {
        o.consensus_encode(&mut output_bytes).unwrap();
    }
    buffer.extend(sha256::Hash::hash(&output_bytes).into_32()); // outputs hash

    buffer.extend(0_u32.to_le_bytes()); // inputs index

    let hash = sha256::Hash::hash(&buffer);
    hash.into_32()
}

pub(crate) fn create_ctv_spending_tx(
    outpoint: OutPoint,
    previous_output: TxOut,
    output: TxOut,
    oracle_attestation: OracleAttestation,
    contract_descriptor: ContractDescriptor,
    oracle_info: OracleInfo
) -> anyhow::Result<Transaction> {
    let secp = Secp256k1::new();

    let mut collateral_txin = TxIn {
        previous_output: outpoint.clone(),
        ..Default::default()
    };

    let txn = Transaction {
        lock_time: LockTime::ZERO,
        version: 2,
        input: vec![collateral_txin.clone()],
        output: vec![output.clone()],
    };

    // let priv_key = oracle_attestation; // get private key from oracle attestation
    let secret_key = signatures_to_secret(&[oracle_attestation.signatures]);
    // Rust-bitcoin get something to signature
    // Could be better handled
    // todo calculate correct txn signature hash

    // pass the signature in the witness

    let builder = build_ctv_taproot_leafs(
        contract_descriptor,
        oracle_attestation.oracle_public_key,
        &[oracle_info],
    );

    let mut sighash_cache = SighashCache::new(&txn);
    // Pass the script from builder for outcome.
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&previous_output]),
            TapLeafHash::from_script(
                ScriptBuf::new().as_script(), /*going to be script for given outcome*/
                LeafVersion::TapScript,
            ),
            TapSighashType::Default,
        )
        .unwrap();

    let sighash_message =
        dlc::secp256k1_zkp::Message::from_slice(&sighash.to_byte_array()).unwrap();

    let oracle_signature =
        secp.sign_schnorr_no_aux_rand(&sighash_message, &secret_key.keypair(&secp));

    collateral_txin.witness.push(oracle_signature.encode());
    // Get outcome with Calc_ctv_hash script for a singular outcome.

    let outcome = ScriptBuf::new(); // todo calculate corresponding script for oracle outcome
    collateral_txin.witness.push(
        builder
            .control_block(&(outcome, LeafVersion::TapScript))
            .expect("control block should work")
            .serialize(),
    );

    Ok(Transaction {
        lock_time: LockTime::ZERO,
        version: 2,
        input: vec![collateral_txin],
        output: vec![output],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::create_dummy_announcement;
    use bitcoin::consensus::serialize;
    use bitcoin::opcodes::all::OP_NOP4;
    use bitcoin::{Address, Network, ScriptBuf};
    use std::str::FromStr;

    #[test]
    fn test_create_address() {
        let bitcoind_address =
            Address::from_str("tb1qe65apqqe3zq7qzaw45zjr4d7fenqdymhr3gums").unwrap();

        let value = 100_000;
        let out = TxOut {
            script_pubkey: bitcoind_address.payload.script_pubkey(),
            value,
        };
        let mut contract_address = ScriptBuf::new();
        let ctv = calc_ctv_hash(&[out.clone()]);
        contract_address.push_slice(ctv);
        contract_address.push_opcode(OP_NOP4);
        let contract_address = Address::p2wsh(contract_address.as_script(), Network::Signet);
        println!("{}", contract_address);

        let outpoint = OutPoint::from_str(
            "8adfd002860b1205228d3d9d7c169f2d982fad655f4921f3d67bf00e9b134f25:0",
        )
        .unwrap();
        let attestation = create_dummy_announcement().1;
        let spending_tx = create_ctv_spending_tx(outpoint, out, attestation).unwrap();

        println!("{}", hex::encode(serialize(&spending_tx).to_vec()));
    }
}
