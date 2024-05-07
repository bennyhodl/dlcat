use crate::op_cat::sigops::{
    compute_signature_from_components, get_sigmsg_components, grind_transaction, GrindField,
};
use crate::op_cat::{op_cat_dlc_payout, TxCommitmentSpec};
use crate::utils::create_nums_key;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::Secp256k1;
use dlc_messages::oracle_msgs::OracleAttestation;
use log::debug;

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
    output: TxOut,
    oracle_attestation: OracleAttestation,
) -> anyhow::Result<Transaction> {
    let secp = Secp256k1::new();

    let mut collateral_txin = TxIn {
        previous_output: outpoint,
        ..Default::default()
    };

    // let priv_key = oracle_attestation; // get private key from oracle attestation
    //
    // // todo calculate correct txn signature hash
    // let signature = secp.sign_schnorr_no_aux_rand(&[], &priv_key);
    //
    // vault_txin.witness.push(signature);
    //
    // let builder = build_taproot_leafs((), (), &[]);
    //
    // let outcome = (); // todo calculate corresponding script for oracle outcome
    // vault_txin.witness.push(
    //     builder
    //         .control_block(&(outcome, LeafVersion::TapScript))
    //         .expect("control block should work")
    //         .serialize(),
    // );

    let txn = Transaction {
        lock_time: LockTime::ZERO,
        version: 2,
        input: vec![collateral_txin],
        output: vec![output],
    };

    Ok(txn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::create_dummy_announcement;
    use bitcoin::consensus::serialize;
    use bitcoin::opcodes::all::OP_NOP4;
    use bitcoin::{Address, Network};
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
