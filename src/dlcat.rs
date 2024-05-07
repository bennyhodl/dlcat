use crate::op_cat::{create_cat_spending_tx, op_cat_dlc_payout};
use crate::op_ctv::calc_ctv_hash;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NOP4};
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    ScriptBuf,
};
use dlc::get_adaptor_point_from_oracle_info;
use dlc::secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey};
use dlc::OracleInfo;
use dlc_messages::contract_msgs::ContractDescriptor;

pub fn build_cat_taproot_leafs(
    outcome: ContractDescriptor,
    key: XOnlyPublicKey,
    oracle_infos: &[OracleInfo],
) -> TaprootSpendInfo {
    let secp = Secp256k1::new();

    let mut builder = TaprootBuilder::new();

    match outcome {
        ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor) => {
            // todo order better by common occurrence
            for (index, payout) in enum_descriptor.payouts.iter().enumerate() {
                let depth = (index / 2) as u8;
                let msg = Message::from_hashed_data::<dlc::secp256k1_zkp::hashes::sha256::Hash>(
                    payout.outcome.as_bytes(),
                );
                // builder = builder.add_leaf(depth, script).unwrap();
            }
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(_) => unimplemented!("not yet"),
    }

    builder.finalize(&secp, key).unwrap()
}

pub fn build_ctv_taproot_leafs(
    outcome: ContractDescriptor,
    key: XOnlyPublicKey,
    oracle_infos: &[OracleInfo],
) -> TaprootSpendInfo {
    let secp = Secp256k1::new();

    let mut builder = TaprootBuilder::new();

    match outcome {
        ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor) => {
            // todo order better by common occurrence
            for (index, payout) in enum_descriptor.payouts.iter().enumerate() {
                let depth = (index / 2) as u8;
                let msg = Message::from_hashed_data::<dlc::secp256k1_zkp::hashes::sha256::Hash>(
                    payout.outcome.as_bytes(),
                );
                let adaptor_point =
                    get_adaptor_point_from_oracle_info(&secp, oracle_infos, &[vec![msg]]).unwrap();
                let adaptor_point_bytes: PushBytesBuf =
                    adaptor_point.serialize().try_into().unwrap();

                let mut script = ScriptBuf::new();
                let ctv_hash = calc_ctv_hash(&[]); // todo correct outputs
                script.push_slice(ctv_hash);
                script.push_opcode(OP_NOP4);
                script.push_slice(adaptor_point_bytes);
                script.push_opcode(OP_CHECKSIGVERIFY);

                builder = builder.add_leaf(depth, script).unwrap();
            }
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(_) => unimplemented!("not yet"),
    }

    builder.finalize(&secp, key).unwrap()
}
