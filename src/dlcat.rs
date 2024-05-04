use crate::utils::calc_ctv_hash;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NOP4};
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf,
};
use dlc::get_adaptor_point_from_oracle_info;
use dlc::secp256k1_zkp::{Secp256k1, XOnlyPublicKey, Message};
use dlc_messages::contract_msgs::ContractDescriptor;
use dlc::OracleInfo;
use bitcoin_hashes::Hash;

pub fn build_taproot_leafs(outcome: ContractDescriptor, key: XOnlyPublicKey, oracle_infos: &[OracleInfo]) -> TaprootSpendInfo {
    let secp = Secp256k1::new();

    let mut builder = TaprootBuilder::new();
    
    match outcome {
        ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor) => {
            for (index, payout) in enum_descriptor.payouts.iter().enumerate() {
                let depth = (index / 2) as u8;
                let msg = Message::from_hashed_data::<dlc::secp256k1_zkp::hashes::sha256::Hash>(payout.outcome.as_bytes());
                let adaptor_point = get_adaptor_point_from_oracle_info(&secp, oracle_infos, &[vec![msg]]).unwrap();
                let adaptor_point_bytes: PushBytesBuf = adaptor_point.serialize().try_into().unwrap();

                let mut script = ScriptBuf::new();
                let ctv_hash = calc_ctv_hash(&[]); // todo correct outputs
                script.push_slice(ctv_hash);
                script.push_opcode(OP_NOP4);
                script.push_slice(adaptor_point_bytes); //todo calculate this
                script.push_opcode(OP_CHECKSIGVERIFY);

                builder = builder.add_leaf(depth, script).unwrap();
            }
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(_) => unimplemented!("not yet"),
    }

    builder.finalize(&secp, key).unwrap()
}

/// The collateral address for both parties to deposit to.
///
/// If they do not producs the same output key when building
/// the taproot tree, then the contract should not be funded.
#[allow(dead_code)]
fn build_collateral_address(info: TaprootSpendInfo) -> Address {
    let hash_match = info.output_key();
    Address::p2tr_tweaked(hash_match, Network::Regtest)
}

// Get an adaptor point generated using the given oracle information and messages.
// pub fn get_adaptor_point_from_oracle_info<C: Verification>(
//     secp: &Secp256k1<C>,
//     oracle_infos: &[OracleInfo],
//     msgs: &[Vec<Message>],
// ) -> Result<PublicKey, Error> {
//     if oracle_infos.is_empty() || msgs.is_empty() {
//         return Err(Error::InvalidArgument);
//     }
//
//     let mut oracle_sigpoints = Vec::with_capacity(msgs[0].len());
//     for (i, info) in oracle_infos.iter().enumerate() {
//         oracle_sigpoints.push(get_oracle_sig_point(secp, info, &msgs[i])?);
//     }
//     Ok(PublicKey::combine_keys(
//         &oracle_sigpoints.iter().collect::<Vec<_>>(),
//     )?)
// }
