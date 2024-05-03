use bitcoin::{taproot::{TaprootBuilder, TaprootSpendInfo}, ScriptBuf};
use dlc_messages::contract_msgs::ContractDescriptor;
use dlc::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};

#[allow(dead_code)]
fn build_taproot_leafs(outcome: ContractDescriptor, key: XOnlyPublicKey) -> TaprootSpendInfo {
    let secp = Secp256k1::new();
    let mut builder = TaprootBuilder::new();
    match outcome {
        ContractDescriptor::EnumeratedContractDescriptor(enum_descriptor) => {
            for (index, _) in enum_descriptor.payouts.iter().enumerate() {
                let depth = (index / 2) as u8;
                // let script = <cat stuff>
                builder = builder.add_leaf(depth, ScriptBuf::new()).unwrap();
            }
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(_numeric_descriptor) => unimplemented!("not yet")
    }

    builder.finalize(&secp, key).unwrap()
}
