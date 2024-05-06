use anyhow::anyhow;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::opcodes::all::{
    OP_2DUP, OP_CAT, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROT, OP_SHA256,
    OP_SWAP, OP_TOALTSTACK,
};
use bitcoin::script::{Builder, PushBytes, PushBytesBuf};
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::{Annex, TapSighash, TapSighashType};
use bitcoin::taproot::{TapLeafHash, TaprootBuilder};
use bitcoin::{Amount, Script, ScriptBuf, Sequence, Transaction, TxOut};
use lazy_static::lazy_static;
use log::debug;

lazy_static! {
    pub(crate) static ref G_X: [u8; 32] =
        secp256kfun::G.into_point_with_even_y().0.to_xonly_bytes();
    pub(crate) static ref TAPSIGHASH_TAG: [u8; 10] = {
        let mut tag = [0u8; 10];
        let val = "TapSighash".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref BIP0340_CHALLENGE_TAG: [u8; 17] = {
        let mut tag = [0u8; 17];
        let val = "BIP0340/challenge".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref DUST_AMOUNT: [u8; 8] = {
        let mut dust = [0u8; 8];
        let mut buffer = Vec::new();
        let amount: u64 = 546;
        amount.consensus_encode(&mut buffer).unwrap();
        dust.copy_from_slice(&buffer);
        dust
    };
}

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

pub(crate) fn get_sigmsg_components<S: Into<TapLeafHash>>(
    spec: &TxCommitmentSpec,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    annex: Option<Annex>,
    leaf_hash: S,
    sighash_type: TapSighashType,
) -> anyhow::Result<Vec<Vec<u8>>> {
    // all this serialization code was lifted from bitcoin-0.31.1/src/crypto/sighash.rs:597 and
    // then very violently hacked up.

    let mut components = Vec::new();

    let leaf_hash_code_separator = Some((leaf_hash.into(), 0xFFFFFFFFu32));

    let (sighash, anyone_can_pay) = match sighash_type {
        TapSighashType::Default => (TapSighashType::Default, false),
        TapSighashType::All => (TapSighashType::All, false),
        TapSighashType::None => (TapSighashType::None, false),
        TapSighashType::Single => (TapSighashType::Single, false),
        TapSighashType::AllPlusAnyoneCanPay => (TapSighashType::All, true),
        TapSighashType::NonePlusAnyoneCanPay => (TapSighashType::None, true),
        TapSighashType::SinglePlusAnyoneCanPay => (TapSighashType::Single, true),
    };

    if spec.epoch {
        let mut epoch = Vec::new();
        0u8.consensus_encode(&mut epoch)?;
        debug!("epoch: {:?}", hex::encode(&epoch));
        components.push(epoch);
    }

    if spec.control {
        let mut control = Vec::new();
        (sighash_type as u8).consensus_encode(&mut control)?;
        debug!("control: {:?}", hex::encode(&control));
        components.push(control);
    }

    if spec.version {
        let mut version = Vec::new();
        tx.version.consensus_encode(&mut version)?;
        debug!("version: {:?}", hex::encode(&version));
        components.push(version);
    }

    if spec.lock_time {
        let mut lock_time = Vec::new();
        tx.lock_time.consensus_encode(&mut lock_time)?;
        debug!("lock_time: {:?}", hex::encode(&lock_time));
        components.push(lock_time);
    }

    if !anyone_can_pay {
        if spec.prevouts {
            let mut prevouts = Vec::new();
            let mut buffer = Vec::new();
            for prevout in tx.input.iter() {
                prevout
                    .previous_output
                    .consensus_encode(&mut buffer)
                    .unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prevouts).unwrap();
            debug!("prevouts: {:?}", hex::encode(&prevouts));
            components.push(prevouts);
        }

        if spec.prev_amounts {
            let mut prev_amounts = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.value.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_amounts).unwrap();
            debug!("prev_amounts: {:?}", hex::encode(&prev_amounts));
            components.push(prev_amounts);
        }
        if spec.prev_sciptpubkeys {
            let mut prev_sciptpubkeys = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.script_pubkey.consensus_encode(&mut buffer).unwrap();
            }
            debug!("prev_sciptpubkeys buffer: {:?}", hex::encode(&buffer));

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_sciptpubkeys).unwrap();
            debug!("prev_sciptpubkeys: {:?}", hex::encode(&prev_sciptpubkeys));
            components.push(prev_sciptpubkeys);
        }
        if spec.sequences {
            let mut sequences = Vec::new();
            let mut buffer = Vec::new();
            for i in tx.input.iter() {
                i.sequence.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut sequences).unwrap();
            debug!("sequences: {:?}", hex::encode(&sequences));
            components.push(sequences);
        }
    }

    if spec.outputs && sighash != TapSighashType::None && sighash != TapSighashType::Single {
        let mut outputs = Vec::new();
        let mut buffer = Vec::new();
        for o in tx.output.iter() {
            o.consensus_encode(&mut buffer).unwrap();
        }
        let hash = sha256::Hash::hash(&buffer);
        hash.consensus_encode(&mut outputs).unwrap();
        debug!("outputs: {:?}", hex::encode(&outputs));
        components.push(outputs);
    }

    if spec.spend_type {
        let mut encoded_spend_type = Vec::new();
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut encoded_spend_type)?;
        debug!("spend_type: {:?}", hex::encode(&encoded_spend_type));
        components.push(encoded_spend_type);
    }

    // TODO: wrap these fields in spec checks. right now we dont use ANYONECANPAY so it doesnt matter. But some other applications might want to use it.

    // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
    //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
    //      amount (8): value of the previous output spent by this input.
    //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
    //      nSequence (4): nSequence of this input.
    if anyone_can_pay {
        let txin = &tx
            .input
            .get(input_index)
            .ok_or(anyhow!("IndexOutOfInputsBounds"))?;
        let previous_output = prevouts
            .get(input_index)
            .ok_or(anyhow!("IndexOutOfInputsBounds"))?;
        let mut prevout = Vec::new();
        txin.previous_output.consensus_encode(&mut prevout)?;
        debug!("input prevout: {:?}", hex::encode(&prevout));
        components.push(prevout);
        let mut amount = Vec::new();
        previous_output.value.consensus_encode(&mut amount)?;
        debug!("input amount: {:?}", hex::encode(&amount));
        components.push(amount);
        let mut script_pubkey = Vec::new();
        previous_output
            .script_pubkey
            .consensus_encode(&mut script_pubkey)?;
        debug!("input script_pubkey: {:?}", hex::encode(&script_pubkey));
        components.push(script_pubkey);
        let mut sequence = Vec::new();
        txin.sequence.consensus_encode(&mut sequence)?;
        debug!("input sequence: {:?}", hex::encode(&sequence));
        components.push(sequence);
    } else {
        let mut input_idx = Vec::new();
        (input_index as u32).consensus_encode(&mut input_idx)?;
        debug!("input index: {:?}", hex::encode(&input_idx));
        components.push(input_idx);
    }

    // If an annex is present (the lowest bit of spend_type is set):
    //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
    //      includes the mandatory 0x50 prefix.
    if spec.annex {
        if let Some(annex) = annex {
            let mut encoded_annex = Vec::new();
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut encoded_annex)?;
            debug!("annex: {:?}", hex::encode(&encoded_annex));
            components.push(encoded_annex);
        }
    }

    // * Data about this output:
    // If hash_type & 3 equals SIGHASH_SINGLE:
    //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
    if spec.single_output && sighash == TapSighashType::Single {
        let mut encoded_single_output = Vec::new();
        let mut enc = sha256::Hash::engine();
        tx.output
            .get(input_index)
            .ok_or(anyhow!("SingleWithoutCorrespondingOutput"))?
            .consensus_encode(&mut enc)?;
        let hash = sha256::Hash::from_engine(enc);
        hash.consensus_encode(&mut encoded_single_output)?;
        debug!("single_output: {:?}", hex::encode(&encoded_single_output));
        components.push(encoded_single_output);
    }

    //     if (scriptpath):
    //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
    //         ss += bytes([0])
    //         ss += struct.pack("<i", codeseparator_pos)

    if spec.scriptpath {
        #[allow(non_snake_case)]
        let KEY_VERSION_0 = 0u8;

        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            let mut encoded_leaf_hash = Vec::new();
            hash.as_byte_array()
                .consensus_encode(&mut encoded_leaf_hash)?;
            debug!("leaf_hash: {:?}", hex::encode(&encoded_leaf_hash));
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            KEY_VERSION_0.consensus_encode(&mut encoded_leaf_hash)?;
            debug!("leaf_ver: {:?}", hex::encode(&encoded_leaf_hash));
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            code_separator_pos.consensus_encode(&mut encoded_leaf_hash)?;
            debug!("code_separator_pos: {:?}", hex::encode(&encoded_leaf_hash));
            components.push(encoded_leaf_hash);
        }
    }

    Ok(components)
}

pub(crate) fn compute_signature_from_components(
    components: &[Vec<u8>],
) -> anyhow::Result<[u8; 64]> {
    let sigmsg = compute_sigmsg_from_components(components)?;
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    let challenge = make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice());
    Ok(make_signature(&challenge))
}

pub(crate) fn compute_sigmsg_from_components(components: &[Vec<u8>]) -> anyhow::Result<[u8; 32]> {
    debug!("creating sigmsg from components",);
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input("TapSighash".as_bytes());
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    let mut serialized_tx = sha256::Hash::engine();
    serialized_tx.input(hashed_tag.as_ref());
    serialized_tx.input(hashed_tag.as_ref());

    {
        let tapsighash_engine = TapSighash::engine();
        assert_eq!(tapsighash_engine.midstate(), serialized_tx.midstate());
    }

    for component in components.iter() {
        serialized_tx.input(component.as_slice());
    }

    let tagged_hash = sha256::Hash::from_engine(serialized_tx);
    Ok(tagged_hash.into_32())
}

pub(crate) fn compute_challenge(sigmsg: &[u8; 32]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice())
}

fn make_signature(challenge: &[u8; 32]) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    signature[0..32].copy_from_slice(G_X.as_slice());
    signature[32..64].copy_from_slice(challenge);
    signature
}

fn make_tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // make a hashed_tag which is sha256(tag)
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input(tag);
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    // compute the message to be hashed. It is prefixed with the hashed_tag twice
    // for example, hashed_tag || hashed_tag || data
    let mut message = sha256::Hash::engine();
    message.input(hashed_tag.as_ref());
    message.input(hashed_tag.as_ref());
    message.input(data);
    let message = sha256::Hash::from_engine(message);
    message.into_32()
}

pub(crate) struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) enum GrindField {
    LockTime,
    Sequence,
}

pub(crate) fn grind_transaction<S>(
    initial_tx: Transaction,
    grind_field: GrindField,
    prevouts: &[TxOut],
    leaf_hash: S,
) -> anyhow::Result<ContractComponents>
where
    S: Into<TapLeafHash> + Clone,
{
    let signature_components: Vec<Vec<u8>>;
    let mut counter = 0;

    let mut spend_tx = initial_tx.clone();

    loop {
        match grind_field {
            GrindField::LockTime => spend_tx.lock_time = LockTime::from_height(counter)?,
            GrindField::Sequence => {
                // make sure counter has the 31st bit set, so that it's not used as a relative timelock
                // (BIP68 tells us that bit disables the consensus meaning of sequence numbers for RTL)
                counter |= 1 << 31;
                // set the sequence number of the last input to the counter, we'll use that to pay fees if there is more than one input
                spend_tx.input.last_mut().unwrap().sequence = Sequence::from_consensus(counter);
            }
        }
        debug!("grinding counter {}", counter);

        let components_for_signature = get_sigmsg_components(
            &TxCommitmentSpec::default(),
            &spend_tx,
            0,
            prevouts,
            None,
            leaf_hash.clone(),
            TapSighashType::Default,
        )?;
        let sigmsg = compute_sigmsg_from_components(&components_for_signature)?;
        let challenge = compute_challenge(&sigmsg);

        if challenge[31] == 0x00 {
            debug!("Found a challenge with a 0 at the end!");
            debug!("{:?} is {}", grind_field, counter);
            debug!("Here's the challenge: {}", hex::encode(&challenge),);
            signature_components = components_for_signature;
            break;
        }
        counter += 1;
    }
    Ok(ContractComponents {
        transaction: spend_tx,
        signature_components,
    })
}

pub(crate) fn enforce_payout(payout_spk: ScriptBuf, amount: u64) -> ScriptBuf {
    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys and pre_amounts,
    // followed by the output amount, then the script pubkey,
    // followed by the fee amount, then the fee-paying scriptpubkey
    // and finally the mangled signature

    let output = TxOut {
        script_pubkey: payout_spk,
        value: amount,
    };
    let mut outputs = Vec::new();
    let mut buffer = Vec::new();
    output.consensus_encode(&mut buffer).unwrap();
    let hash = sha256::Hash::hash(&buffer);
    hash.consensus_encode(&mut outputs).unwrap();
    println!("outputs: {:?}", hex::encode(&outputs));

    builder = builder
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        // .push_opcode(OP_TOALTSTACK) // push the fee-paying scriptpubkey to the alt stack
        // .push_opcode(OP_TOALTSTACK) // push the fee amount to the alt stack
        // .push_opcode(OP_2DUP) // make a second copy of the vault scriptpubkey and amount so we can check input = output
        // .push_opcode(OP_TOALTSTACK) // push the second copy of the vault scriptpubkey to the alt stack
        // .push_opcode(OP_TOALTSTACK) // push the second copy of the vault amount to the alt stack
        .push_slice(hash.into_32()) // push the payout output hash
        .push_opcode(OP_TOALTSTACK) // push the payout output hash to the alt stack
        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_opcode(OP_FROMALTSTACK) // get the output hash
        .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        // .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault amount
        // .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault scriptpubkey
        // .push_opcode(OP_FROMALTSTACK) // get the fee amount
        // .push_opcode(OP_FROMALTSTACK) // get the fee-paying scriptpubkey
        // .push_opcode(OP_SWAP) // move the fee-paying scriptpubkey below the fee amount
        // .push_opcode(OP_TOALTSTACK) // move fee amount to alt stack
        // .push_opcode(OP_CAT) // cat the vault scriptpubkey fee-paying scriptpubkey
        // .push_opcode(OP_SWAP) // move the vault amount to the top of the stack
        // .push_opcode(OP_TOALTSTACK) // move the vault amount to the alt stack
        .push_opcode(OP_SHA256) // hash the scriptpubkeys, should now be consensus encoding
        .push_opcode(OP_SWAP) // move the hashed encoded scriptpubkeys below our working sigmsg
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_FROMALTSTACK) // get the vault amount
        // .push_opcode(OP_FROMALTSTACK) // get the fee amount
        // .push_opcode(OP_CAT) // cat the vault amount and the fee amount
        .push_opcode(OP_SHA256) // hash the amounts
        .push_opcode(OP_SWAP) // move the hashed encoded amounts below our working sigmsg
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
