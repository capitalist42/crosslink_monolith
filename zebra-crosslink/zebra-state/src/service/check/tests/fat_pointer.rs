//! The fat pointer is bound into NU5 `hashBlockCommitments` and rejected
//! wherever the commitment has no terminator to bind it.

use std::sync::Arc;

use chrono::{TimeZone, Utc};

use zebra_chain::{
    amount::{Amount, NonNegative},
    block::{
        fat_pointer_digest, Block, ChainHistoryBlockTxAuthCommitmentHash, CommitmentError,
        FatPointerToBftBlock, Hash, Header, Height,
    },
    fmt::HexDebug,
    history_tree::HistoryTree,
    orchard,
    parameters::{Network, NetworkUpgrade},
    primitives::zcash_history::BlockCommitmentTreeRoots,
    sapling,
    serialization::BytesInDisplayOrder,
    transaction::{LockTime, Transaction},
    transparent::{self, Script},
    work::{difficulty::CompactDifficulty, equihash::Solution},
};

use crate::{service::check::block_commitment_is_valid_for_chain_history, ValidateContextError};

fn non_null_pointer() -> FatPointerToBftBlock {
    let mut pointer = FatPointerToBftBlock::null();
    pointer.vote_for_block_without_finalizer_public_key[0] = 0xaa;
    pointer.vote_for_block_without_finalizer_public_key[32] = 1;
    pointer
}

fn coinbase(height: Height, network_upgrade: NetworkUpgrade) -> Transaction {
    let input = transparent::Input::Coinbase {
        height,
        data: Vec::new(),
        sequence: u32::MAX,
    };
    let output = transparent::Output::new(Amount::<NonNegative>::zero(), Script::new(&[]));
    match network_upgrade {
        NetworkUpgrade::Nu5
        | NetworkUpgrade::Nu6
        | NetworkUpgrade::Nu6_1
        | NetworkUpgrade::Nu6_2
        | NetworkUpgrade::Nu6_3
        | NetworkUpgrade::Nu7 => Transaction::V5 {
            network_upgrade,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            inputs: vec![input],
            outputs: vec![output],
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        },
        _ => Transaction::V4 {
            inputs: vec![input],
            outputs: vec![output],
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            joinsplit_data: None,
            sapling_shielded_data: None,
        },
    }
}

fn block_at(
    height: Height,
    network_upgrade: NetworkUpgrade,
    commitment: [u8; 32],
    pointer: FatPointerToBftBlock,
) -> Arc<Block> {
    Arc::new(Block {
        header: Arc::new(Header {
            version: 6,
            previous_block_hash: Hash([0; 32]),
            merkle_root: zebra_chain::block::merkle::Root([0; 32]),
            commitment_bytes: HexDebug(commitment),
            time: Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .expect("timestamp is in range"),
            difficulty_threshold: CompactDifficulty::from_bytes_in_display_order(&[
                0x20, 0x0f, 0x0f, 0x0f,
            ])
            .expect("compact difficulty is valid"),
            nonce: HexDebug([0; 32]),
            solution: Solution::for_proposal(),
            fat_pointer_to_bft_block: pointer,
        }),
        transactions: vec![Arc::new(coinbase(height, network_upgrade))],
    })
}

fn empty_roots() -> (
    sapling::tree::Root,
    orchard::tree::Root,
    orchard::tree::Root,
) {
    (
        sapling::tree::NoteCommitmentTree::default().root(),
        orchard::tree::NoteCommitmentTree::default().root(),
        orchard::tree::NoteCommitmentTree::default().root(),
    )
}

fn assert_unbound(result: Result<(), ValidateContextError>) {
    match result {
        Err(ValidateContextError::InvalidBlockCommitment(
            CommitmentError::NonNullFatPointerBeforeBlockCommitments,
        )) => {}
        other => panic!("expected an unbound fat pointer, got {other:?}"),
    }
}

#[test]
fn pre_nu5_commitments_reject_a_non_null_fat_pointer() {
    let network = Network::Mainnet;
    let heartwood = NetworkUpgrade::Heartwood
        .activation_height(&network)
        .expect("mainnet activates Heartwood");
    let canopy = NetworkUpgrade::Canopy
        .activation_height(&network)
        .expect("mainnet activates Canopy");

    let reserved = block_at(
        heartwood,
        NetworkUpgrade::Heartwood,
        [0u8; 32],
        FatPointerToBftBlock::null(),
    );
    block_commitment_is_valid_for_chain_history(reserved, &network, &HistoryTree::default())
        .expect("a null pointer at Heartwood activation is the reserved commitment");

    let pointed = block_at(
        heartwood,
        NetworkUpgrade::Heartwood,
        [0u8; 32],
        non_null_pointer(),
    );
    assert_unbound(block_commitment_is_valid_for_chain_history(
        pointed,
        &network,
        &HistoryTree::default(),
    ));

    // Canopy carries the raw history root, which also cannot bind a pointer.
    // The pointer check runs before the root is read, so an empty tree is enough.
    let canopy_block = block_at(
        canopy,
        NetworkUpgrade::Canopy,
        [0u8; 32],
        non_null_pointer(),
    );
    assert_unbound(block_commitment_is_valid_for_chain_history(
        canopy_block,
        &network,
        &HistoryTree::default(),
    ));
}

#[test]
fn nu5_commitment_binds_the_fat_pointer() {
    let network = Network::Mainnet;
    let heartwood = NetworkUpgrade::Heartwood
        .activation_height(&network)
        .expect("mainnet activates Heartwood");
    let nu5 = NetworkUpgrade::Nu5
        .activation_height(&network)
        .expect("mainnet activates NU5");

    let activation = block_at(
        heartwood,
        NetworkUpgrade::Heartwood,
        [0u8; 32],
        FatPointerToBftBlock::null(),
    );
    let (sapling, orchard_root, ironwood) = empty_roots();
    let history_tree = HistoryTree::from_block(
        &network,
        activation,
        BlockCommitmentTreeRoots {
            sapling: &sapling,
            orchard: &orchard_root,
            ironwood: &ironwood,
        },
    )
    .expect("the Heartwood activation block starts a history tree");
    let history_root = history_tree
        .hash()
        .expect("a tree built from a block has a root");

    let pointer = non_null_pointer();
    let unbound = block_at(nu5, NetworkUpgrade::Nu5, [0u8; 32], pointer.clone());
    let auth_root = unbound.auth_data_root();
    let bound_bytes = ChainHistoryBlockTxAuthCommitmentHash::from_commitments(
        &history_root,
        &auth_root,
        &fat_pointer_digest(&pointer),
    )
    .bytes_in_serialized_order();
    let legacy_bytes = ChainHistoryBlockTxAuthCommitmentHash::from_commitments(
        &history_root,
        &auth_root,
        &[0u8; 32],
    )
    .bytes_in_serialized_order();

    let legacy = block_at(nu5, NetworkUpgrade::Nu5, legacy_bytes, pointer.clone());
    match block_commitment_is_valid_for_chain_history(legacy, &network, &history_tree) {
        Err(ValidateContextError::InvalidBlockCommitment(
            CommitmentError::InvalidChainHistoryBlockTxAuthCommitment { .. },
        )) => {}
        other => panic!("a pointer omitted from the commitment must be rejected, got {other:?}"),
    }

    let bound = block_at(nu5, NetworkUpgrade::Nu5, bound_bytes, pointer);
    block_commitment_is_valid_for_chain_history(bound, &network, &history_tree)
        .expect("a commitment that mixes in the pointer digest is valid");
}
