//! The Commitment enum, used for the corresponding block header field.

use std::fmt;

use hex::{FromHex, ToHex};
use thiserror::Error;

use zcash_primitives::bft::FatPointerToBftBlock;

use crate::{
    block::{self, merkle::AuthDataRoot},
    parameters::{
        Network,
        NetworkUpgrade::{self, *},
    },
    sapling,
    serialization::BytesInDisplayOrder,
};

/// BLAKE2b personalization for [`fat_pointer_digest`]. Sixteen bytes, the
/// personalization length.
const FAT_POINTER_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZcashCLFatPtrHsh";

/// Digest of `fat_pointer` mixed into the ZIP 244 terminator of
/// `hashBlockCommitments`.
///
/// A null pointer digests to 32 zero bytes, which is the upstream ZIP 244
/// terminator, so a block that carries a null pointer keeps the commitment it
/// had before the pointer was bound. Any other pointer digests to
/// BLAKE2b-256 of its serialization under the personalization
/// `ZcashCLFatPtrHsh`.
pub fn fat_pointer_digest(fat_pointer: &FatPointerToBftBlock) -> [u8; 32] {
    if fat_pointer == &FatPointerToBftBlock::null() {
        return [0u8; 32];
    }
    let mut bytes = Vec::new();
    fat_pointer
        .zcash_serialize(&mut bytes)
        .expect("serialization into a vec can't fail");
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(FAT_POINTER_DIGEST_PERSONALIZATION)
        .hash(&bytes);
    <[u8; 32]>::try_from(digest.as_bytes()).expect("hash_length is 32")
}

/// Zcash blocks contain different kinds of commitments to their contents,
/// depending on the network and height.
///
/// The `Header.commitment_bytes` field is interpreted differently, based on the
/// network and height. The interpretation changes in the network upgrade
/// activation block, or in the block immediately after network upgrade
/// activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Commitment {
    /// [Pre-Sapling] "A reserved field, to be ignored."
    ///
    /// This field is not verified.
    PreSaplingReserved([u8; 32]),

    /// [Sapling and Blossom] The final Sapling treestate of this block.
    ///
    /// The root LEBS2OSP256(rt) of the Sapling note commitment tree
    /// corresponding to the final Sapling treestate of this block.
    ///
    /// Subsequent `Commitment` variants also commit to the `FinalSaplingRoot`,
    /// via their `EarliestSaplingRoot` and `LatestSaplingRoot` fields.
    ///
    /// Since Zebra checkpoints on Canopy, we don't need to validate this
    /// field, but since it's included in the ChainHistoryRoot, we are
    /// already calculating it, so we might as well validate it.
    ///
    /// TODO: this field is verified during semantic verification
    FinalSaplingRoot(sapling::tree::Root),

    /// [Heartwood activation block] Reserved field.
    ///
    /// The value of this field MUST be all zeroes.
    ///
    /// This MUST NOT be interpreted as a root hash.
    /// See ZIP-221 for details.
    ///
    /// This field is verified in `Commitment::from_bytes`.
    ChainHistoryActivationReserved,

    /// [(Heartwood activation block + 1) to Canopy] The root of a Merkle
    /// Mountain Range chain history tree.
    ///
    /// This root hash commits to various features of the chain's history,
    /// including the Sapling commitment tree. This commitment supports the
    /// FlyClient protocol. See ZIP-221 for details.
    ///
    /// The commitment in each block covers the chain history from the most
    /// recent network upgrade, through to the previous block. In particular,
    /// an activation block commits to the entire previous network upgrade, and
    /// the block after activation commits only to the activation block. (And
    /// therefore transitively to all previous network upgrades covered by a
    /// chain history hash in their activation block, via the previous block
    /// hash field.)
    ///
    /// Since Zebra's mandatory checkpoint includes Canopy activation, we only
    /// need to verify the chain history root from `Canopy + 1 block` onwards,
    /// using a new history tree based on the `Canopy` activation block.
    ///
    /// NU5 and later upgrades use the [`Commitment::ChainHistoryBlockTxAuthCommitment`]
    /// variant.
    ///
    /// TODO: this field is verified during contextual verification
    ChainHistoryRoot(ChainHistoryMmrRootHash),

    /// [NU5 activation onwards] A commitment to:
    /// - the chain history Merkle Mountain Range tree, and
    /// - the auth data merkle tree covering this block.
    ///
    /// The chain history Merkle Mountain Range tree commits to the previous
    /// block and all ancestors in the current network upgrade. (A new chain
    /// history tree starts from each network upgrade's activation block.)
    ///
    /// The auth data merkle tree commits to this block.
    ///
    /// This commitment supports the FlyClient protocol and non-malleable
    /// transaction IDs. See ZIP-221 and ZIP-244 for details.
    ///
    /// See also the [`Commitment::ChainHistoryRoot`] variant.
    ///
    /// TODO: this field is verified during contextual verification
    ChainHistoryBlockTxAuthCommitment(ChainHistoryBlockTxAuthCommitmentHash),
}

/// The required value of reserved `Commitment`s.
pub const CHAIN_HISTORY_ACTIVATION_RESERVED: [u8; 32] = [0; 32];

impl Commitment {
    /// Returns `bytes` as the Commitment variant for `network` and `height`.
    //
    // TODO: rename as from_bytes_in_serialized_order()
    pub(super) fn from_bytes(
        bytes: [u8; 32],
        network: &Network,
        height: block::Height,
    ) -> Result<Commitment, CommitmentError> {
        use Commitment::*;
        use CommitmentError::*;

        match NetworkUpgrade::current_with_activation_height(network, height) {
            (Genesis | BeforeOverwinter | Overwinter, _) => Ok(PreSaplingReserved(bytes)),
            (Sapling | Blossom, _) => match sapling::tree::Root::try_from(bytes) {
                Ok(root) => Ok(FinalSaplingRoot(root)),
                _ => Err(InvalidSapingRootBytes),
            },
            (Heartwood, activation_height) if height == activation_height => {
                if bytes == CHAIN_HISTORY_ACTIVATION_RESERVED {
                    Ok(ChainHistoryActivationReserved)
                } else {
                    Err(InvalidChainHistoryActivationReserved { actual: bytes })
                }
            }
            // It's possible for the current network upgrade to be Heartwood or any network upgrade after Heartwood at
            // the Heartwood activation height on Regtest or configured test networks. The reserved chain history root
            // activation bytes should still be used pre-NU5.
            //
            // `NetworkUpgrade::current()` returns the *latest* upgrade activated at this height, so on a network
            // that configures several upgrades at the same low height -- Regtest, and Crosslink's testnets, which
            // activate everything at height 0/1 -- it returns NU5+ here rather than Canopy. Upstream matches only
            // `Canopy`, which makes such a chain's reserved (all-zero) commitment fail validation at its first
            // block. Match every post-Heartwood upgrade *at the Heartwood activation height* instead.
            //
            // See <https://zips.z.cash/zip-0221> and the [protocol specification §7.6](https://zips.z.cash/protocol/protocol.pdf).
            (Canopy | Nu5 | Nu6 | Nu6_1 | Nu6_2 | Nu6_3 | Nu7, activation_height)
                if height == activation_height
                    && Some(height) == Heartwood.activation_height(network) =>
            {
                if bytes == CHAIN_HISTORY_ACTIVATION_RESERVED {
                    Ok(ChainHistoryActivationReserved)
                } else {
                    Err(InvalidChainHistoryActivationReserved { actual: bytes })
                }
            }
            (Heartwood | Canopy, _) => Ok(ChainHistoryRoot(ChainHistoryMmrRootHash(bytes))),
            (Nu5 | Nu6 | Nu6_1 | Nu6_2 | Nu6_3 | Nu7, _) => Ok(ChainHistoryBlockTxAuthCommitment(
                ChainHistoryBlockTxAuthCommitmentHash(bytes),
            )),

            #[cfg(zcash_unstable = "zfuture")]
            (ZFuture, _) => Ok(ChainHistoryBlockTxAuthCommitment(
                ChainHistoryBlockTxAuthCommitmentHash(bytes),
            )),

            #[cfg(zcash_unstable = "zfuture")]
            (ZFuture, _) => Ok(ChainHistoryBlockTxAuthCommitment(
                ChainHistoryBlockTxAuthCommitmentHash(bytes),
            )),
        }
    }

    /// Returns the serialized bytes for this Commitment.
    //
    // TODO: refactor as bytes_in_serialized_order(&self)
    #[cfg(test)]
    pub(super) fn to_bytes(self) -> [u8; 32] {
        use Commitment::*;

        match self {
            PreSaplingReserved(bytes) => bytes,
            FinalSaplingRoot(hash) => hash.0.into(),
            ChainHistoryActivationReserved => CHAIN_HISTORY_ACTIVATION_RESERVED,
            ChainHistoryRoot(hash) => hash.0,
            ChainHistoryBlockTxAuthCommitment(hash) => hash.0,
        }
    }
}

/// The root hash of a Merkle Mountain Range chain history tree.
// TODO:
//    - add methods for maintaining the MMR peaks, and calculating the root
//      hash from the current set of peaks
//    - move to a separate file
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChainHistoryMmrRootHash([u8; 32]);

impl fmt::Display for ChainHistoryMmrRootHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.encode_hex::<String>())
    }
}

impl fmt::Debug for ChainHistoryMmrRootHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ChainHistoryMmrRootHash")
            .field(&self.encode_hex::<String>())
            .finish()
    }
}

impl From<[u8; 32]> for ChainHistoryMmrRootHash {
    fn from(hash: [u8; 32]) -> Self {
        ChainHistoryMmrRootHash(hash)
    }
}

impl From<ChainHistoryMmrRootHash> for [u8; 32] {
    fn from(hash: ChainHistoryMmrRootHash) -> Self {
        hash.0
    }
}

impl BytesInDisplayOrder<true> for ChainHistoryMmrRootHash {
    fn bytes_in_serialized_order(&self) -> [u8; 32] {
        self.0
    }

    fn from_bytes_in_serialized_order(bytes: [u8; 32]) -> Self {
        ChainHistoryMmrRootHash(bytes)
    }
}

impl ToHex for &ChainHistoryMmrRootHash {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.bytes_in_display_order().encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.bytes_in_display_order().encode_hex_upper()
    }
}

impl ToHex for ChainHistoryMmrRootHash {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        (&self).encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        (&self).encode_hex_upper()
    }
}

impl FromHex for ChainHistoryMmrRootHash {
    type Error = <[u8; 32] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut hash = <[u8; 32]>::from_hex(hex)?;
        hash.reverse();

        Ok(hash.into())
    }
}

/// A block commitment to chain history and transaction auth.
/// - the chain history tree for all ancestors in the current network upgrade,
///   and
/// - the transaction authorising data in this block.
///
/// Introduced in NU5.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainHistoryBlockTxAuthCommitmentHash([u8; 32]);

impl fmt::Display for ChainHistoryBlockTxAuthCommitmentHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.encode_hex::<String>())
    }
}

impl fmt::Debug for ChainHistoryBlockTxAuthCommitmentHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ChainHistoryBlockTxAuthCommitmentHash")
            .field(&self.encode_hex::<String>())
            .finish()
    }
}

impl From<[u8; 32]> for ChainHistoryBlockTxAuthCommitmentHash {
    fn from(hash: [u8; 32]) -> Self {
        ChainHistoryBlockTxAuthCommitmentHash(hash)
    }
}

impl From<ChainHistoryBlockTxAuthCommitmentHash> for [u8; 32] {
    fn from(hash: ChainHistoryBlockTxAuthCommitmentHash) -> Self {
        hash.0
    }
}

impl BytesInDisplayOrder<true> for ChainHistoryBlockTxAuthCommitmentHash {
    fn bytes_in_serialized_order(&self) -> [u8; 32] {
        self.0
    }

    fn from_bytes_in_serialized_order(bytes: [u8; 32]) -> Self {
        ChainHistoryBlockTxAuthCommitmentHash(bytes)
    }
}

impl ChainHistoryBlockTxAuthCommitmentHash {
    /// Compute the block commitment from the history tree root, the
    /// authorization data root, and the fat-pointer digest, as specified in
    /// [ZIP-244] with the terminator replaced by `fat_pointer_digest`.
    ///
    /// `history_tree_root` is the root of the history tree up to and including
    /// the *previous* block.
    /// `auth_data_root` is the root of the Merkle tree of authorizing data
    /// commmitments of each transaction in the *current* block.
    /// `fat_pointer_digest` is [`fat_pointer_digest`] of this block's
    /// `fat_pointer_to_bft_block`. Pass `&[0u8; 32]` for a null pointer; that
    /// is the ZIP 244 terminator, so the result matches the upstream
    /// commitment.
    ///
    /// The commitment is inside the Equihash input. Binding the pointer here
    /// means a different pointer is a different Equihash instance.
    ///
    ///  [ZIP-244]: https://zips.z.cash/zip-0244#block-header-changes
    pub fn from_commitments(
        history_tree_root: &ChainHistoryMmrRootHash,
        auth_data_root: &AuthDataRoot,
        fat_pointer_digest: &[u8; 32],
    ) -> Self {
        // > The value of this hash [hashBlockCommitments] is the BLAKE2b-256 hash personalized
        // > by the string "ZcashBlockCommit" of the following elements:
        // >   hashLightClientRoot (as described in ZIP 221)
        // >   hashAuthDataRoot    (as described below)
        // >   terminator          fat_pointer_digest (32 zero bytes for a null pointer)
        let hash_block_commitments: [u8; 32] = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZcashBlockCommit")
            .to_state()
            .update(&<[u8; 32]>::from(*history_tree_root)[..])
            .update(&<[u8; 32]>::from(*auth_data_root))
            .update(fat_pointer_digest)
            .finalize()
            .as_bytes()
            .try_into()
            .expect("32 byte array");
        Self(hash_block_commitments)
    }
}

impl ToHex for &ChainHistoryBlockTxAuthCommitmentHash {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.bytes_in_display_order().encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.bytes_in_display_order().encode_hex_upper()
    }
}

impl ToHex for ChainHistoryBlockTxAuthCommitmentHash {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        (&self).encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        (&self).encode_hex_upper()
    }
}

impl FromHex for ChainHistoryBlockTxAuthCommitmentHash {
    type Error = <[u8; 32] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut hash = <[u8; 32]>::from_hex(hex)?;
        hash.reverse();

        Ok(hash.into())
    }
}

/// Errors that can occur when checking RootHash consensus rules.
///
/// Each error variant corresponds to a consensus rule, so enumerating
/// all possible verification failures enumerates the consensus rules we
/// implement, and ensures that we don't reject blocks or transactions
/// for a non-enumerated reason.
#[allow(missing_docs)]
#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    #[error(
        "invalid final sapling root: expected {:?}, actual: {:?}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    InvalidFinalSaplingRoot {
        // TODO: are these fields a security risk? If so, open a ticket to remove
        // similar fields across Zebra
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("invalid chain history activation reserved block commitment: expected all zeroes, actual: {:?}",  hex::encode(actual))]
    InvalidChainHistoryActivationReserved { actual: [u8; 32] },

    #[error(
        "invalid chain history root: expected {:?}, actual: {:?}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    InvalidChainHistoryRoot {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error(
        "invalid block commitment root: expected {:?}, actual: {:?}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    InvalidChainHistoryBlockTxAuthCommitment {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// A non-null fat pointer on a block whose commitment cannot bind it.
    ///
    /// Pre-NU5 commitments (the reserved Heartwood value, a chain-history
    /// root, a Sapling root, or the pre-Sapling reserved field) have no
    /// terminator to mix the pointer into. A non-null pointer there would be
    /// outside the Equihash input.
    #[error("non-null fat pointer on a block whose commitment does not bind it")]
    NonNullFatPointerBeforeBlockCommitments,

    #[error("missing required block height: block commitments can't be parsed without a block height, block hash: {block_hash:?}")]
    MissingBlockHeight { block_hash: block::Hash },

    #[error("provided bytes are not a valid sapling root")]
    InvalidSapingRootBytes,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use crate::{
        block::{merkle, Hash, Header},
        fmt::HexDebug,
        serialization::ZcashSerialize,
        work::{difficulty::CompactDifficulty, equihash::Solution},
    };

    use super::*;

    fn sample_roots() -> (ChainHistoryMmrRootHash, AuthDataRoot) {
        ([1u8; 32].into(), [2u8; 32].into())
    }

    fn header_with(commitment: [u8; 32], pointer: FatPointerToBftBlock) -> Header {
        Header {
            version: 6,
            previous_block_hash: Hash([0; 32]),
            merkle_root: merkle::Root([3; 32]),
            commitment_bytes: HexDebug(commitment),
            time: Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .expect("timestamp is in range"),
            difficulty_threshold: CompactDifficulty(0),
            nonce: HexDebug([0; 32]),
            solution: Solution::Regtest([0; 36]),
            fat_pointer_to_bft_block: pointer,
        }
    }

    fn equihash_input(header: &Header) -> Vec<u8> {
        let mut bytes = Vec::new();
        header
            .zcash_serialize(&mut bytes)
            .expect("serialization into a vec can't fail");
        bytes[..Solution::INPUT_LENGTH].to_vec()
    }

    fn non_null_pointer(height_byte: u8) -> FatPointerToBftBlock {
        let mut pointer = FatPointerToBftBlock::null();
        pointer.vote_for_block_without_finalizer_public_key[0] = 0xaa;
        pointer.vote_for_block_without_finalizer_public_key[32] = height_byte;
        pointer
    }

    #[test]
    fn null_pointer_digest_is_the_zip244_terminator() {
        assert_eq!(fat_pointer_digest(&FatPointerToBftBlock::null()), [0u8; 32]);

        let (history, auth) = sample_roots();
        let bound = ChainHistoryBlockTxAuthCommitmentHash::from_commitments(
            &history,
            &auth,
            &fat_pointer_digest(&FatPointerToBftBlock::null()),
        );
        let upstream =
            ChainHistoryBlockTxAuthCommitmentHash::from_commitments(&history, &auth, &[0u8; 32]);
        assert_eq!(bound, upstream);

        let legacy: [u8; 32] = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZcashBlockCommit")
            .to_state()
            .update(&[1u8; 32])
            .update(&[2u8; 32])
            .update(&[0u8; 32])
            .finalize()
            .as_bytes()
            .try_into()
            .expect("hash_length is 32");
        assert_eq!(<[u8; 32]>::from(bound), legacy);
    }

    #[test]
    fn a_different_pointer_is_a_different_equihash_input() {
        let (history, auth) = sample_roots();
        let null_pointer = FatPointerToBftBlock::null();
        let pointed = non_null_pointer(1);
        let pointed_again = non_null_pointer(2);

        let null_digest = fat_pointer_digest(&null_pointer);
        let pointed_digest = fat_pointer_digest(&pointed);
        assert_ne!(pointed_digest, [0u8; 32]);
        assert_ne!(pointed_digest, fat_pointer_digest(&pointed_again));

        let null_commitment =
            ChainHistoryBlockTxAuthCommitmentHash::from_commitments(&history, &auth, &null_digest);
        let pointed_commitment = ChainHistoryBlockTxAuthCommitmentHash::from_commitments(
            &history,
            &auth,
            &pointed_digest,
        );
        assert_ne!(null_commitment, pointed_commitment);

        let unbound = header_with(null_commitment.into(), null_pointer.clone());
        // Varying the pointer without rebinding the commitment leaves the
        // Equihash input alone: that is the grind this binding closes.
        let grind = header_with(null_commitment.into(), pointed.clone());
        assert_eq!(equihash_input(&unbound), equihash_input(&grind));

        let bound = header_with(pointed_commitment.into(), pointed);
        assert_ne!(equihash_input(&unbound), equihash_input(&bound));
    }
}
