use ckb_merkle_mountain_range::{
    MerkleProof,
    MMR, Merge, Result as MMRResult, MMRStore,
    util::{
        MemMMR,
        MemStore
    },
};
use sha3::Digest;

pub type BlockNumber = u32;

#[derive(
    Eq, PartialEq, Clone, Debug, Default, 
    serde::Serialize, serde::Deserialize
)]
pub struct Leaf(pub Vec<u8>);
impl From<Vec<u8>> for Leaf {
    fn from(data: Vec<u8>) -> Self {
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(&data);
        let hash = hasher.finalize();
        Leaf(hash.to_vec().into())
    }
}

pub struct MergeLeaves;

impl Merge for MergeLeaves {
    type Item = Leaf;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> MMRResult<Self::Item> {
		let mut hasher = sha3::Sha3_256::default();
        hasher.update(&lhs.0);
        hasher.update(&rhs.0);
        let hash = hasher.finalize();
        Ok(Leaf(hash.to_vec().into()))
    }
}