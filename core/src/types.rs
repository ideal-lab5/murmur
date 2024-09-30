/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ckb_merkle_mountain_range::{Merge, Result as MMRResult};
pub use etf_crypto_primitives::ibe::fullident::Identity;
use sha3::Digest;
use alloc::vec::Vec;

/// The type to represent a block number
pub type BlockNumber = u32;

/// An opaque ciphertext type
pub type Ciphertext = Vec<u8>;

/// A leaf in the MMR
/// The payload is an opaque, any-length vec
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

/// Merge leaves together with a sha256 hasher
#[derive(Debug)]
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

/// Something that builds unique identities (e.g. using crypto hash function) for any block number
pub trait IdentityBuilder<BlockNumber> {
    fn build_identity(at: BlockNumber) -> Identity;
}