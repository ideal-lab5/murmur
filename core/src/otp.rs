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

use totp_rs::{Secret, TOTP, Algorithm};
use alloc::{
    vec::Vec,
    string::String,
};

/// a block based otp generator
pub struct BOTPGenerator {
    /// the time-based otp generator
    totp: TOTP
}

impl BOTPGenerator {
    /// create a new BOTP generator with the given seed
    pub fn new(seed: Vec<u8>) -> Self {
        let secret = Secret::Raw(seed.to_vec()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA256, // algorithm
            6,                 // num digits
            1,                 // skew
            1,                 // step
            secret             // secret
        ).unwrap();

        BOTPGenerator { totp }
    }

    /// generate an otp code
    pub fn generate(&self, block_height: u32) -> String {
        self.totp.generate(block_height as u64)
    }

}