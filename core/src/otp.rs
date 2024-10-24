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

use alloc::{
    vec::Vec,
    string::String,
};
use totp_rs::{Secret, TOTP, Algorithm};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum OTPError {
	/// The secret size is too large
	InvalidSecret,
}

/// A block based otp generator
pub struct BOTPGenerator {
	/// The time-based otp generator
	totp: TOTP,
}

impl BOTPGenerator {
    /// Create a new BOTP generator with the given seed
    ///
    /// * `seed`: The seed used to generate OTP codes
    ///
    pub fn new(mut seed: Vec<u8>) -> Result<Self, OTPError> {
        let mut secret = Secret::Raw(seed.clone()).to_bytes()
            .map_err(|_| OTPError::InvalidSecret)?;
        seed.zeroize();
        let totp = TOTP::new(
            Algorithm::SHA256, // algorithm
            6,                 // num digits
            1,                 // skew
            1,                 // step
            secret.clone()             // secret
        ).map_err(|_| OTPError::InvalidSecret)?;
        secret.zeroize();
        Ok(BOTPGenerator { totp })
    }

    /// Generate an otp code
    ///
    /// * `block_height`: The block for which the code is valid
    ///
    pub fn generate(&self, block_height: u64) -> String {
        self.totp.generate(block_height)
    }
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

	#[test]
	pub fn it_can_generate_otp_codes_with_valid_seed() {
		let botp = BOTPGenerator::new([1; 32].to_vec()).unwrap();
		let otp_min = botp.generate(0);
		assert!(otp_min.len() == 6);

		let otp_max = botp.generate(u64::MAX);
		assert!(otp_max.len() == 6);
	}

	#[test]
	pub fn it_fails_to_build_otp_generator_with_invalid_seed() {
		assert!(BOTPGenerator::new(vec![1]).is_err());
	}
}
