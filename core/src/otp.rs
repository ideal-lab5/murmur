//! # #[cfg(not(feature = "otpauth"))] {
//! use etf_otp::{BOTPGenerator};
//!
//! let totp = BOTPGenerator::new(b"123456789123456789123456".to_vec());
//! let otp = totp.generate(1);
//!
use totp_rs::{Secret, TOTP, Algorithm};

pub struct BOTPGenerator {
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

    pub fn generate(&self, block_height: u32) -> String {
        self.totp.generate(block_height as u64)
    }

}