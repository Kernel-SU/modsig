//! # KSU Signing Block
//! This library is used to extract the KSU Signing Block from an Module file.
//!
//! CLI usage:
//! ```shell
//! cargo install ksusig
//! ksusig <filename>
//! ```
//!

#![deny(
    missing_docs,
    clippy::all,
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // clippy::arithmetic_side_effects,
    // clippy::pedantic,
    clippy::nursery
)]
#![warn(clippy::multiple_crate_versions)]

pub mod common;
pub mod file_formats;
pub mod signable;
pub mod signing_block;
pub mod utils;

// Backward compatibility: re-export old module paths
pub mod module {
    //! Module file handling (re-exported from file_formats::module)
    pub use crate::file_formats::module::*;
}

pub mod zip {
    //! ZIP file utilities (re-exported from file_formats::module::zip)
    pub use crate::file_formats::module::zip::*;
}

// Conditional modules
#[cfg(feature = "keystore")]
pub mod keystore;

#[cfg(feature = "signing")]
pub mod signer;

#[cfg(feature = "verify")]
pub mod verifier;

// re-export
#[cfg(feature = "hash")]
pub use file_formats::module::digest::digest_module;

pub use file_formats::module::Module;
pub use signable::{DigestRegion, FileFormat, Signable, SignableError, SignableFile};
pub use signing_block::algorithms::Algorithms;
#[cfg(feature = "signing")]
pub use signing_block::algorithms::PrivateKey;
pub use signing_block::scheme_v2::{SignatureSchemeV2, SIGNATURE_SCHEME_V2_BLOCK_ID};
pub use signing_block::source_stamp::{SourceStamp, SOURCE_STAMP_BLOCK_ID};
#[cfg(feature = "signing")]
pub use signing_block::source_stamp::{
    SourceStampSigner, SourceStampSignerBuilder, SourceStampSignerConfig,
};
pub use signing_block::{
    scheme_v2, source_stamp, RawData, SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN,
};
pub use utils::MyReader;

// Keystore exports
#[cfg(feature = "keystore")]
pub use keystore::{
    load_p12, load_p12_from_bytes, load_pem, load_pem_from_bytes, KeystoreError, SignerCredentials,
};

// Signer exports
#[cfg(feature = "signing")]
pub use signer::{
    ModuleSigner, ModuleSignerConfig, SourceStampSigner as NewSourceStampSigner, V2Signer,
};

// Verify exports
#[cfg(feature = "verify")]
pub use verifier::{
    verify_with_digest, verify_with_roots_and_digest, CertChainVerifier, DigestContext,
    SignatureVerifier, SignerVerifyResult, TrustedRoots, VerifyAllResult, VerifyError, VerifyResult,
};

