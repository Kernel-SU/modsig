//! # KSU Signing Block
//! This library is used to extract the KSU Signing Block from an Module file.
//!
//! CLI usage:
//! ```shell
//! cargo install modsig
//! modsig <filename>
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
pub mod module;
pub mod signing_block;
pub mod utils;
pub mod zip;

// Conditional modules
#[cfg(feature = "keystore")]
pub mod keystore;

#[cfg(feature = "signing")]
pub mod signer;

#[cfg(feature = "verify")]
pub mod verifier;

// re-export
#[cfg(feature = "hash")]
pub use signing_block::digest::digest_module;

pub use module::Module;
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
    verify_signing_block, verify_with_roots, CertChainVerifier, SignatureVerifier, TrustedRoots,
    VerifyError, VerifyResult,
};

// shortcuts
use utils::add_space;
