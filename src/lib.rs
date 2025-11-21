//! # APK Signing Block
//! This library is used to extract the APK Signing Block from an APK file.
//!
//! CLI usage:
//! ```shell
//! cargo install apksig
//! apksig <filename>
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

pub mod module;
pub mod common;
pub mod signing_block;
pub mod utils;
pub mod zip;

// re-export
#[cfg(feature = "hash")]
pub use signing_block::digest::digest_apk;

pub use module::Module;
pub use signing_block::algorithms::Algorithms;
#[cfg(feature = "signing")]
pub use signing_block::algorithms::PrivateKey;
pub use signing_block::scheme_v2::{SignatureSchemeV2, SIGNATURE_SCHEME_V2_BLOCK_ID};
pub use signing_block::{scheme_v2, RawData, SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN};
pub use utils::MyReader;

// shortcuts
use utils::add_space;
