//! Source Stamp Signature Scheme
//! <https://source.android.com/docs/security/features/apksigning/v2#source-stamp>

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::add_space;
use crate::common::{
    AdditionalAttribute, AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey,
    Signature, Signatures,
};
use crate::utils::print_string;
use crate::MyReader;

#[cfg(feature = "signing")]
use crate::signing_block::algorithms::{Algorithms, PrivateKey};

/// Source Stamp Block ID (V2)
pub const SOURCE_STAMP_BLOCK_ID: u32 = 0x6dff_800d;

/// Source Stamp Certificate Hash ZIP Entry Name
pub const SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME: &str = "stamp-cert-sha256";

/// Stamp Time Attribute ID
pub const STAMP_TIME_ATTR_ID: u32 = 0xe43c_5946;

/// The `SourceStamp` struct represents the source stamp signature scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SourceStamp {
    /// The size of the source stamp.
    pub size: usize,

    /// The ID of the source stamp.
    pub id: u32,

    /// The stamp block data.
    pub stamp_block: StampBlock,
}

impl SourceStamp {
    /// Create a new source stamp
    pub const fn new(stamp_block: StampBlock) -> Self {
        Self {
            size: stamp_block.size,
            id: SOURCE_STAMP_BLOCK_ID,
            stamp_block,
        }
    }

    /// Parse the source stamp
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(size: usize, id: u32, data: &mut MyReader) -> Result<Self, String> {
        add_space!(4);
        print_string!("Source Stamp Block:");
        let stamp_block = StampBlock::parse(data)?;
        Ok(Self {
            size,
            id,
            stamp_block,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self.stamp_block.to_u8();
        [(self.size as u64).to_le_bytes().to_vec(), self.id.to_le_bytes().to_vec(), content]
            .concat()
    }
}

/// The `StampBlock` struct represents the stamp block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StampBlock {
    /// The size of the stamp block.
    pub size: usize,

    /// The signed data of the stamp.
    pub signed_data: SignedData,

    /// The signatures of the stamp.
    pub signatures: Signatures,

    /// The public key of the stamp.
    pub public_key: PubKey,
}

impl StampBlock {
    /// Create a new stamp block
    pub fn new(signed_data: SignedData, signatures: Signatures, public_key: PubKey) -> Self {
        let size = mem::size_of::<u32>() + signed_data.size()
            + mem::size_of::<u32>() + signatures.size
            + mem::size_of::<u32>() + public_key.size;
        Self {
            size,
            signed_data,
            signatures,
            public_key,
        }
    }

    /// Parse the stamp block
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_stamp_block = data.read_size()?;
        add_space!(4);
        print_string!("size_stamp_block: {}", size_stamp_block);

        let data = &mut data.as_slice(size_stamp_block)?;

        let signed_data = SignedData::parse(data)?;
        let signatures = Signatures::parse(data)?;
        let public_key = PubKey::parse(data)?;

        Ok(Self {
            size: size_stamp_block,
            signed_data,
            signatures,
            public_key,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        [
            (self.size as u32).to_le_bytes().to_vec(),
            self.signed_data.to_u8(),
            self.signatures.to_u8(),
            self.public_key.to_u8(),
        ]
        .concat()
    }
}

/// The `SignedData` struct represents the signed data of the stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedData {
    /// The digests of the stamp.
    pub digests: Digests,

    /// The certificates of the stamp.
    pub certificates: Certificates,

    /// The additional attributes of the stamp.
    pub additional_attributes: AdditionalAttributes,
}

impl SignedData {
    /// Create a new signed data
    pub const fn new(
        digests: Digests,
        certificates: Certificates,
        additional_attributes: AdditionalAttributes,
    ) -> Self {
        Self {
            digests,
            certificates,
            additional_attributes,
        }
    }

    /// Parse the signed data
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signed_data = data.read_size()?;
        add_space!(4);
        print_string!("size_signed_data: {}", size_signed_data);

        let data = &mut data.as_slice(size_signed_data)?;

        let digests = Digests::parse(data)?;
        let certificates = Certificates::parse(data)?;
        let additional_attributes = AdditionalAttributes::parse(data)?;

        Ok(Self {
            digests,
            certificates,
            additional_attributes,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.digests.to_u8(),
            self.certificates.to_u8(),
            self.additional_attributes.to_u8(),
        ]
        .concat();
        [(content.len() as u32).to_le_bytes().to_vec(), content].concat()
    }

    /// Size of the signed data
    pub fn size(&self) -> usize {
        self.digests.size
            + self.certificates.size
            + self.additional_attributes.size
            + mem::size_of::<u32>() * 3 // size prefixes for each component
    }
}

/// Configuration for Source Stamp signing
#[cfg(feature = "signing")]
pub struct SourceStampSignerConfig {
    /// The private key used for signing
    pub private_key: PrivateKey,
    /// The certificate (DER encoded)
    pub certificate: Vec<u8>,
    /// The signature algorithm to use
    pub algorithm: Algorithms,
    /// Whether to include timestamp attribute
    pub timestamp_enabled: bool,
}

#[cfg(feature = "signing")]
impl SourceStampSignerConfig {
    /// Create a new signer config
    pub const fn new(
        private_key: PrivateKey,
        certificate: Vec<u8>,
        algorithm: Algorithms,
        timestamp_enabled: bool,
    ) -> Self {
        Self {
            private_key,
            certificate,
            algorithm,
            timestamp_enabled,
        }
    }
}

/// Source Stamp Signer for generating signed Source Stamp blocks
#[cfg(feature = "signing")]
pub struct SourceStampSigner {
    /// Signer configuration
    config: SourceStampSignerConfig,
}

#[cfg(feature = "signing")]
impl SourceStampSigner {
    /// Create a new Source Stamp Signer
    pub const fn new(config: SourceStampSignerConfig) -> Self {
        Self { config }
    }

    /// Generate a signed Source Stamp block
    ///
    /// # Arguments
    /// * `digests` - The digests to include in the signed data
    ///
    /// # Returns
    /// A complete `SourceStamp` with signatures
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign(&self, digests: Digests) -> Result<SourceStamp, String> {
        // Create certificates from the signer's certificate
        let certificates = Certificates::new(vec![Certificate::new(self.config.certificate.clone())]);

        // Create additional attributes
        let mut additional_attrs_data = Vec::new();

        // Add timestamp attribute if enabled
        if self.config.timestamp_enabled {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("Failed to get timestamp: {}", e))?
                .as_secs();

            let mut timestamp_bytes = timestamp.to_le_bytes().to_vec();
            // Ensure we have exactly 8 bytes
            timestamp_bytes.resize(8, 0);

            additional_attrs_data.push(AdditionalAttribute {
                size: mem::size_of::<u32>() + timestamp_bytes.len(),
                id: STAMP_TIME_ATTR_ID,
                data: timestamp_bytes,
            });
        }

        let additional_attributes = AdditionalAttributes::new(additional_attrs_data);

        // Create signed data
        let signed_data = SignedData::new(digests, certificates, additional_attributes);

        // Get the raw bytes of signed data for signing (without the size prefix)
        let signed_data_bytes = signed_data.to_u8();
        // Skip the first 4 bytes (size prefix) when signing
        let data_to_sign = signed_data_bytes
            .get(4..)
            .ok_or("Invalid signed data")?;

        // Sign the data
        let signature_bytes = self.config.algorithm.sign(&self.config.private_key, data_to_sign)?;

        // Create signatures
        let signatures = Signatures::new(vec![Signature::new(
            self.config.algorithm.clone(),
            signature_bytes,
        )]);

        // Get public key
        let public_key_der = self.config.private_key.public_key_der()?;
        let public_key = PubKey::new(public_key_der);

        // Create stamp block
        let stamp_block = StampBlock::new(signed_data, signatures, public_key);

        // Create and return the source stamp
        Ok(SourceStamp::new(stamp_block))
    }

    /// Generate a signed Source Stamp block from raw digest data
    ///
    /// This is a convenience method that creates digests from algorithm-digest pairs
    ///
    /// # Arguments
    /// * `digest_pairs` - Vector of (algorithm, digest_bytes) pairs
    ///
    /// # Returns
    /// A complete `SourceStamp` with signatures
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_with_digests(&self, digest_pairs: Vec<(Algorithms, Vec<u8>)>) -> Result<SourceStamp, String> {
        let digests_data: Vec<Digest> = digest_pairs
            .into_iter()
            .map(|(algo, digest)| Digest::new(algo, digest))
            .collect();
        let digests = Digests::new(digests_data);
        self.sign(digests)
    }
}

/// Builder for creating Source Stamp Signer with optional configurations
#[cfg(feature = "signing")]
pub struct SourceStampSignerBuilder {
    /// The private key used for signing
    private_key: PrivateKey,
    /// The certificate (DER encoded)
    certificate: Vec<u8>,
    /// The signature algorithm to use
    algorithm: Algorithms,
    /// Whether to include timestamp attribute
    timestamp_enabled: bool,
}

#[cfg(feature = "signing")]
impl SourceStampSignerBuilder {
    /// Create a new builder with required parameters
    pub const fn new(private_key: PrivateKey, certificate: Vec<u8>, algorithm: Algorithms) -> Self {
        Self {
            private_key,
            certificate,
            algorithm,
            timestamp_enabled: true, // Default to enabled like Java implementation
        }
    }

    /// Set whether timestamp should be enabled
    pub const fn timestamp_enabled(mut self, enabled: bool) -> Self {
        self.timestamp_enabled = enabled;
        self
    }

    /// Build the SourceStampSigner
    pub fn build(self) -> SourceStampSigner {
        SourceStampSigner::new(SourceStampSignerConfig::new(
            self.private_key,
            self.certificate,
            self.algorithm,
            self.timestamp_enabled,
        ))
    }
}
