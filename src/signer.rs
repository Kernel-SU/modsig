//! Unified signer module for V2 signature scheme and Source Stamp
//!
//! This module provides a high-level API for signing Module/APK files.

use crate::common::{
    AdditionalAttribute, AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey,
    Signature, Signatures,
};
use crate::signing_block::algorithms::{Algorithms, PrivateKey};
use crate::signing_block::scheme_v2::{SignatureSchemeV2, SignedData, Signer, Signers};
use crate::signing_block::source_stamp::{
    SignedData as SourceStampSignedData, SourceStamp, StampBlock, STAMP_TIME_ATTR_ID,
};
use crate::signing_block::{SigningBlock, ValueSigningBlock};
use std::mem;

#[cfg(feature = "keystore")]
use crate::keystore::SignerCredentials;

/// Configuration for module signing
pub struct ModuleSignerConfig {
    /// The private key for signing
    pub private_key: PrivateKey,
    /// The certificate (DER format)
    pub certificate: Vec<u8>,
    /// The signing algorithm
    pub algorithm: Algorithms,
    /// Optional certificate chain
    pub cert_chain: Vec<Vec<u8>>,
}

impl ModuleSignerConfig {
    /// Create a new signer config
    pub const fn new(private_key: PrivateKey, certificate: Vec<u8>, algorithm: Algorithms) -> Self {
        Self {
            private_key,
            certificate,
            algorithm,
            cert_chain: Vec::new(),
        }
    }

    /// Create config with certificate chain
    pub const fn with_cert_chain(
        private_key: PrivateKey,
        certificate: Vec<u8>,
        algorithm: Algorithms,
        cert_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            private_key,
            certificate,
            algorithm,
            cert_chain,
        }
    }

    /// Create from SignerCredentials (keystore module)
    #[cfg(feature = "keystore")]
    pub fn from_credentials(creds: SignerCredentials) -> Self {
        Self {
            private_key: creds.private_key,
            certificate: creds.certificate,
            algorithm: creds.algorithm,
            cert_chain: creds.cert_chain,
        }
    }
}

/// V2 Signature Scheme Signer
pub struct V2Signer {
    /// Signer configuration
    config: ModuleSignerConfig,
}

impl V2Signer {
    /// Create a new V2 signer
    pub const fn new(config: ModuleSignerConfig) -> Self {
        Self { config }
    }

    /// Sign digests and create a V2 signature block
    ///
    /// # Arguments
    /// * `digests` - The content digests to sign
    ///
    /// # Returns
    /// A `SignatureSchemeV2` block ready to be included in the signing block
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign(&self, digests: Digests) -> Result<SignatureSchemeV2, String> {
        // Create certificates list
        let mut certs_data = vec![Certificate::new(self.config.certificate.clone())];
        for chain_cert in &self.config.cert_chain {
            certs_data.push(Certificate::new(chain_cert.clone()));
        }
        let certificates = Certificates::new(certs_data);

        // Empty additional attributes for V2
        let additional_attributes = AdditionalAttributes::new(Vec::new());

        // Create signed data
        let signed_data = SignedData::new(digests, certificates, additional_attributes);

        // Get the raw bytes of signed data for signing (without the size prefix)
        let signed_data_bytes = signed_data.to_u8();
        let data_to_sign = signed_data_bytes.get(4..).ok_or("Invalid signed data")?;

        // Sign the data
        let signature_bytes = self
            .config
            .algorithm
            .sign(&self.config.private_key, data_to_sign)?;

        // Create signature
        let signatures = Signatures::new(vec![Signature::new(
            self.config.algorithm.clone(),
            signature_bytes,
        )]);

        // Get public key
        let public_key_der = self.config.private_key.public_key_der()?;
        let pub_key = PubKey::new(public_key_der);

        // Create signer
        let signer = Signer::new(signed_data, signatures, pub_key);

        // Create signers
        let signers = Signers::new(vec![signer]);

        // Create and return the V2 signature scheme
        Ok(SignatureSchemeV2::new(signers))
    }

    /// Sign with raw digest pairs
    ///
    /// # Arguments
    /// * `digest_pairs` - Vector of (algorithm, digest_bytes) pairs
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_with_digests(
        &self,
        digest_pairs: Vec<(Algorithms, Vec<u8>)>,
    ) -> Result<SignatureSchemeV2, String> {
        let digests_data: Vec<Digest> = digest_pairs
            .into_iter()
            .map(|(algo, digest)| Digest::new(algo, digest))
            .collect();
        let digests = Digests::new(digests_data);
        self.sign(digests)
    }
}

/// Source Stamp Signer with improved API
pub struct SourceStampSigner {
    /// Signer configuration
    config: ModuleSignerConfig,
    /// Whether to include timestamp
    timestamp_enabled: bool,
}

impl SourceStampSigner {
    /// Create a new source stamp signer
    pub const fn new(config: ModuleSignerConfig) -> Self {
        Self {
            config,
            timestamp_enabled: true,
        }
    }

    /// Create with timestamp option
    pub const fn with_timestamp(config: ModuleSignerConfig, timestamp_enabled: bool) -> Self {
        Self {
            config,
            timestamp_enabled,
        }
    }

    /// Sign digests and create a Source Stamp block
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign(&self, digests: Digests) -> Result<SourceStamp, String> {
        // Create certificates
        let certificates =
            Certificates::new(vec![Certificate::new(self.config.certificate.clone())]);

        // Create additional attributes
        let mut additional_attrs_data = Vec::new();

        if self.timestamp_enabled {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("Failed to get timestamp: {}", e))?
                .as_secs();

            let timestamp_bytes = timestamp.to_le_bytes().to_vec();
            additional_attrs_data.push(AdditionalAttribute {
                size: mem::size_of::<u32>() + timestamp_bytes.len(),
                id: STAMP_TIME_ATTR_ID,
                data: timestamp_bytes,
            });
        }

        let additional_attributes = AdditionalAttributes::new(additional_attrs_data);

        // Create signed data
        let signed_data = SourceStampSignedData::new(digests, certificates, additional_attributes);

        // Get the raw bytes of signed data for signing
        let signed_data_bytes = signed_data.to_u8();
        let data_to_sign = signed_data_bytes.get(4..).ok_or("Invalid signed data")?;

        // Sign the data
        let signature_bytes = self
            .config
            .algorithm
            .sign(&self.config.private_key, data_to_sign)?;

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

        Ok(SourceStamp::new(stamp_block))
    }

    /// Sign with raw digest pairs
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_with_digests(
        &self,
        digest_pairs: Vec<(Algorithms, Vec<u8>)>,
    ) -> Result<SourceStamp, String> {
        let digests_data: Vec<Digest> = digest_pairs
            .into_iter()
            .map(|(algo, digest)| Digest::new(algo, digest))
            .collect();
        let digests = Digests::new(digests_data);
        self.sign(digests)
    }
}

/// Combined module signer that can sign both V2 and Source Stamp
pub struct ModuleSigner {
    /// V2 signer config
    v2_config: Option<ModuleSignerConfig>,
    /// Source stamp signer config
    stamp_config: Option<ModuleSignerConfig>,
    /// Whether to include timestamp in source stamp
    timestamp_enabled: bool,
    /// Whether to add 4K alignment padding (Verity padding)
    padding_enabled: bool,
}

impl ModuleSigner {
    /// Create a new module signer with V2 signing only
    pub const fn v2_only(config: ModuleSignerConfig) -> Self {
        Self {
            v2_config: Some(config),
            stamp_config: None,
            timestamp_enabled: true,
            padding_enabled: true,
        }
    }

    /// Create a new module signer with both V2 and Source Stamp
    pub const fn with_source_stamp(
        v2_config: ModuleSignerConfig,
        stamp_config: ModuleSignerConfig,
    ) -> Self {
        Self {
            v2_config: Some(v2_config),
            stamp_config: Some(stamp_config),
            timestamp_enabled: true,
            padding_enabled: true,
        }
    }

    /// Create a new module signer with Source Stamp only (for re-signing)
    pub const fn stamp_only(stamp_config: ModuleSignerConfig) -> Self {
        Self {
            v2_config: None,
            stamp_config: Some(stamp_config),
            timestamp_enabled: true,
            padding_enabled: true,
        }
    }

    /// Set timestamp option for source stamp
    pub const fn timestamp_enabled(mut self, enabled: bool) -> Self {
        self.timestamp_enabled = enabled;
        self
    }

    /// Set 4K alignment padding option (Verity padding)
    ///
    /// When enabled (default), the signing block will be padded to 4096 byte alignment.
    /// This is recommended for compatibility with tools that expect Verity padding.
    pub const fn padding_enabled(mut self, enabled: bool) -> Self {
        self.padding_enabled = enabled;
        self
    }

    /// Get all algorithms needed for signing
    ///
    /// Returns a list of unique algorithms required by all configured signers.
    /// This is useful for calculating the correct digests before signing.
    pub fn required_algorithms(&self) -> Vec<Algorithms> {
        let mut algos = Vec::new();
        if let Some(ref v2) = self.v2_config {
            algos.push(v2.algorithm.clone());
        }
        if let Some(ref stamp) = self.stamp_config {
            if !algos.contains(&stamp.algorithm) {
                algos.push(stamp.algorithm.clone());
            }
        }
        algos
    }

    /// Sign and generate a complete signing block
    ///
    /// # Arguments
    /// * `digests` - The content digests to include
    ///
    /// # Returns
    /// A complete `SigningBlock` ready to be inserted into the module file.
    /// If `padding_enabled` is true (default), the block will be padded to 4096 byte alignment.
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign(&self, digests: Digests) -> Result<SigningBlock, String> {
        let mut blocks = Vec::new();

        // Sign with V2 if configured
        if let Some(ref v2_config) = self.v2_config {
            let v2_signer = V2Signer::new(ModuleSignerConfig {
                private_key: clone_private_key(&v2_config.private_key)?,
                certificate: v2_config.certificate.clone(),
                algorithm: v2_config.algorithm.clone(),
                cert_chain: v2_config.cert_chain.clone(),
            });
            let v2_block = v2_signer.sign(digests.clone())?;
            blocks.push(ValueSigningBlock::SignatureSchemeV2Block(v2_block));
        }

        // Sign source stamp if configured
        if let Some(ref stamp_config) = self.stamp_config {
            let stamp_signer = SourceStampSigner::with_timestamp(
                ModuleSignerConfig {
                    private_key: clone_private_key(&stamp_config.private_key)?,
                    certificate: stamp_config.certificate.clone(),
                    algorithm: stamp_config.algorithm.clone(),
                    cert_chain: stamp_config.cert_chain.clone(),
                },
                self.timestamp_enabled,
            );
            let stamp_block = stamp_signer.sign(digests)?;
            blocks.push(ValueSigningBlock::SourceStampBlock(stamp_block));
        }

        if blocks.is_empty() {
            return Err("No signing configuration provided".to_string());
        }

        // Use padding for 4K alignment if enabled (recommended for Verity compatibility)
        if self.padding_enabled {
            SigningBlock::new_with_padding(blocks)
                .map_err(|e| format!("Failed to create padded signing block: {}", e))
        } else {
            SigningBlock::new(blocks)
                .map_err(|e| format!("Failed to create signing block: {}", e))
        }
    }

    /// Add source stamp to an existing signing block
    ///
    /// This is useful for re-signing a module with a source stamp.
    /// The signing block will be rebuilt with proper 4K alignment padding
    /// if `padding_enabled` is true (default).
    ///
    /// # Arguments
    /// * `existing_block` - The existing signing block
    /// * `digests` - The content digests for the stamp
    ///
    /// # Errors
    /// Returns an error if no stamp config is set or signing fails
    pub fn add_source_stamp(
        &self,
        existing_block: SigningBlock,
        digests: Digests,
    ) -> Result<SigningBlock, String> {
        use crate::signing_block::VERITY_PADDING_BLOCK_ID;

        let stamp_config = self
            .stamp_config
            .as_ref()
            .ok_or("No source stamp configuration")?;

        let stamp_signer = SourceStampSigner::with_timestamp(
            ModuleSignerConfig {
                private_key: clone_private_key(&stamp_config.private_key)?,
                certificate: stamp_config.certificate.clone(),
                algorithm: stamp_config.algorithm.clone(),
                cert_chain: stamp_config.cert_chain.clone(),
            },
            self.timestamp_enabled,
        );

        let stamp_block = stamp_signer.sign(digests)?;

        // Collect all blocks except Source Stamp and Padding (we'll regenerate padding)
        let mut new_content: Vec<ValueSigningBlock> = existing_block
            .content
            .into_iter()
            .filter(|block| {
                !matches!(block, ValueSigningBlock::SourceStampBlock(_))
                    && block.id() != VERITY_PADDING_BLOCK_ID
            })
            .collect();

        // Add new source stamp
        new_content.push(ValueSigningBlock::SourceStampBlock(stamp_block));

        // Rebuild the signing block with proper padding if enabled
        if self.padding_enabled {
            SigningBlock::new_with_padding(new_content)
                .map_err(|e| format!("Failed to create padded signing block: {}", e))
        } else {
            SigningBlock::new(new_content)
                .map_err(|e| format!("Failed to create signing block: {}", e))
        }
    }
}

/// Clone a private key (workaround since PrivateKey doesn't implement Clone)
/// # Errors
/// Returns an error if the key cannot be cloned
fn clone_private_key(key: &PrivateKey) -> Result<PrivateKey, String> {
    match key {
        PrivateKey::EcdsaP256(k) => {
            let bytes = k.to_bytes();
            let new_key = p256::ecdsa::SigningKey::from_bytes(&bytes)
                .map_err(|e| format!("Failed to clone P256 key: {}", e))?;
            Ok(PrivateKey::EcdsaP256(new_key))
        }
        PrivateKey::EcdsaP384(k) => {
            let bytes = k.to_bytes();
            let new_key = p384::ecdsa::SigningKey::from_bytes(&bytes)
                .map_err(|e| format!("Failed to clone P384 key: {}", e))?;
            Ok(PrivateKey::EcdsaP384(new_key))
        }
    }
}
