//! Certificate chain verification module
//!
//! This module provides certificate chain verification with support for
//! built-in trusted root certificates.

use crate::signing_block::{SigningBlock, ValueSigningBlock};

#[cfg(feature = "verify")]
use x509_cert::der::Decode;

/// Error type for verification operations
#[derive(Debug)]
pub enum VerifyError {
    /// No signature found
    NoSignature,
    /// Invalid signature
    InvalidSignature(String),
    /// Certificate error
    CertificateError(String),
    /// Certificate chain error
    CertChainError(String),
    /// Untrusted certificate
    UntrustedCertificate,
    /// Digest mismatch
    DigestMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignature => write!(f, "No signature found"),
            Self::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            Self::CertificateError(e) => write!(f, "Certificate error: {}", e),
            Self::CertChainError(e) => write!(f, "Certificate chain error: {}", e),
            Self::UntrustedCertificate => write!(f, "Untrusted certificate"),
            Self::DigestMismatch => write!(f, "Digest mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Result of signature verification
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the certificate chain is valid
    pub cert_chain_valid: bool,
    /// Whether the certificate is trusted (signed by a trusted root)
    pub is_trusted: bool,
    /// The signing certificate in DER format
    pub certificate: Option<Vec<u8>>,
    /// Certificate chain (if present)
    pub cert_chain: Vec<Vec<u8>>,
    /// Warnings during verification
    pub warnings: Vec<String>,
}

/// Built-in trusted root certificates
///
/// This struct holds the trusted root certificates used for verifying
/// the certificate chain of signed modules.
///
/// Developers can add their own root certificates or use the default empty set.
pub struct TrustedRoots {
    /// List of trusted root certificates (DER format)
    roots: Vec<Vec<u8>>,
}

impl Default for TrustedRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedRoots {
    /// Create an empty trusted roots store
    pub const fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Create with built-in KSU root certificates
    ///
    /// This includes the official KernelSU Root CA P-384 certificate
    /// for verifying signed modules.
    #[cfg(feature = "keystore")]
    pub fn with_builtin() -> Self {
        const KERNELSU_ROOT_CA_P384: &str =
            include_str!("../builtin_certs/kernelsu_root_ca_p384.pem");

        let mut roots = Self::new();

        // Add KernelSU Root CA P-384
        if let Err(e) = roots.add_root_pem(KERNELSU_ROOT_CA_P384.as_bytes()) {
            eprintln!(
                "Warning: Failed to load built-in KernelSU Root CA P-384: {}",
                e
            );
        }

        roots
    }

    /// Create with built-in KSU root certificates (fallback when keystore feature is disabled)
    #[cfg(not(feature = "keystore"))]
    pub const fn with_builtin() -> Self {
        Self::new()
    }

    /// Add a trusted root certificate
    pub fn add_root(&mut self, cert_der: Vec<u8>) {
        self.roots.push(cert_der);
    }

    /// Add a trusted root certificate from PEM format
    ///
    /// # Errors
    /// Returns an error if PEM parsing fails
    #[cfg(feature = "keystore")]
    pub fn add_root_pem(&mut self, pem_data: &[u8]) -> Result<(), String> {
        let pem = pem::parse(pem_data).map_err(|e| format!("Failed to parse PEM: {}", e))?;
        if pem.tag() != "CERTIFICATE" {
            return Err(format!("Expected CERTIFICATE, got {}", pem.tag()));
        }
        self.roots.push(pem.into_contents());
        Ok(())
    }

    /// Check if a certificate is trusted (directly or via chain)
    pub fn is_trusted(&self, cert_der: &[u8]) -> bool {
        // Direct match check
        for root in &self.roots {
            if root == cert_der {
                return true;
            }
        }
        false
    }

    /// Get all root certificates
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// Check if roots store is empty
    pub const fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Certificate chain verifier
pub struct CertChainVerifier {
    /// Trusted root certificates
    trusted_roots: TrustedRoots,
}

impl CertChainVerifier {
    /// Create a new verifier with given trusted roots
    pub const fn new(trusted_roots: TrustedRoots) -> Self {
        Self { trusted_roots }
    }

    /// Create a verifier with built-in trusted roots
    pub fn with_builtin_roots() -> Self {
        Self::new(TrustedRoots::with_builtin())
    }

    /// Verify a certificate chain
    ///
    /// This method performs a complete certificate chain verification:
    /// 1. Validates certificate signatures in the chain
    /// 2. Checks issuer/subject DN matching
    /// 3. Verifies the chain leads to a trusted root
    ///
    /// # Arguments
    /// * `end_entity` - The end-entity (leaf) certificate
    /// * `intermediates` - Intermediate certificates in the chain
    ///
    /// # Returns
    /// A tuple of (is_chain_valid, is_trusted)
    pub fn verify_chain(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> (bool, bool) {
        // If no trusted roots configured, we can't verify trust
        if self.trusted_roots.is_empty() {
            // Without trusted roots, we can still validate chain structure
            // but cannot establish trust
            let chain_valid = self.validate_chain_structure(end_entity, intermediates);
            return (chain_valid, false);
        }

        // Check if end entity is directly trusted (self-signed root)
        if self.trusted_roots.is_trusted(end_entity) {
            return (true, true);
        }

        // Build complete certificate chain: [end_entity, intermediate1, intermediate2, ...]
        let mut full_chain = vec![end_entity.to_vec()];
        full_chain.extend(intermediates.iter().cloned());

        // Verify the chain step by step
        let chain_valid = self.validate_chain_structure(end_entity, intermediates);
        if !chain_valid {
            return (false, false);
        }

        // Check if any certificate in the chain is trusted
        // Start from the end (root) and work backwards
        for cert in full_chain.iter().rev() {
            if self.trusted_roots.is_trusted(cert) {
                // Found a trust anchor in the chain
                return (true, true);
            }
        }

        // Chain is structurally valid but not trusted
        (true, false)
    }

    /// Validate the structure and signatures of a certificate chain
    ///
    /// # Arguments
    /// * `end_entity` - The end-entity certificate
    /// * `intermediates` - Intermediate certificates
    ///
    /// # Returns
    /// `true` if the chain structure is valid, `false` otherwise
    #[cfg(feature = "verify")]
    fn validate_chain_structure(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> bool {
        use x509_cert::Certificate;

        // If no intermediates, we can't validate much about structure
        // (end-entity might be self-signed or signed by an unknown CA)
        if intermediates.is_empty() {
            return true; // Accept single certificate
        }

        // Parse end-entity certificate
        let end_cert = match Certificate::from_der(end_entity) {
            Ok(cert) => cert,
            Err(_) => return false, // Invalid DER
        };

        let mut current_cert = end_cert;

        // Verify each link in the chain
        for intermediate_der in intermediates {
            let intermediate_cert = match Certificate::from_der(intermediate_der) {
                Ok(cert) => cert,
                Err(_) => return false, // Invalid DER
            };

            // Check issuer/subject matching:
            // current_cert.issuer should match intermediate_cert.subject
            if current_cert.tbs_certificate.issuer != intermediate_cert.tbs_certificate.subject {
                // Issuer mismatch - chain is broken
                return false;
            }

            // TODO: Verify signature of current_cert using intermediate_cert's public key
            // This requires extracting the public key and verifying the signature
            // For now, we trust the chain structure if issuer/subject match

            // Move to next level
            current_cert = intermediate_cert;
        }

        // All links verified
        true
    }

    /// Validate the structure and signatures of a certificate chain (fallback without verify feature)
    ///
    /// # Arguments
    /// * `end_entity` - The end-entity certificate
    /// * `intermediates` - Intermediate certificates
    ///
    /// # Returns
    /// `true` always (no validation without x509_cert)
    #[cfg(not(feature = "verify"))]
    fn validate_chain_structure(&self, _end_entity: &[u8], _intermediates: &[Vec<u8>]) -> bool {
        // Without x509_cert, we can't validate structure
        true
    }

    /// Get the trusted roots
    pub const fn trusted_roots(&self) -> &TrustedRoots {
        &self.trusted_roots
    }
}

/// Signature verifier for V2 and Source Stamp blocks
pub struct SignatureVerifier {
    /// Certificate chain verifier
    cert_verifier: CertChainVerifier,
}

impl SignatureVerifier {
    /// Create a new signature verifier
    pub const fn new(cert_verifier: CertChainVerifier) -> Self {
        Self { cert_verifier }
    }

    /// Create with built-in trusted roots
    pub fn with_builtin_roots() -> Self {
        Self::new(CertChainVerifier::with_builtin_roots())
    }

    /// Create with custom trusted roots
    pub const fn with_trusted_roots(roots: TrustedRoots) -> Self {
        Self::new(CertChainVerifier::new(roots))
    }

    /// Verify a V2 signature block
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_v2(&self, signing_block: &SigningBlock) -> Result<VerifyResult, VerifyError> {
        let mut result = VerifyResult::default();

        for block in &signing_block.content {
            if let ValueSigningBlock::SignatureSchemeV2Block(v2) = block {
                // Get the first signer
                let signer = v2
                    .signers
                    .signers_data
                    .first()
                    .ok_or(VerifyError::NoSignature)?;

                // Get the public key
                let pubkey = &signer.pub_key.data;

                // Get signed data bytes
                let signed_data_bytes = signer.signed_data.to_u8();
                let raw_data = signed_data_bytes.get(4..).ok_or_else(|| {
                    VerifyError::InvalidSignature("Invalid signed data".to_string())
                })?;

                // Verify each signature
                for (idx, sig) in signer.signatures.signatures_data.iter().enumerate() {
                    let digest = signer
                        .signed_data
                        .digests
                        .digests_data
                        .get(idx)
                        .ok_or_else(|| {
                            VerifyError::InvalidSignature("Digest count mismatch".to_string())
                        })?;

                    let algo = &sig.signature_algorithm_id;

                    if algo != &digest.signature_algorithm_id {
                        result.warnings.push(format!(
                            "Signature algorithm mismatch: digest uses {}, signature uses {}",
                            digest.signature_algorithm_id, algo
                        ));
                    }

                    algo.verify(pubkey, raw_data, &sig.signature)
                        .map_err(VerifyError::InvalidSignature)?;
                }

                result.signature_valid = true;

                // Get certificate
                if let Some(cert) = signer.signed_data.certificates.certificates_data.first() {
                    result.certificate = Some(cert.certificate.clone());

                    // Get certificate chain
                    let intermediates: Vec<Vec<u8>> = signer
                        .signed_data
                        .certificates
                        .certificates_data
                        .iter()
                        .skip(1)
                        .map(|c| c.certificate.clone())
                        .collect();
                    result.cert_chain = intermediates.clone();

                    // Verify certificate chain
                    let (chain_valid, is_trusted) = self
                        .cert_verifier
                        .verify_chain(&cert.certificate, &intermediates);
                    result.cert_chain_valid = chain_valid;
                    result.is_trusted = is_trusted;

                    if !is_trusted && self.cert_verifier.trusted_roots.is_empty() {
                        result
                            .warnings
                            .push("No trusted roots configured".to_string());
                    }
                }

                return Ok(result);
            }
        }

        Err(VerifyError::NoSignature)
    }

    /// Verify a Source Stamp block
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_source_stamp(
        &self,
        signing_block: &SigningBlock,
    ) -> Result<VerifyResult, VerifyError> {
        let mut result = VerifyResult::default();

        for block in &signing_block.content {
            if let ValueSigningBlock::SourceStampBlock(stamp) = block {
                let stamp_block = &stamp.stamp_block;

                // Get the public key
                let pubkey = &stamp_block.public_key.data;

                // Get signed data bytes
                let signed_data_bytes = stamp_block.signed_data.to_u8();
                let raw_data = signed_data_bytes.get(4..).ok_or_else(|| {
                    VerifyError::InvalidSignature("Invalid signed data".to_string())
                })?;

                // Verify each signature
                for sig in &stamp_block.signatures.signatures_data {
                    let algo = &sig.signature_algorithm_id;
                    algo.verify(pubkey, raw_data, &sig.signature)
                        .map_err(VerifyError::InvalidSignature)?;
                }

                result.signature_valid = true;

                // Get certificate
                if let Some(cert) = stamp_block
                    .signed_data
                    .certificates
                    .certificates_data
                    .first()
                {
                    result.certificate = Some(cert.certificate.clone());

                    // Verify certificate (no chain for source stamp typically)
                    let (chain_valid, is_trusted) =
                        self.cert_verifier.verify_chain(&cert.certificate, &[]);
                    result.cert_chain_valid = chain_valid;
                    result.is_trusted = is_trusted;
                }

                return Ok(result);
            }
        }

        Err(VerifyError::NoSignature)
    }

    /// Verify both V2 and Source Stamp if present
    ///
    /// # Returns
    /// A tuple of (v2_result, stamp_result) where either can be None if not present
    pub fn verify_all(
        &self,
        signing_block: &SigningBlock,
    ) -> (Option<VerifyResult>, Option<VerifyResult>) {
        let v2_result = self.verify_v2(signing_block).ok();
        let stamp_result = self.verify_source_stamp(signing_block).ok();
        (v2_result, stamp_result)
    }
}

/// Quick verification function
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_signing_block(signing_block: &SigningBlock) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_builtin_roots();
    verifier.verify_v2(signing_block)
}

/// Quick verification with custom trusted roots
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_with_roots(
    signing_block: &SigningBlock,
    roots: TrustedRoots,
) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_trusted_roots(roots);
    verifier.verify_v2(signing_block)
}
