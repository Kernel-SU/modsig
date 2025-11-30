//! Certificate chain verification module
//!
//! This module provides certificate chain verification with support for
//! built-in trusted root certificates, digest verification, and multi-signer support.

use crate::signing_block::{SigningBlock, ValueSigningBlock};

#[cfg(feature = "verify")]
use x509_cert::der::Decode;

#[cfg(feature = "verify")]
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};

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
    /// Digest mismatch - stored digest doesn't match computed digest
    DigestMismatch,
    /// Certificate has expired
    CertificateExpired,
    /// Certificate is not yet valid
    CertificateNotYetValid,
    /// Certificate chain signature validation failed
    ChainSignatureInvalid(String),
    /// Multiple signers with at least one failure
    MultiSignerFailure(Vec<String>),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignature => write!(f, "No signature found"),
            Self::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            Self::CertificateError(e) => write!(f, "Certificate error: {}", e),
            Self::CertChainError(e) => write!(f, "Certificate chain error: {}", e),
            Self::UntrustedCertificate => write!(f, "Untrusted certificate"),
            Self::DigestMismatch => write!(f, "Digest mismatch: stored digest doesn't match computed file content"),
            Self::CertificateExpired => write!(f, "Certificate has expired"),
            Self::CertificateNotYetValid => write!(f, "Certificate is not yet valid"),
            Self::ChainSignatureInvalid(e) => write!(f, "Certificate chain signature invalid: {}", e),
            Self::MultiSignerFailure(errors) => {
                write!(f, "Multiple signer verification failed: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Result of verifying a single signer
#[derive(Debug, Default, Clone)]
pub struct SignerVerifyResult {
    /// Signer index (0-based)
    pub signer_index: usize,
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the digest matches computed content
    pub digest_valid: bool,
    /// Whether the certificate chain is valid (structure and signatures)
    pub cert_chain_valid: bool,
    /// Whether the certificate is trusted (signed by a trusted root)
    pub is_trusted: bool,
    /// The signing certificate in DER format
    pub certificate: Option<Vec<u8>>,
    /// Certificate chain (if present)
    pub cert_chain: Vec<Vec<u8>>,
    /// Warnings during verification
    pub warnings: Vec<String>,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Result of signature verification (aggregates all signers)
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// Results for each signer
    pub signers: Vec<SignerVerifyResult>,
    /// Overall signature validity (all signers must pass)
    pub signature_valid: bool,
    /// Overall digest validity (all signers must pass)
    pub digest_valid: bool,
    /// Overall certificate chain validity (all signers must pass)
    pub cert_chain_valid: bool,
    /// Overall trust status (all signers must be trusted)
    pub is_trusted: bool,
    /// The first signing certificate (for backwards compatibility)
    pub certificate: Option<Vec<u8>>,
    /// Certificate chain of first signer (for backwards compatibility)
    pub cert_chain: Vec<Vec<u8>>,
    /// All warnings from all signers
    pub warnings: Vec<String>,
}

/// Combined verification result for both V2 and Source Stamp
#[derive(Debug)]
pub struct VerifyAllResult {
    /// V2 verification result
    pub v2: Result<VerifyResult, VerifyError>,
    /// Source Stamp verification result
    pub source_stamp: Result<VerifyResult, VerifyError>,
}

impl VerifyAllResult {
    /// Check if all present signatures are fully verified
    ///
    /// Returns true only if all present signatures pass complete verification:
    /// - Signature is cryptographically valid
    /// - Certificate chain is valid
    /// - Certificate is trusted (signed by a trusted root)
    ///
    /// Blocks that are not present (NoSignature) are ignored.
    #[allow(clippy::missing_const_for_fn)] // matches! macro doesn't work in const context
    pub fn is_valid(&self) -> bool {
        let v2_ok = matches!(&self.v2, Ok(r) if r.signature_valid && r.cert_chain_valid && r.is_trusted)
            || matches!(&self.v2, Err(VerifyError::NoSignature));
        let stamp_ok = matches!(&self.source_stamp, Ok(r) if r.signature_valid && r.cert_chain_valid && r.is_trusted)
            || matches!(&self.source_stamp, Err(VerifyError::NoSignature));
        v2_ok && stamp_ok
    }

    /// Check if V2 signature exists (regardless of validity)
    #[allow(clippy::missing_const_for_fn)] // matches! macro doesn't work in const context
    pub fn has_v2(&self) -> bool {
        !matches!(&self.v2, Err(VerifyError::NoSignature))
    }

    /// Check if Source Stamp exists (regardless of validity)
    #[allow(clippy::missing_const_for_fn)] // matches! macro doesn't work in const context
    pub fn has_source_stamp(&self) -> bool {
        !matches!(&self.source_stamp, Err(VerifyError::NoSignature))
    }

    /// Get V2 error if present
    pub fn v2_error(&self) -> Option<&VerifyError> {
        self.v2.as_ref().err()
    }

    /// Get Source Stamp error if present
    pub fn source_stamp_error(&self) -> Option<&VerifyError> {
        self.source_stamp.as_ref().err()
    }
}

impl VerifyResult {
    /// Create a new VerifyResult from signer results
    fn from_signers(signers: Vec<SignerVerifyResult>) -> Self {
        if signers.is_empty() {
            return Self::default();
        }

        // All signers must pass for overall success (strict mode)
        let signature_valid = signers.iter().all(|s| s.signature_valid);
        let digest_valid = signers.iter().all(|s| s.digest_valid);
        let cert_chain_valid = signers.iter().all(|s| s.cert_chain_valid);
        let is_trusted = signers.iter().all(|s| s.is_trusted);

        // Backwards compatibility: use first signer's certificate
        let certificate = signers.first().and_then(|s| s.certificate.clone());
        let cert_chain = signers.first().map(|s| s.cert_chain.clone()).unwrap_or_default();

        // Collect all warnings
        let warnings: Vec<String> = signers
            .iter()
            .enumerate()
            .flat_map(|(idx, s)| {
                s.warnings
                    .iter()
                    .map(move |w| format!("Signer #{}: {}", idx + 1, w))
            })
            .collect();

        Self {
            signers,
            signature_valid,
            digest_valid,
            cert_chain_valid,
            is_trusted,
            certificate,
            cert_chain,
            warnings,
        }
    }
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
    #[cfg(feature = "verify")]
    /// Parsed trust anchors for webpki verification
    trust_anchors: Vec<TrustAnchor<'static>>,
}

impl Default for TrustedRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedRoots {
    /// Create an empty trusted roots store
    pub const fn new() -> Self {
        Self {
            roots: Vec::new(),
            #[cfg(feature = "verify")]
            trust_anchors: Vec::new(),
        }
    }

    /// Create with built-in KSU root certificates
    ///
    /// This includes the official KernelSU Root CA P-384 certificate
    /// for verifying signed modules.
    ///
    /// Note: Requires either `keystore` or `verify` feature to be enabled.
    /// When neither is enabled, returns an empty trusted roots store.
    #[cfg(any(feature = "keystore", feature = "verify"))]
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

    /// Create with built-in KSU root certificates (fallback when neither keystore nor verify feature is enabled)
    #[cfg(not(any(feature = "keystore", feature = "verify")))]
    pub fn with_builtin() -> Self {
        Self::new()
    }

    /// Add a trusted root certificate (DER format)
    #[cfg(feature = "verify")]
    pub fn add_root(&mut self, cert_der: Vec<u8>) {
        // Try to create a trust anchor from the certificate
        if let Ok(anchor) = webpki::anchor_from_trusted_cert(&CertificateDer::from(cert_der.clone())) {
            self.trust_anchors.push(anchor.to_owned());
        }
        self.roots.push(cert_der);
    }

    /// Add a trusted root certificate (DER format) - fallback without verify feature
    #[cfg(not(feature = "verify"))]
    pub fn add_root(&mut self, cert_der: Vec<u8>) {
        self.roots.push(cert_der);
    }

    /// Add a trusted root certificate from PEM format
    ///
    /// # Errors
    /// Returns an error if PEM parsing fails
    #[cfg(any(feature = "keystore", feature = "verify"))]
    pub fn add_root_pem(&mut self, pem_data: &[u8]) -> Result<(), String> {
        let pem = pem::parse(pem_data).map_err(|e| format!("Failed to parse PEM: {}", e))?;
        if pem.tag() != "CERTIFICATE" {
            return Err(format!("Expected CERTIFICATE, got {}", pem.tag()));
        }
        self.add_root(pem.into_contents());
        Ok(())
    }

    /// Check if a certificate is directly in the trusted roots (by DER equality)
    pub fn is_direct_root(&self, cert_der: &[u8]) -> bool {
        self.roots.iter().any(|root| root == cert_der)
    }

    /// Get all root certificates
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// Check if roots store is empty
    pub const fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Get trust anchors for webpki verification
    #[cfg(feature = "verify")]
    pub fn trust_anchors(&self) -> &[TrustAnchor<'static>] {
        &self.trust_anchors
    }
}

/// Certificate chain verifier using rustls-webpki
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

    /// Verify a certificate chain using webpki
    ///
    /// This method performs complete certificate chain verification:
    /// 1. Validates certificate signatures in the chain
    /// 2. Checks certificate validity periods
    /// 3. Verifies the chain leads to a trusted root
    ///
    /// # Arguments
    /// * `end_entity` - The end-entity (leaf) certificate in DER format
    /// * `intermediates` - Intermediate certificates in the chain
    ///
    /// # Returns
    /// A tuple of (is_chain_valid, is_trusted, Option<error_message>)
    #[cfg(feature = "verify")]
    pub fn verify_chain(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> (bool, bool, Option<String>) {
        use webpki::{EndEntityCert, ALL_VERIFICATION_ALGS};

        // If no trusted roots configured, we can only validate structure
        if self.trusted_roots.is_empty() {
            let chain_valid = self.validate_chain_structure(end_entity, intermediates);
            return (chain_valid, false, Some("No trusted roots configured".to_string()));
        }

        // Check if end entity is directly trusted (self-signed root)
        if self.trusted_roots.is_direct_root(end_entity) {
            return (true, true, None);
        }

        // Parse end-entity certificate
        let ee_der = CertificateDer::from(end_entity);
        let ee_cert = match EndEntityCert::try_from(&ee_der) {
            Ok(cert) => cert,
            Err(e) => {
                return (false, false, Some(format!("Failed to parse end-entity certificate: {:?}", e)));
            }
        };

        // Convert intermediates to CertificateDer
        let intermediate_certs: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect();

        // Get current time for validity check (seconds since Unix epoch)
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ));

        // Verify certificate chain with codeSigning EKU requirement
        let result = ee_cert.verify_for_usage(
            ALL_VERIFICATION_ALGS,
            self.trusted_roots.trust_anchors(),
            &intermediate_certs,
            now,
            &webpki::ExtendedKeyUsage::code_signing(),
            None, // No CRL checking
            None, // No verify_path callback
        );

        match result {
            Ok(_) => (true, true, None),
            Err(webpki::Error::CertExpired { .. }) => {
                (false, false, Some("Certificate has expired".to_string()))
            }
            Err(webpki::Error::CertNotValidYet { .. }) => {
                (false, false, Some("Certificate is not yet valid".to_string()))
            }
            Err(webpki::Error::UnknownIssuer) => {
                // Chain structure might be valid but not trusted
                let chain_valid = self.validate_chain_structure(end_entity, intermediates);
                (chain_valid, false, Some("Unknown issuer - certificate not signed by trusted root".to_string()))
            }
            Err(webpki::Error::RequiredEkuNotFound(_)) => {
                (false, false, Some("Certificate does not have codeSigning EKU".to_string()))
            }
            Err(e) => {
                (false, false, Some(format!("Chain verification failed: {:?}", e)))
            }
        }
    }

    /// Verify a certificate chain (fallback without verify feature)
    #[cfg(not(feature = "verify"))]
    pub fn verify_chain(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> (bool, bool, Option<String>) {
        // Without verify feature, we can only do basic checks
        if self.trusted_roots.is_empty() {
            return (true, false, Some("No trusted roots configured".to_string()));
        }

        // Check if end entity is directly trusted
        if self.trusted_roots.is_direct_root(end_entity) {
            return (true, true, None);
        }

        // Check if any intermediate is trusted
        for intermediate in intermediates {
            if self.trusted_roots.is_direct_root(intermediate) {
                return (true, true, None);
            }
        }

        (true, false, Some("Certificate not in trusted roots".to_string()))
    }

    /// Validate the structure of a certificate chain (issuer/subject matching)
    #[cfg(feature = "verify")]
    fn validate_chain_structure(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> bool {
        use x509_cert::Certificate;

        // If no intermediates, accept (could be self-signed or signed by unknown CA)
        if intermediates.is_empty() {
            return true;
        }

        // Parse end-entity certificate
        let end_cert = match Certificate::from_der(end_entity) {
            Ok(cert) => cert,
            Err(_) => return false,
        };

        let mut current_cert = end_cert;

        // Verify each link in the chain
        for intermediate_der in intermediates {
            let intermediate_cert = match Certificate::from_der(intermediate_der) {
                Ok(cert) => cert,
                Err(_) => return false,
            };

            // Check issuer/subject matching
            if current_cert.tbs_certificate.issuer != intermediate_cert.tbs_certificate.subject {
                return false;
            }

            current_cert = intermediate_cert;
        }

        true
    }

    /// Validate chain structure (fallback without verify feature)
    #[cfg(not(feature = "verify"))]
    fn validate_chain_structure(&self, _end_entity: &[u8], _intermediates: &[Vec<u8>]) -> bool {
        true
    }

    /// Get the trusted roots
    pub const fn trusted_roots(&self) -> &TrustedRoots {
        &self.trusted_roots
    }
}

/// Digest verification context
///
/// Provides the computed digests for verifying against stored digests in the signing block.
#[derive(Debug, Clone, Default)]
pub struct DigestContext {
    /// Computed digests keyed by algorithm ID
    pub digests: std::collections::HashMap<u32, Vec<u8>>,
}

impl DigestContext {
    /// Create a new digest context
    pub fn new() -> Self {
        Self {
            digests: std::collections::HashMap::new(),
        }
    }

    /// Add a computed digest for an algorithm
    pub fn add_digest(&mut self, algo_id: u32, digest: Vec<u8>) {
        self.digests.insert(algo_id, digest);
    }

    /// Get computed digest for an algorithm
    pub fn get_digest(&self, algo_id: u32) -> Option<&Vec<u8>> {
        self.digests.get(&algo_id)
    }

    /// Check if a stored digest matches the computed digest
    pub fn verify_digest(&self, algo_id: u32, stored_digest: &[u8]) -> bool {
        self.digests
            .get(&algo_id)
            .is_some_and(|computed| computed.as_slice() == stored_digest)
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

    /// Verify a V2 signature block with digest verification
    ///
    /// This method verifies ALL signers and checks digests against computed values.
    ///
    /// # Arguments
    /// * `signing_block` - The signing block to verify
    /// * `digest_context` - Optional computed digests for content verification
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails (any signer fails = overall failure)
    pub fn verify_v2_with_digest(
        &self,
        signing_block: &SigningBlock,
        digest_context: Option<&DigestContext>,
    ) -> Result<VerifyResult, VerifyError> {
        let mut signer_results = Vec::new();

        for block in &signing_block.content {
            if let ValueSigningBlock::SignatureSchemeV2Block(v2) = block {
                // Verify ALL signers (not just the first one)
                for (signer_idx, signer) in v2.signers.signers_data.iter().enumerate() {
                    let mut signer_result = SignerVerifyResult {
                        signer_index: signer_idx,
                        ..Default::default()
                    };

                    // Verify signature
                    let pubkey = &signer.pub_key.data;
                    let signed_data_bytes = signer.signed_data.to_u8();
                    let raw_data = match signed_data_bytes.get(4..) {
                        Some(data) => data,
                        None => {
                            signer_result.error = Some("Invalid signed data".to_string());
                            signer_results.push(signer_result);
                            continue;
                        }
                    };

                    // Verify each signature
                    let mut sig_valid = true;
                    for sig in signer.signatures.signatures_data.iter() {
                        let algo = &sig.signature_algorithm_id;

                        // Find the digest by algorithm ID instead of by index
                        // This ensures correct matching when digest/signature order differs
                        let digest = signer
                            .signed_data
                            .digests
                            .digests_data
                            .iter()
                            .find(|d| d.signature_algorithm_id == *algo);

                        let digest = match digest {
                            Some(d) => d,
                            None => {
                                signer_result.warnings.push(format!(
                                    "No digest found for algorithm {}",
                                    algo
                                ));
                                sig_valid = false;
                                break;
                            }
                        };

                        // Verify signature
                        if let Err(e) = algo.verify(pubkey, raw_data, &sig.signature) {
                            signer_result.error = Some(format!("Signature verification failed: {}", e));
                            sig_valid = false;
                            break;
                        }

                        // Verify digest against computed content (if provided)
                        if let Some(ctx) = digest_context {
                            let algo_id = algo.to_u32();
                            if !ctx.verify_digest(algo_id, &digest.digest) {
                                signer_result.error = Some("Digest mismatch: stored digest doesn't match computed file content".to_string());
                                signer_result.digest_valid = false;
                            } else {
                                signer_result.digest_valid = true;
                            }
                        } else {
                            // No digest context provided - content integrity NOT verified
                            // Security: digest_valid must be false when content is not verified
                            signer_result.digest_valid = false;
                            signer_result.warnings.push("Content integrity NOT verified: no computed digest provided. Use verify_v2_with_digest for full verification.".to_string());
                        }
                    }

                    signer_result.signature_valid = sig_valid && signer_result.error.is_none();

                    // Get certificate and verify chain
                    if let Some(cert) = signer.signed_data.certificates.certificates_data.first() {
                        signer_result.certificate = Some(cert.certificate.clone());

                        let intermediates: Vec<Vec<u8>> = signer
                            .signed_data
                            .certificates
                            .certificates_data
                            .iter()
                            .skip(1)
                            .map(|c| c.certificate.clone())
                            .collect();
                        signer_result.cert_chain = intermediates.clone();

                        // Verify certificate chain
                        let (chain_valid, is_trusted, chain_error) = self
                            .cert_verifier
                            .verify_chain(&cert.certificate, &intermediates);

                        signer_result.cert_chain_valid = chain_valid;
                        signer_result.is_trusted = is_trusted;

                        if let Some(err) = chain_error {
                            signer_result.warnings.push(err);
                        }
                    }

                    signer_results.push(signer_result);
                }
            }
        }

        if signer_results.is_empty() {
            return Err(VerifyError::NoSignature);
        }

        // Check for any failures (strict mode: any failure = overall failure)
        let failures: Vec<String> = signer_results
            .iter()
            .filter_map(|s| s.error.clone())
            .collect();

        if !failures.is_empty() {
            return Err(VerifyError::MultiSignerFailure(failures));
        }

        Ok(VerifyResult::from_signers(signer_results))
    }

    /// Verify a Source Stamp block with digest verification
    ///
    /// This method verifies the Source Stamp signature AND checks that the stored
    /// digests match the computed content digests.
    ///
    /// # Arguments
    /// * `signing_block` - The signing block containing the Source Stamp
    /// * `digest_context` - Optional computed digests for content verification
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_source_stamp_with_digest(
        &self,
        signing_block: &SigningBlock,
        digest_context: Option<&DigestContext>,
    ) -> Result<VerifyResult, VerifyError> {
        let mut signer_results = Vec::new();

        for block in &signing_block.content {
            if let ValueSigningBlock::SourceStampBlock(stamp) = block {
                let stamp_block = &stamp.stamp_block;
                let mut signer_result = SignerVerifyResult {
                    signer_index: 0,
                    ..Default::default()
                };

                // Get the public key
                let pubkey = &stamp_block.public_key.data;

                // Get signed data bytes
                let signed_data_bytes = stamp_block.signed_data.to_u8();
                let raw_data = match signed_data_bytes.get(4..) {
                    Some(data) => data,
                    None => {
                        signer_result.error = Some("Invalid signed data".to_string());
                        signer_results.push(signer_result);
                        continue;
                    }
                };

                // Verify each signature and digest
                let mut sig_valid = true;
                let mut digest_verified = false;

                for sig in &stamp_block.signatures.signatures_data {
                    let algo = &sig.signature_algorithm_id;

                    // Verify signature
                    if let Err(e) = algo.verify(pubkey, raw_data, &sig.signature) {
                        signer_result.error = Some(format!("Signature verification failed: {}", e));
                        sig_valid = false;
                        break;
                    }

                    // Find and verify digest by algorithm ID (like V2 verification)
                    let digest = stamp_block
                        .signed_data
                        .digests
                        .digests_data
                        .iter()
                        .find(|d| d.signature_algorithm_id == *algo);

                    if let Some(digest_entry) = digest {
                        // Verify digest against computed content (if provided)
                        if let Some(ctx) = digest_context {
                            let algo_id = algo.to_u32();
                            if !ctx.verify_digest(algo_id, &digest_entry.digest) {
                                signer_result.error = Some("Source Stamp digest mismatch: stored digest doesn't match computed file content".to_string());
                                signer_result.digest_valid = false;
                            } else {
                                signer_result.digest_valid = true;
                                digest_verified = true;
                            }
                        }
                    }
                }

                // If no digest context provided, content integrity is NOT verified
                if digest_context.is_none() {
                    signer_result.digest_valid = false;
                    signer_result.warnings.push(
                        "Source Stamp content integrity NOT verified: no computed digest provided."
                            .to_string(),
                    );
                } else if !digest_verified && signer_result.error.is_none() {
                    // Digest context was provided but no matching digest found
                    signer_result.digest_valid = false;
                    signer_result.warnings.push(
                        "No matching digest found in Source Stamp for verification.".to_string(),
                    );
                }

                signer_result.signature_valid = sig_valid && signer_result.error.is_none();

                // Get certificate
                if let Some(cert) = stamp_block
                    .signed_data
                    .certificates
                    .certificates_data
                    .first()
                {
                    signer_result.certificate = Some(cert.certificate.clone());

                    // Verify certificate (no chain for source stamp typically)
                    let (chain_valid, is_trusted, chain_error) =
                        self.cert_verifier.verify_chain(&cert.certificate, &[]);
                    signer_result.cert_chain_valid = chain_valid;
                    signer_result.is_trusted = is_trusted;

                    if let Some(err) = chain_error {
                        signer_result.warnings.push(err);
                    }
                }

                signer_results.push(signer_result);
                break; // Only process first source stamp
            }
        }

        if signer_results.is_empty() {
            return Err(VerifyError::NoSignature);
        }

        // Check for any failures
        let failures: Vec<String> = signer_results
            .iter()
            .filter_map(|s| s.error.clone())
            .collect();

        if !failures.is_empty() {
            return Err(VerifyError::MultiSignerFailure(failures));
        }

        Ok(VerifyResult::from_signers(signer_results))
    }

    /// Verify a Source Stamp block (without digest verification)
    ///
    /// **Warning**: This method only verifies the signature, NOT the content integrity.
    /// For full verification including digest checks, use `verify_source_stamp_with_digest`.
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_source_stamp(
        &self,
        signing_block: &SigningBlock,
    ) -> Result<VerifyResult, VerifyError> {
        // Call the full verification without digest context
        // This will set digest_valid = false and add a warning
        self.verify_source_stamp_with_digest(signing_block, None)
    }

    /// Verify both V2 and Source Stamp with digest verification
    ///
    /// This method preserves full error information for both signature types,
    /// allowing callers to distinguish between "signature not present" and
    /// "signature verification failed".
    ///
    /// # Arguments
    /// * `signing_block` - The signing block to verify
    /// * `digest_context` - Optional computed digests for content verification
    ///
    /// # Returns
    /// A `VerifyAllResult` containing results for both V2 and Source Stamp
    pub fn verify_all_with_digest(
        &self,
        signing_block: &SigningBlock,
        digest_context: Option<&DigestContext>,
    ) -> VerifyAllResult {
        VerifyAllResult {
            v2: self.verify_v2_with_digest(signing_block, digest_context),
            source_stamp: self.verify_source_stamp_with_digest(signing_block, digest_context),
        }
    }
}

/// Quick verification with digest context
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_with_digest(
    signing_block: &SigningBlock,
    digest_context: &DigestContext,
) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_builtin_roots();
    verifier.verify_v2_with_digest(signing_block, Some(digest_context))
}

/// Quick verification with custom roots and digest context
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_with_roots_and_digest(
    signing_block: &SigningBlock,
    roots: TrustedRoots,
    digest_context: &DigestContext,
) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_trusted_roots(roots);
    verifier.verify_v2_with_digest(signing_block, Some(digest_context))
}
