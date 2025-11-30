//! Handling the Module file by providing methods as `Module` struct.

pub mod zip;

#[cfg(feature = "hash")]
pub mod digest;

use std::{
    fs::{read, File},
    io::{copy, Read, Seek, Write},
    path::PathBuf,
};

use crate::SigningBlock;
use zip::{find_eocd, EndOfCentralDirectoryRecord, FileOffsets};

#[cfg(feature = "hash")]
use crate::Algorithms;
#[cfg(feature = "hash")]
use digest::digest_module;

#[cfg(feature = "signing")]
use crate::ValueSigningBlock;

/// The `Module` struct represents the Module file.
#[derive(Default)]
pub struct Module {
    /// If the Module is raw (not signed)
    pub raw: bool,

    /// The path of the Module file.
    pub path: PathBuf,

    /// The length of the Module file.
    pub file_len: usize,

    /// The signing block of the Module file.
    pub sig: Option<SigningBlock>,
}

impl Module {
    /// Create a new Module file.
    /// # Errors
    /// Returns an error if the path is not found.
    pub fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = File::open(&path)?;
        let file_len = file.metadata()?.len() as usize;
        Ok(Self {
            path,
            file_len,
            ..Default::default()
        })
    }

    /// Create a new raw Module file.
    /// # Errors
    /// Returns an error if the path is not found.
    pub fn new_raw(path: PathBuf) -> Result<Self, std::io::Error> {
        Ok(Self {
            raw: true,
            ..Self::new(path)?
        })
    }

    /// Decode the signing block of the Module file.
    ///
    /// The signing block is located between the ZIP content and the Central Directory.
    /// This method first parses the EOCD to find the Central Directory offset,
    /// then searches for the signing block before that position.
    ///
    /// # Errors
    /// Returns a string if the decoding fails.
    pub fn get_signing_block(&self) -> Result<SigningBlock, std::io::Error> {
        match self.sig {
            Some(ref sig) => Ok(sig.clone()),
            None => {
                if self.raw {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Module is raw",
                    ));
                }

                // First, find the EOCD to locate the Central Directory
                // The signing block is located BEFORE the Central Directory, not at the file end
                // Structure: [ZIP Content] → [Signing Block] → [Central Directory] → [EOCD]
                let eocd = self.find_eocd()?;
                let cd_offset = eocd.cd_offset as usize;

                // Calculate end_offset: how far from file end is the Central Directory start
                // This tells from_reader to stop searching at the Central Directory position
                let end_offset = self.file_len.saturating_sub(cd_offset);

                let file = File::open(&self.path)?;
                let sig = SigningBlock::from_reader(file, self.file_len, end_offset)?;
                Ok(sig)
            }
        }
    }

    /// Fully verify the Module file including content integrity and certificate chain.
    ///
    /// This method performs complete verification of both V2 signature and Source Stamp:
    /// 1. Verifies the V2 cryptographic signature
    /// 2. Computes the module content digest and verifies it matches the stored digest
    /// 3. Validates the certificate chain (if `verify` feature is enabled)
    /// 4. Checks if the certificate is trusted (if trusted roots are provided)
    /// 5. Verifies the Source Stamp signature (if present)
    ///
    /// # Returns
    /// Returns `VerifyAllResult` containing verification results for both V2 and Source Stamp.
    /// Use `result.is_valid()` to check if all present signatures passed verification.
    #[cfg(feature = "signing")]
    #[cfg(feature = "hash")]
    pub fn verify_full(&self) -> crate::verifier::VerifyAllResult {
        use crate::verifier::{DigestContext, SignatureVerifier, VerifyAllResult, VerifyError};

        let signing_block = match self.get_signing_block() {
            Ok(block) => block,
            Err(e) => {
                return VerifyAllResult {
                    v2: Err(VerifyError::InvalidSignature(format!(
                        "Failed to get signing block: {}",
                        e
                    ))),
                    source_stamp: Err(VerifyError::NoSignature),
                };
            }
        };

        // Build digest context from computed digests
        let mut digest_context = DigestContext::new();

        // Find all algorithms used in the signing block and compute digests
        for block in &signing_block.content {
            if let ValueSigningBlock::SignatureSchemeV2Block(v2) = block {
                for signer in &v2.signers.signers_data {
                    for digest_entry in &signer.signed_data.digests.digests_data {
                        let algo = &digest_entry.signature_algorithm_id;
                        let algo_id = algo.to_u32();

                        // Only compute if not already present
                        if digest_context.get_digest(algo_id).is_none() {
                            if let Ok(computed) = self.digest(algo) {
                                digest_context.add_digest(algo_id, computed);
                            }
                        }
                    }
                }
            }
        }

        let verifier = SignatureVerifier::with_builtin_roots();
        verifier.verify_all_with_digest(&signing_block, Some(&digest_context))
    }

    /// Fully verify the Module file with custom trusted roots.
    ///
    /// This method performs complete verification of both V2 signature and Source Stamp
    /// with custom trusted root certificates.
    ///
    /// # Returns
    /// Returns `VerifyAllResult` containing verification results for both V2 and Source Stamp.
    /// Use `result.is_valid()` to check if all present signatures passed verification.
    #[cfg(feature = "signing")]
    #[cfg(feature = "hash")]
    pub fn verify_with_roots(
        &self,
        roots: crate::verifier::TrustedRoots,
    ) -> crate::verifier::VerifyAllResult {
        use crate::verifier::{DigestContext, SignatureVerifier, VerifyAllResult, VerifyError};

        let signing_block = match self.get_signing_block() {
            Ok(block) => block,
            Err(e) => {
                return VerifyAllResult {
                    v2: Err(VerifyError::InvalidSignature(format!(
                        "Failed to get signing block: {}",
                        e
                    ))),
                    source_stamp: Err(VerifyError::NoSignature),
                };
            }
        };

        // Build digest context from computed digests
        let mut digest_context = DigestContext::new();

        // Find all algorithms used in the signing block and compute digests
        for block in &signing_block.content {
            if let ValueSigningBlock::SignatureSchemeV2Block(v2) = block {
                for signer in &v2.signers.signers_data {
                    for digest_entry in &signer.signed_data.digests.digests_data {
                        let algo = &digest_entry.signature_algorithm_id;
                        let algo_id = algo.to_u32();

                        // Only compute if not already present
                        if digest_context.get_digest(algo_id).is_none() {
                            if let Ok(computed) = self.digest(algo) {
                                digest_context.add_digest(algo_id, computed);
                            }
                        }
                    }
                }
            }
        }

        let verifier = SignatureVerifier::with_trusted_roots(roots);
        verifier.verify_all_with_digest(&signing_block, Some(&digest_context))
    }

    /// find_eocd finds the End of Central Directory Record of the Module file.
    /// # Errors
    /// Returns a string if the End of Central Directory Record is not found.
    /// Or a problem occurs
    pub fn find_eocd(&self) -> Result<EndOfCentralDirectoryRecord, std::io::Error> {
        let mut file = File::open(&self.path)?;
        find_eocd(&mut file, self.file_len)
    }

    /// Get the offsets of the Module file.
    /// # Errors
    /// Returns an error if the offsets cannot be determined or if the signing block is corrupted.
    /// Note: A module without a signing block is handled normally (returns offsets without signature).
    /// However, a corrupted signing block will return an error.
    pub fn get_offsets(&self) -> Result<FileOffsets, std::io::Error> {
        let eocd = self.find_eocd()?;
        match self.get_signing_block() {
            Ok(sig) => {
                let file_len = if self.raw {
                    self.file_len + sig.get_full_size()
                } else {
                    self.file_len
                };
                let stop_cd = if self.raw {
                    eocd.file_offset + sig.get_full_size()
                } else {
                    eocd.file_offset
                };
                Ok(FileOffsets::new(
                    sig.file_offset_start,
                    sig.file_offset_end,
                    stop_cd,
                    file_len,
                ))
            }
            Err(e) => {
                // Distinguish between "no signature" and "corrupted signature"
                // "Magic not found" means no signing block exists - this is normal for unsigned modules
                // Other errors (InvalidData, IO errors) indicate corruption - propagate these
                let err_msg = e.to_string();
                if err_msg.contains("Magic not found") || err_msg.contains("Module is raw") {
                    // No signing block - normal case for unsigned modules
                    let stop_content = eocd.cd_offset as usize;
                    Ok(FileOffsets::without_signature(
                        stop_content,
                        eocd.file_offset,
                        self.file_len,
                    ))
                } else {
                    // Signing block exists but is corrupted or unreadable
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Signing block corrupted or unreadable: {}", e),
                    ))
                }
            }
        }
    }

    /// Calculate the digest of the Module file.
    /// # Errors
    /// Returns a string if the digest fails.
    #[cfg(feature = "hash")]
    pub fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, std::io::Error> {
        let mut file = File::open(&self.path)?;
        let offsets = self.get_offsets()?;
        digest_module(&mut file, &offsets, algo)
    }

    /// Get the raw Module file.
    /// # Errors
    /// Returns a string if the raw Module file fails.
    pub fn get_raw_module(&self) -> Result<Vec<u8>, std::io::Error> {
        let full_raw_file = read(&self.path)?;

        if self.raw {
            return Ok(full_raw_file);
        }

        let sig = self.get_signing_block()?;

        let start_sig = sig.file_offset_start;
        let end_sig = sig.file_offset_end;
        let size_sig = end_sig - start_sig;

        let start_without_sig = match full_raw_file.get(..start_sig) {
            Some(data) => data,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid start signature",
                ))
            }
        };
        let mut eocd = self.find_eocd()?;
        eocd.cd_offset = eocd.cd_offset.checked_sub(size_sig as u32).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signing block: signature size exceeds central directory offset",
            )
        })?;

        let eocd_serialized = eocd.to_u8();

        let end_without_sig =
            match full_raw_file.get(end_sig..(full_raw_file.len() - eocd_serialized.len())) {
                Some(data) => data,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid end signature",
                    ))
                }
            };

        let module_without_signature =
            [start_without_sig, end_without_sig, &eocd_serialized].concat();

        Ok(module_without_signature)
    }

    /// Write the Module file with the signature.
    /// # Errors
    /// Returns a string if the writing fails.
    pub fn write_with_signature<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let sig = self.get_signing_block()?;
        let offsets = self.get_offsets()?;
        let mut eocd = self.find_eocd()?;
        eocd.cd_offset = eocd
            .cd_offset
            .checked_add(sig.get_full_size() as u32)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid signing block: offset overflow when adding signature",
                )
            })?;
        let oecd_serialized = eocd.to_u8();
        let eocd_len = oecd_serialized.len();

        // copy entries
        let file_reader = File::open(&self.path)?;
        let mut reader_entries = file_reader.take(offsets.stop_content as u64);
        copy(&mut reader_entries, writer)?;

        // copy signature block
        writer.write_all(&sig.to_u8())?;

        // copy zip central directory
        let mut file_reader_end = File::open(&self.path)?;
        let seek_end = (offsets.start_cd - sig.get_full_size()) as u64;
        file_reader_end.seek(std::io::SeekFrom::Start(seek_end))?;
        let take = (offsets.stop_eocd - offsets.start_cd - eocd_len) as u64;
        let mut file_reader_end = file_reader_end.take(take);
        copy(&mut file_reader_end, writer)?;

        // copy end of central directory
        writer.write_all(&oecd_serialized)?;

        Ok(())
    }

    /// Sign the Module file with the given algorithm.
    /// # Errors
    /// Returns a string if the signing fails.
    #[cfg(feature = "signing")]
    #[cfg(feature = "hash")] // implied by "signing"
    pub fn sign_v2(
        &mut self,
        algo: &Algorithms,
        cert: &[u8],
        private_key: &crate::signing_block::algorithms::PrivateKey,
    ) -> Result<(), std::io::Error> {
        use crate::{
            common::{
                AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey,
                Signature, Signatures,
            },
            scheme_v2::{SignedData as SignedDataV2, Signer, Signers},
        };
        let pubkey = private_key
            .public_key_der()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let digest = self.digest(algo)?;

        let signed_data = SignedDataV2::new(
            Digests::new(vec![Digest::new(algo.clone(), digest)]),
            Certificates::new(vec![Certificate::new(cert.to_vec())]),
            AdditionalAttributes::new(vec![]),
        );

        let signed_data_serialized = signed_data.to_u8();
        let to_sign = &signed_data_serialized.get(4..).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signed data")
        })?;
        let signature = algo
            .sign(private_key, to_sign)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let one_signer = Signer::new(
            signed_data,
            Signatures::new(vec![Signature::new(algo.clone(), signature)]),
            PubKey::new(pubkey),
        );

        let mut signing_block =
            SigningBlock::new_with_padding(vec![ValueSigningBlock::new_v2(Signers::new(vec![
                one_signer,
            ]))])?;
        let eocd = self.find_eocd()?;
        signing_block.offset_by(eocd.cd_offset as usize);

        self.sig = Some(signing_block);
        Ok(())
    }
}
