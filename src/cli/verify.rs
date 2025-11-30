//! Verify command - Verify module signatures with digest verification

use clap::Args;
use ksusig::{Algorithms, DigestContext, Module, SignatureVerifier, TrustedRoots, VerifyError};
use std::fs;
use std::path::PathBuf;

use super::cert::{describe_certificate, describe_chain};

/// Arguments for the verify command
#[derive(Args)]
pub struct VerifyArgs {
    /// Module file to verify
    #[arg(value_name = "MODULE")]
    pub module: PathBuf,

    /// Trusted root certificate file (optional, PEM format)
    #[arg(long = "root")]
    pub root_cert: Option<PathBuf>,

    /// Verbose output
    #[arg(long, short)]
    pub verbose: bool,
}

/// Execute the verify command
pub fn execute(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying module signature...");
    println!("File: {}", args.module.display());
    println!();

    // Read module file
    let module = Module::new(args.module.clone())?;

    // Get signing block
    let signing_block = module
        .get_signing_block()
        .map_err(|e| format!("Cannot read signing block: {}", e))?;

    println!("✓ Signing block found");

    // Create verifier
    let verifier = if let Some(root_path) = args.root_cert {
        // Use custom root certificate
        let root_pem = fs::read(&root_path)?;

        let mut roots = TrustedRoots::new();
        roots
            .add_root_pem(&root_pem)
            .map_err(|e| format!("Cannot load root certificate: {}", e))?;

        println!("✓ Using custom root certificate: {}", root_path.display());

        SignatureVerifier::with_trusted_roots(roots)
    } else {
        // Use built-in root certificate
        SignatureVerifier::with_builtin_roots()
    };

    // Compute digest for verification
    let mut digest_context = DigestContext::new();

    // Try SHA2-256 (ECDSA P-256)
    match module.digest(&Algorithms::ECDSA_SHA2_256) {
        Ok(digest) => {
            digest_context.add_digest(Algorithms::ECDSA_SHA2_256.to_u32(), digest);
            if args.verbose {
                println!("✓ Computed SHA2-256 digest");
            }
        }
        Err(e) => {
            if args.verbose {
                println!("⚠ Could not compute SHA2-256 digest: {}", e);
            }
        }
    }

    // Try SHA2-512 (ECDSA P-384)
    match module.digest(&Algorithms::ECDSA_SHA2_512) {
        Ok(digest) => {
            digest_context.add_digest(Algorithms::ECDSA_SHA2_512.to_u32(), digest);
            if args.verbose {
                println!("✓ Computed SHA2-512 digest");
            }
        }
        Err(e) => {
            if args.verbose {
                println!("⚠ Could not compute SHA2-512 digest: {}", e);
            }
        }
    }

    if digest_context.digests.is_empty() {
        eprintln!("✗ Could not compute any digests for verification");
        return Err("Digest computation failed".into());
    }

    println!("✓ File digests computed");

    // Verify V2 signature with digest
    let v2_result = match verifier.verify_v2_with_digest(&signing_block, Some(&digest_context)) {
        Ok(r) => Some(r),
        Err(VerifyError::NoSignature) => {
            println!("ℹ V2 signature not found");
            None
        }
        Err(VerifyError::MultiSignerFailure(errors)) => {
            eprintln!("✗ V2 signature verification failed:");
            for (idx, err) in errors.iter().enumerate() {
                eprintln!("  Signer #{}: {}", idx + 1, err);
            }
            return Err("V2 signature verification failed".into());
        }
        Err(e) => {
            eprintln!("✗ V2 signature verification failed: {}", e);
            return Err("V2 signature verification failed".into());
        }
    };

    // Verify Source Stamp (if present)
    // Note: We preserve the error to distinguish between "not found" and "verification failed"
    let stamp_result = verifier.verify_source_stamp(&signing_block);

    // Display V2 signature verification result
    match &v2_result {
        Some(result) => {
            if result.signature_valid {
                println!("✓ V2 signature verification passed");
                println!("  Signers verified: {}", result.signers.len());

                // Show per-signer details
                for signer in &result.signers {
                    let signer_num = signer.signer_index + 1;
                    println!("  ─── Signer #{} ───", signer_num);
                    println!("    Signature valid: {}", signer.signature_valid);
                    println!("    Digest valid: {}", signer.digest_valid);
                    println!("    Certificate chain valid: {}", signer.cert_chain_valid);
                    println!("    Trusted: {}", signer.is_trusted);

                    if let Some(ref cert) = signer.certificate {
                        println!(
                            "    Certificate: {} bytes; {}",
                            cert.len(),
                            describe_certificate(cert)
                        );
                    }

                    if !signer.cert_chain.is_empty() {
                        println!(
                            "    Chain: {} certificate(s)",
                            signer.cert_chain.len()
                        );
                        if args.verbose {
                            for line in describe_chain(&signer.cert_chain) {
                                println!("      {}", line);
                            }
                        }
                    }

                    if !signer.warnings.is_empty() && args.verbose {
                        println!("    Warnings:");
                        for warning in &signer.warnings {
                            println!("      ⚠ {}", warning);
                        }
                    }
                }

                // Overall status
                println!("  ─── Overall ───");
                println!("  Digest valid: {}", result.digest_valid);
                println!("  Certificate chain valid: {}", result.cert_chain_valid);
                println!("  Trusted: {}", result.is_trusted);

                if !result.warnings.is_empty() {
                    println!("  Warnings:");
                    for warning in &result.warnings {
                        println!("    ⚠ {}", warning);
                    }
                }

                // Check for failures
                if !result.digest_valid {
                    eprintln!("✗ Digest mismatch: file content may have been tampered");
                    return Err("Digest verification failed".into());
                }
                if !result.cert_chain_valid {
                    eprintln!("✗ Certificate chain invalid");
                    return Err("Certificate chain invalid".into());
                }
                if !result.is_trusted {
                    eprintln!("✗ Untrusted certificate: not signed by trusted root");
                    return Err("Untrusted certificate".into());
                }
            } else {
                eprintln!("✗ V2 signature invalid");
                if !result.warnings.is_empty() {
                    eprintln!("  Errors:");
                    for warning in &result.warnings {
                        eprintln!("    • {}", warning);
                    }
                }
                return Err("V2 signature verification failed".into());
            }
        }
        None => {
            println!("ℹ V2 signature not found");
        }
    }

    // Display Source Stamp verification result
    match &stamp_result {
        Ok(result) => {
            if result.signature_valid {
                println!("✓ Source Stamp verification passed");
                println!("  Signature valid: {}", result.signature_valid);
                println!("  Certificate chain valid: {}", result.cert_chain_valid);
                println!("  Trusted: {}", result.is_trusted);
                if let Some(ref cert) = result.certificate {
                    println!(
                        "  Stamp certificate: {} bytes; {}",
                        cert.len(),
                        describe_certificate(cert)
                    );
                }
            } else {
                eprintln!("⚠ Source Stamp signature invalid");
                if !result.warnings.is_empty() {
                    for warning in &result.warnings {
                        eprintln!("  ⚠ {}", warning);
                    }
                }
                // Source Stamp failure is a warning, but we should report it
            }
        }
        Err(VerifyError::NoSignature) => {
            println!("ℹ Source Stamp not found");
        }
        Err(VerifyError::MultiSignerFailure(errors)) => {
            eprintln!("✗ Source Stamp verification failed:");
            for err in errors {
                eprintln!("  ✗ {}", err);
            }
            // Source Stamp verification failure is significant - warn strongly
            eprintln!("⚠ WARNING: Source Stamp present but verification failed!");
        }
        Err(e) => {
            eprintln!("✗ Source Stamp verification error: {}", e);
            // Source Stamp verification failure is significant - warn strongly
            eprintln!("⚠ WARNING: Source Stamp present but verification failed!");
        }
    }

    // Check if Source Stamp verification failed (not just missing)
    let stamp_failed = matches!(
        &stamp_result,
        Err(e) if !matches!(e, VerifyError::NoSignature)
    );

    // Overall result
    if v2_result.is_some() && v2_result.as_ref().is_some_and(|r| r.signature_valid && r.digest_valid) {
        println!();
        if stamp_failed {
            println!("⚠ Module V2 signature verified, but Source Stamp verification FAILED!");
            println!("  V2 checks passed: signature, digest, chain, trust");
            println!("  Source Stamp: VERIFICATION FAILED - may indicate tampering");
            // Return error because Source Stamp failure is a security concern
            Err("Source Stamp verification failed".into())
        } else {
            println!("✓ Module signature verification successful!");
            println!("  All checks passed: signature, digest, chain, trust");
            Ok(())
        }
    } else {
        Err("Module signature verification failed".into())
    }
}
