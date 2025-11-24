//! Verify command - Verify module signatures

use clap::Args;
use modsig::{Module, SignatureVerifier, TrustedRoots, VerifyError};
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

    // Verify V2 signature
    let v2_result = match verifier.verify_v2(&signing_block) {
        Ok(r) => Some(r),
        Err(VerifyError::NoSignature) => {
            println!("ℹ V2 signature not found");
            None
        }
        Err(e) => {
            eprintln!("✗ V2 signature verification failed: {}", e);
            return Err("V2 signature verification failed".into());
        }
    };

    // Verify Source Stamp (if present)
    let stamp_result = verifier.verify_source_stamp(&signing_block).ok();

    // Display V2 signature verification result
    match &v2_result {
        Some(result) => {
            if result.signature_valid {
                println!("✓ V2 signature verification passed");
                println!("  Certificate chain valid: {}", result.cert_chain_valid);
                println!("  Trusted: {}", result.is_trusted);
                if let Some(ref cert) = result.certificate {
                    println!(
                        "  Leaf certificate: {} bytes; {}",
                        cert.len(),
                        describe_certificate(cert)
                    );
                }
                if !result.cert_chain.is_empty() {
                    println!("  Certificate chain: {} certificate(s)", result.cert_chain.len());
                    for line in describe_chain(&result.cert_chain) {
                        println!("    {}", line);
                    }
                } else {
                    println!("  Certificate chain: none (self-signed or single cert)");
                }
                if !result.warnings.is_empty() {
                    println!("  Warnings:");
                    for warning in &result.warnings {
                        println!("    ⚠ {}", warning);
                    }
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
        Some(result) => {
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
                eprintln!("⚠ Source Stamp verification failed");
                // Source Stamp failure is not a critical error
            }
        }
        None => {
            println!("ℹ Source Stamp not found");
        }
    }

    // Overall result
    if v2_result.is_some() && v2_result.as_ref().is_some_and(|r| r.signature_valid) {
        println!();
        println!("✓ Module signature verification successful!");
        Ok(())
    } else {
        Err("Module signature verification failed".into())
    }
}
