//! Info command - Display signing block information

use clap::Args;
use modsig::{SignatureVerifier, SigningBlock};
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::PathBuf;

use super::cert::{describe_certificate, describe_chain};

/// Arguments for displaying module signing block information
#[derive(Args)]
pub struct InfoArgs {
    /// Module file path
    #[arg(value_name = "MODULE")]
    pub module: PathBuf,
}

/// Execute the info command
pub fn execute(args: InfoArgs) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(&args.module)?;
    let mut reader = BufReader::new(file);

    let file_len = reader.seek(SeekFrom::End(0))? as usize;

    println!("File: {}", args.module.display());
    println!("File size: {} bytes", file_len);
    println!();

    match SigningBlock::from_reader(reader, file_len, 0) {
        Ok(sig_block) => {
            println!("✓ KSU signing block found");
            println!(
                "  Location: {} - {}",
                sig_block.file_offset_start, sig_block.file_offset_end
            );
            println!("  Size: {} bytes", sig_block.size_of_block_start + 8);
            println!();

            // Display signing block types
            if !sig_block.content.is_empty() {
                println!("Signing block contents:");
                for value in &sig_block.content {
                    match value {
                        modsig::ValueSigningBlock::SignatureSchemeV2Block(_) => {
                            println!("  ✓ V2 Signature Scheme");
                        }
                        modsig::ValueSigningBlock::SourceStampBlock(_) => {
                            println!("  ✓ Source Stamp");
                        }
                        modsig::ValueSigningBlock::BaseSigningBlock(data) => {
                            println!("  • Unknown Block (ID: 0x{:x})", data.id);
                        }
                    }
                }
            }

            // Additional certificate details
            let verifier = SignatureVerifier::with_builtin_roots();

            match verifier.verify_v2(&sig_block) {
                Ok(result) => {
                    println!();
                    println!("V2 Certificate details:");
                    println!("  Signature valid: {}", result.signature_valid);
                    println!("  Certificate chain valid: {}", result.cert_chain_valid);
                    println!("  Trusted: {}", result.is_trusted);
                    if let Some(cert) = result.certificate {
                        println!(
                            "  Leaf certificate: {} bytes; {}",
                            cert.len(),
                            describe_certificate(&cert)
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
                }
                Err(e) => {
                    println!();
                    println!("ℹ V2 certificate info unavailable: {}", e);
                }
            }

            match verifier.verify_source_stamp(&sig_block) {
                Ok(result) if result.signature_valid => {
                    println!();
                    println!("Source Stamp certificate details:");
                    println!("  Signature valid: {}", result.signature_valid);
                    println!("  Certificate chain valid: {}", result.cert_chain_valid);
                    println!("  Trusted: {}", result.is_trusted);
                    if let Some(cert) = result.certificate {
                        println!(
                            "  Stamp certificate: {} bytes; {}",
                            cert.len(),
                            describe_certificate(&cert)
                        );
                    }
                }
                _ => { /* Source Stamp may be absent or invalid; ignore silently */ }
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Error: Cannot parse KSU signing block");
            eprintln!("  Details: {:?}", e);
            Err(e.into())
        }
    }
}
