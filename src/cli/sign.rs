//! Sign command - Sign module files

use clap::Args;
use modsig::{
    common::{Digest, Digests},
    digest_module, load_p12, load_pem,
    zip::find_eocd,
    Algorithms, ModuleSigner, ModuleSignerConfig,
};
use std::fs::{File, OpenOptions};
use std::io::{copy, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Arguments for the sign command
#[derive(Args)]
pub struct SignArgs {
    /// Input module file
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output module file
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// V2 signature private key file (PEM or P12 format)
    #[arg(long = "key")]
    pub key: Option<PathBuf>,

    /// V2 signature certificate file (PEM format)
    #[arg(long = "cert")]
    pub cert: Option<PathBuf>,

    /// V2 signature P12 keystore file
    #[arg(long = "p12")]
    pub p12: Option<PathBuf>,

    /// P12 keystore password
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Source Stamp private key file
    #[arg(long = "stamp-key")]
    pub stamp_key: Option<PathBuf>,

    /// Source Stamp certificate file
    #[arg(long = "stamp-cert")]
    pub stamp_cert: Option<PathBuf>,

    /// Source Stamp P12 keystore
    #[arg(long = "stamp-p12")]
    pub stamp_p12: Option<PathBuf>,

    /// Source Stamp P12 password
    #[arg(long = "stamp-password")]
    pub stamp_password: Option<String>,
}

/// Execute the sign command
pub fn execute(args: SignArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("Signing module file...");
    println!("Input: {}", args.input.display());
    println!("Output: {}", args.output.display());
    println!();

    // Load V2 signature credentials
    let v2_creds = if let Some(p12_path) = args.p12 {
        // Load from P12
        let password = args
            .password
            .ok_or("P12 format requires password (--password)")?;
        let p12_str = p12_path.to_str().ok_or("Invalid P12 file path")?;
        load_p12(p12_str, &password)?
    } else if let Some(key_path) = args.key {
        // Load from PEM
        let cert_path = args.cert.ok_or("--cert required when using --key")?;
        let key_str = key_path.to_str().ok_or("Invalid key file path")?;
        let cert_str = cert_path.to_str().ok_or("Invalid certificate file path")?;
        load_pem(key_str, cert_str, args.password.as_deref())?
    } else {
        return Err("Must specify --key/--cert or --p12".into());
    };

    println!("✓ V2 signing key loaded");

    // Load Source Stamp credentials (if provided)
    let stamp_creds = if let Some(stamp_p12) = args.stamp_p12 {
        let password = args
            .stamp_password
            .ok_or("Source Stamp P12 requires password (--stamp-password)")?;
        let p12_str = stamp_p12
            .to_str()
            .ok_or("Invalid Source Stamp P12 file path")?;
        Some(load_p12(p12_str, &password)?)
    } else if let Some(stamp_key) = args.stamp_key {
        let stamp_cert = args
            .stamp_cert
            .ok_or("--stamp-cert required when using --stamp-key")?;
        let key_str = stamp_key
            .to_str()
            .ok_or("Invalid Source Stamp key file path")?;
        let cert_str = stamp_cert
            .to_str()
            .ok_or("Invalid Source Stamp certificate file path")?;
        Some(load_pem(key_str, cert_str, args.stamp_password.as_deref())?)
    } else {
        None
    };

    if stamp_creds.is_some() {
        println!("✓ Source Stamp key loaded");
    }

    // Create signer
    let signer = if let Some(stamp) = stamp_creds {
        ModuleSigner::with_source_stamp(
            ModuleSignerConfig::from_credentials(v2_creds),
            ModuleSignerConfig::from_credentials(stamp),
        )
    } else {
        ModuleSigner::v2_only(ModuleSignerConfig::from_credentials(v2_creds))
    };

    // Read input file
    let mut input_file = File::open(&args.input)?;
    let input_len = input_file.metadata()?.len() as usize;

    // Find EOCD
    let eocd = find_eocd(&mut input_file, input_len)?;
    let cd_offset = eocd.cd_offset as usize;
    let cd_size = eocd.cd_size as usize;
    let eocd_offset = eocd.file_offset;
    let eocd_size = input_len - eocd_offset;

    println!("✓ ZIP structure parsed");
    println!("  Central Directory: {} bytes @ {}", cd_size, cd_offset);
    println!("  EOCD: {} bytes @ {}", eocd_size, eocd_offset);

    // Build file offsets
    let offsets = modsig::zip::FileOffsets {
        start_content: 0,
        stop_content: cd_offset,
        start_cd: cd_offset,
        stop_cd: eocd_offset,
        start_eocd: eocd_offset,
        stop_eocd: input_len,
    };

    // Select algorithm based on V2 private key curve
    let algorithm = v2_creds.algorithm.clone();
    println!(
        "ℹ 自动使用密钥曲线对应算法: {}",
        algorithm
    );

    // Calculate digests
    println!("Calculating digests...");
    input_file.seek(SeekFrom::Start(0))?;
    let digest = digest_module(&mut input_file, &offsets, &algorithm)?;
    println!("✓ Digest calculation complete");

    // Create Digests
    let digests = Digests::new(vec![Digest::new(algorithm, digest)]);

    // Sign
    println!("Signing...");
    let signing_block = signer.sign(digests)?;
    let signing_block_bytes = signing_block.to_u8();
    let signing_block_size = signing_block_bytes.len();
    println!(
        "✓ Signing complete (signing block size: {} bytes)",
        signing_block_size
    );

    // Write output file
    println!("Writing signed module...");
    write_signed_module(
        &args.input,
        &args.output,
        &signing_block_bytes,
        cd_offset,
        &eocd,
    )?;

    println!("✓ Signing successful!");
    println!("Output file: {}", args.output.display());

    Ok(())
}

/// Write signed module file
fn write_signed_module(
    input_path: &PathBuf,
    output_path: &PathBuf,
    signing_block: &[u8],
    cd_offset: usize,
    eocd: &modsig::zip::EndOfCentralDirectoryRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::new(input_file);

    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    let mut writer = BufWriter::new(output_file);

    // 1. Write ZIP content (from start to before Central Directory)
    reader.seek(SeekFrom::Start(0))?;
    let mut content_reader = reader.by_ref().take(cd_offset as u64);
    copy(&mut content_reader, &mut writer)?;

    // 2. Write signing block
    writer.write_all(signing_block)?;

    let new_cd_offset = cd_offset + signing_block.len();

    // 3. Write Central Directory
    reader.seek(SeekFrom::Start(cd_offset as u64))?;
    let cd_size = (eocd.file_offset - cd_offset) as u64;
    let mut cd_reader = reader.by_ref().take(cd_size);
    copy(&mut cd_reader, &mut writer)?;

    // 4. Write updated EOCD (update CD offset)
    let new_eocd = modsig::zip::EndOfCentralDirectoryRecord {
        file_offset: eocd.file_offset + signing_block.len(),
        signature: eocd.signature,
        disk_number: eocd.disk_number,
        disk_with_cd: eocd.disk_with_cd,
        num_entries: eocd.num_entries,
        total_entries: eocd.total_entries,
        cd_size: eocd.cd_size,
        cd_offset: new_cd_offset as u32,
        comment_len: eocd.comment_len,
        comment: eocd.comment.clone(),
    };

    writer.write_all(&new_eocd.to_u8())?;
    writer.flush()?;

    Ok(())
}
