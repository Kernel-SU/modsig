//! Digest command - Calculate digest of signable regions

use clap::Args;
use ksusig::{signing_block::algorithms::Algorithms, FileFormat, SignableFile};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Arguments for the digest command
#[derive(Args)]
pub struct DigestArgs {
    /// Input file (module ZIP or ELF)
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Use SHA-256 algorithm (default)
    #[arg(long = "sha256", group = "algorithm")]
    pub sha256: bool,

    /// Use SHA-512 algorithm
    #[arg(long = "sha512", group = "algorithm")]
    pub sha512: bool,

    /// Dump raw signable regions to file instead of calculating digest
    #[arg(long = "dump", value_name = "OUTPUT")]
    pub dump: Option<PathBuf>,

    /// ELF sections to include (comma separated, ELF files only)
    #[arg(
        long = "elf-section",
        value_name = "SECTION",
        value_delimiter = ',',
        num_args = 0..
    )]
    pub elf_sections: Vec<String>,

    /// Output format: hex (default) or base64
    #[arg(long = "format", value_name = "FORMAT", default_value = "hex")]
    pub format: OutputFormat,
}

/// Output format for digest
#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Hexadecimal output
    #[default]
    Hex,
    /// Base64 output
    Base64,
}

/// Execute the digest command
pub fn execute(args: DigestArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Open and detect file format
    let mut signable = SignableFile::open(&args.input)?;

    // Configure ELF sections if specified
    #[cfg(feature = "elf")]
    if !args.elf_sections.is_empty() {
        signable.set_elf_sections(args.elf_sections.clone())?;
    }

    #[cfg(not(feature = "elf"))]
    if !args.elf_sections.is_empty() {
        return Err("ELF support not enabled, cannot use --elf-section".into());
    }

    // Print file info
    let format_name = match signable.format() {
        FileFormat::Module => "Module (ZIP)",
        #[cfg(feature = "elf")]
        FileFormat::Elf => "ELF",
    };
    eprintln!("File: {}", args.input.display());
    eprintln!("Format: {}", format_name);

    // Get digest regions
    let regions = signable.digest_regions()?;
    eprintln!("Signable regions:");
    let mut total_size: u64 = 0;
    for region in &regions {
        eprintln!(
            "  - {} @ offset {} ({} bytes)",
            region.name, region.offset, region.size
        );
        total_size += region.size;
    }
    eprintln!("Total size: {} bytes", total_size);
    eprintln!();

    // Handle dump mode
    if let Some(dump_path) = args.dump {
        return dump_regions(&args.input, &regions, &dump_path);
    }

    // Determine algorithm
    let algorithm = if args.sha512 {
        Algorithms::ECDSA_SHA2_512
    } else {
        // Default to SHA-256
        Algorithms::ECDSA_SHA2_256
    };

    let algo_name = if args.sha512 { "SHA-512" } else { "SHA-256" };
    eprintln!("Algorithm: {}", algo_name);

    // Calculate digest
    let digest = signable.digest(&algorithm)?;

    // Format output
    let output = match args.format {
        OutputFormat::Hex => hex_encode(&digest),
        OutputFormat::Base64 => base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &digest,
        ),
    };

    // Print digest to stdout (for piping)
    println!("{}", output);

    Ok(())
}

/// Dump raw signable regions to a file using streaming copy
fn dump_regions(
    input_path: &PathBuf,
    regions: &[ksusig::DigestRegion],
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = File::open(input_path)?;
    let mut output = File::create(output_path)?;

    // Use a fixed-size buffer for streaming copy to avoid OOM on large files
    const BUFFER_SIZE: usize = 64 * 1024; // 64 KB buffer
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_written: u64 = 0;

    for region in regions {
        input.seek(SeekFrom::Start(region.offset))?;
        let mut remaining = region.size;

        while remaining > 0 {
            let to_read = (remaining as usize).min(BUFFER_SIZE);
            let buf_slice = match buffer.get_mut(..to_read) {
                Some(s) => s,
                None => return Err("Buffer slice error".into()),
            };
            input.read_exact(buf_slice)?;
            output.write_all(buf_slice)?;
            remaining -= to_read as u64;
        }
        total_written += region.size;
    }

    output.flush()?;

    eprintln!("Dumped {} bytes to {}", total_written, output_path.display());

    Ok(())
}

/// Encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
