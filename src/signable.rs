//! Signable trait for unified file format handling

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::file_formats::module::zip::find_eocd;
use crate::file_formats::module::Module;
use crate::signing_block::algorithms::Algorithms;
use crate::signing_block::SigningBlock;

#[cfg(feature = "elf")]
use crate::file_formats::elf::{ElfError, ElfFile};
#[cfg(feature = "verify")]
use crate::VerifyResult;

/// File format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// KernelSU Module (ZIP format)
    Module,
    /// ELF executable file
    #[cfg(feature = "elf")]
    Elf,
}

/// Represents a region of a file that should be included in digest calculation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestRegion {
    /// Region name (for debugging)
    pub name: String,
    /// File offset
    pub offset: u64,
    /// Region size
    pub size: u64,
}

/// Unified error type for signable operations
#[derive(Debug)]
pub enum SignableError {
    /// IO-level errors
    Io(std::io::Error),
    /// Invalid or unsupported format
    InvalidFormat(String),
    /// Generic parse failure
    Parse(String),
    /// ELF-specific error
    #[cfg(feature = "elf")]
    Elf(ElfError),
}

impl Display for SignableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {}", err),
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            Self::Parse(msg) => write!(f, "Parse error: {}", msg),
            #[cfg(feature = "elf")]
            Self::Elf(err) => write!(f, "ELF error: {}", err),
        }
    }
}

impl std::error::Error for SignableError {}

impl From<std::io::Error> for SignableError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "elf")]
impl From<ElfError> for SignableError {
    fn from(err: ElfError) -> Self {
        Self::Elf(err)
    }
}

/// Signable wrapper that hides concrete file formats
pub enum SignableFile {
    /// ZIP-based KernelSU module
    Module(Module),
    /// ELF executable
    #[cfg(feature = "elf")]
    Elf(ElfFile),
}

impl SignableFile {
    /// Open a file and detect its format automatically
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or the format is unsupported
    pub fn open(path: &Path) -> Result<Self, SignableError> {
        match detect_file_format(path)? {
            FileFormat::Module => Ok(Self::Module(Module::new(path.to_path_buf())?)),
            #[cfg(feature = "elf")]
            FileFormat::Elf => Ok(Self::Elf(ElfFile::new(path.to_path_buf())?)),
            #[allow(unreachable_patterns)]
            other => Err(SignableError::InvalidFormat(format!(
                "Unsupported format: {:?}",
                other
            ))),
        }
    }

    /// Get detected format
    #[must_use]
    pub const fn format(&self) -> FileFormat {
        match self {
            Self::Module(_) => FileFormat::Module,
            #[cfg(feature = "elf")]
            Self::Elf(_) => FileFormat::Elf,
        }
    }

    /// Override ELF signing sections
    ///
    /// # Errors
    /// Returns an error if the target is not ELF or the sections are invalid
    #[cfg(feature = "elf")]
    pub fn set_elf_sections(&mut self, sections: Vec<String>) -> Result<(), SignableError> {
        match self {
            Self::Elf(elf) => elf
                .set_signed_sections(sections)
                .map_err(SignableError::Elf),
            Self::Module(_) => Err(SignableError::InvalidFormat(
                "Only ELF files accept --elf-section".to_string(),
            )),
        }
    }

    /// Calculate digest regions for the underlying file
    ///
    /// # Errors
    /// Propagates underlying parsing errors
    pub fn digest_regions(&self) -> Result<Vec<DigestRegion>, SignableError> {
        match self {
            Self::Module(module) => <Module as Signable>::digest_regions(module),
            #[cfg(feature = "elf")]
            Self::Elf(elf) => <ElfFile as Signable>::digest_regions(elf),
        }
    }

    /// Calculate digest bytes using the chosen algorithm
    ///
    /// # Errors
    /// Propagates underlying errors
    pub fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, SignableError> {
        match self {
            Self::Module(module) => <Module as Signable>::digest(module, algo),
            #[cfg(feature = "elf")]
            Self::Elf(elf) => <ElfFile as Signable>::digest(elf, algo),
        }
    }

    /// Retrieve existing signing block, if present
    ///
    /// # Errors
    /// Propagates underlying errors when the signing block cannot be parsed
    pub fn signing_block(&self) -> Result<Option<SigningBlock>, SignableError> {
        match self {
            Self::Module(module) => <Module as Signable>::get_signing_block(module),
            #[cfg(feature = "elf")]
            Self::Elf(elf) => <ElfFile as Signable>::get_signing_block(elf),
        }
    }

    /// Write the file with the provided signing block
    ///
    /// # Errors
    /// Propagates underlying write errors
    pub fn write_with_signature<W: Write>(
        &self,
        writer: &mut W,
        signing_block: &SigningBlock,
    ) -> Result<(), SignableError> {
        match self {
            Self::Module(module) => {
                <Module as Signable>::write_with_signature(module, writer, signing_block)
            }
            #[cfg(feature = "elf")]
            Self::Elf(elf) => {
                <ElfFile as Signable>::write_with_signature(elf, writer, signing_block)
            }
        }
    }
}

/// Unified interface for signable files
pub trait Signable: Sized {
    /// Error type
    type Error: std::error::Error;

    /// Get the file format type
    fn format(&self) -> FileFormat;

    /// Create instance from file path
    /// # Errors
    /// Returns an error if the file cannot be opened or parsed
    fn open(path: &Path) -> Result<Self, Self::Error>;

    /// Get list of regions to be included in digest calculation
    /// # Errors
    /// Returns an error if regions cannot be determined
    fn digest_regions(&self) -> Result<Vec<DigestRegion>, Self::Error>;

    /// Calculate digest using specified algorithm
    /// # Errors
    /// Returns an error if digest calculation fails
    fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, Self::Error>;

    /// Get existing signing block (if present)
    /// # Errors
    /// Returns an error if signature cannot be read
    fn get_signing_block(&self) -> Result<Option<SigningBlock>, Self::Error>;

    /// Verify signature
    /// # Errors
    /// Returns an error if verification fails
    #[cfg(feature = "verify")]
    fn verify(&self) -> Result<VerifyResult, Self::Error>;

    /// Write file with signature
    /// # Errors
    /// Returns an error if writing fails
    fn write_with_signature<W: Write>(
        &self,
        writer: &mut W,
        signing_block: &SigningBlock,
    ) -> Result<(), Self::Error>;

    /// Check if file is signed
    fn is_signed(&self) -> bool {
        self.get_signing_block()
            .map(|b| b.is_some())
            .unwrap_or(false)
    }
}

/// Detect the file format from its magic/header
///
/// # Errors
/// Returns an error if the file cannot be read or the format is unknown
pub fn detect_file_format(path: &Path) -> Result<FileFormat, SignableError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;

    #[cfg(feature = "elf")]
    if magic == *goblin::elf::header::ELFMAG {
        return Ok(FileFormat::Elf);
    }

    if magic.starts_with(b"PK") {
        return Ok(FileFormat::Module);
    }

    let file_len = file.metadata()?.len() as usize;
    file.seek(SeekFrom::Start(0))?;
    if find_eocd(&mut file, file_len).is_ok() {
        return Ok(FileFormat::Module);
    }

    Err(SignableError::InvalidFormat(format!(
        "无法识别文件格式: {}",
        path.display()
    )))
}

impl Signable for Module {
    type Error = SignableError;

    fn format(&self) -> FileFormat {
        FileFormat::Module
    }

    fn open(path: &Path) -> Result<Self, Self::Error> {
        Self::new(path.to_path_buf()).map_err(SignableError::from)
    }

    fn digest_regions(&self) -> Result<Vec<DigestRegion>, Self::Error> {
        let offsets = Self::get_offsets(self)?;
        Ok(vec![
            DigestRegion {
                name: "zip_entries".to_string(),
                offset: offsets.start_content as u64,
                size: (offsets.stop_content - offsets.start_content) as u64,
            },
            DigestRegion {
                name: "central_directory".to_string(),
                offset: offsets.start_cd as u64,
                size: (offsets.stop_cd - offsets.start_cd) as u64,
            },
            DigestRegion {
                name: "eocd".to_string(),
                offset: offsets.start_eocd as u64,
                size: (offsets.stop_eocd - offsets.start_eocd) as u64,
            },
        ])
    }

    fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, Self::Error> {
        Self::digest(self, algo).map_err(SignableError::from)
    }

    fn get_signing_block(&self) -> Result<Option<SigningBlock>, Self::Error> {
        match Self::get_signing_block(self) {
            Ok(block) => Ok(Some(block)),
            Err(err) if maybe_missing_signature(&err) => Ok(None),
            Err(err) => Err(SignableError::Io(err)),
        }
    }

    #[cfg(feature = "verify")]
    fn verify(&self) -> Result<VerifyResult, Self::Error> {
        Err(SignableError::InvalidFormat(
            "Signable 接口暂未提供 Module 校验实现".to_string(),
        ))
    }

    fn write_with_signature<W: Write>(
        &self,
        writer: &mut W,
        signing_block: &SigningBlock,
    ) -> Result<(), Self::Error> {
        use std::io::Cursor;

        let signing_block_bytes = signing_block.to_u8();

        let (raw_bytes, mut eocd) = match Self::get_signing_block(self) {
            Ok(_) => {
                // Existing valid signature - strip it via get_raw_module
                let bytes = Self::get_raw_module(self)?;
                let mut cursor = Cursor::new(&bytes);
                let eocd = find_eocd(&mut cursor, bytes.len())?;
                (bytes, eocd)
            }
            Err(err) if maybe_missing_signature(&err) => {
                // No signature exists (raw file) - use file as-is
                let bytes = std::fs::read(&self.path)?;
                let mut cursor = Cursor::new(&bytes);
                let eocd = find_eocd(&mut cursor, bytes.len())?;
                (bytes, eocd)
            }
            Err(err) => {
                // Corrupted/invalid signature block - refuse to sign
                // This prevents creating files with layout: [old corrupted block + new block + CD + EOCD]
                // which would produce unverifiable output
                return Err(SignableError::Parse(format!(
                    "Cannot sign file with corrupted signing block: {}. \
                     Please remove the corrupted block first or use a clean unsigned file.",
                    err
                )));
            }
        };

        let cd_offset = eocd.cd_offset as usize;
        let eocd_offset = eocd.file_offset;
        let cd_size = eocd_offset
            .checked_sub(cd_offset)
            .ok_or_else(|| SignableError::Parse("Invalid central directory offset".to_string()))?;
        let eocd_size = raw_bytes.len() - eocd_offset;

        let header_slice = raw_bytes
            .get(..cd_offset)
            .ok_or_else(|| SignableError::Parse("内容范围越界".to_string()))?;
        writer.write_all(header_slice)?;
        writer.write_all(&signing_block_bytes)?;
        let cd_slice = raw_bytes
            .get(cd_offset..eocd_offset)
            .ok_or_else(|| SignableError::Parse("中央目录范围越界".to_string()))?;
        writer.write_all(cd_slice)?;

        let new_cd_offset = cd_offset
            .checked_add(signing_block_bytes.len())
            .ok_or_else(|| SignableError::Parse("签名块过大".to_string()))?;

        eocd.file_offset = eocd_offset + signing_block_bytes.len();
        eocd.cd_offset = new_cd_offset as u32;

        debug_assert_eq!(cd_size + eocd_size + cd_offset, raw_bytes.len());
        writer.write_all(&eocd.to_u8())?;
        Ok(())
    }
}

/// Heuristic to treat a missing signature as a non-fatal condition
/// Determine whether a signing block parsing error likely means "no signature"
fn maybe_missing_signature(err: &std::io::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Magic not found") || msg.contains("Module is raw")
}

#[cfg(feature = "elf")]
impl Signable for ElfFile {
    type Error = SignableError;

    fn format(&self) -> FileFormat {
        FileFormat::Elf
    }

    fn open(path: &Path) -> Result<Self, Self::Error> {
        Self::new(path.to_path_buf()).map_err(SignableError::from)
    }

    fn digest_regions(&self) -> Result<Vec<DigestRegion>, Self::Error> {
        Self::digest_regions(self).map_err(SignableError::from)
    }

    fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, Self::Error> {
        Self::digest(self, algo).map_err(SignableError::from)
    }

    fn get_signing_block(&self) -> Result<Option<SigningBlock>, Self::Error> {
        Self::get_signing_block(self).map_err(SignableError::from)
    }

    #[cfg(feature = "verify")]
    fn verify(&self) -> Result<VerifyResult, Self::Error> {
        Err(SignableError::InvalidFormat("ELF 验证暂未实现".to_string()))
    }

    fn write_with_signature<W: Write>(
        &self,
        writer: &mut W,
        signing_block: &SigningBlock,
    ) -> Result<(), Self::Error> {
        Self::write_with_signature(self, writer, signing_block).map_err(SignableError::from)
    }
}
