//! Module for the KSU Signing Block
//! <https://source.android.com/docs/security/features/apksigning>

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod algorithms;
pub mod digest;
pub mod scheme_v2;
pub mod source_stamp;

#[cfg(feature = "elf")]
pub mod elf_section_info;

use crate::utils::create_fixed_buffer_8;
#[cfg(feature = "directprint")]
use crate::utils::MagicNumberDecoder;

use crate::utils::print_string;
use crate::utils::{add_space, MyReader};
#[cfg(feature = "elf")]
use elf_section_info::{ElfSectionInfo, ELF_SECTION_INFO_BLOCK_ID};
use scheme_v2::{SignatureSchemeV2, Signers as SignersV2, SIGNATURE_SCHEME_V2_BLOCK_ID};
use source_stamp::{SourceStamp, StampBlock, SOURCE_STAMP_BLOCK_ID};

/// Magic number of the KSU Signing Block
pub const MAGIC: &[u8; 16] = b"KSU Sig Block 42";

/// Length of the magic number
pub const MAGIC_LEN: usize = MAGIC.len();

/// <https://android.googlesource.com/platform/tools/ksusig/+/master/src/main/java/com/android/ksusig/internal/apk/apksigningBlockUtils.java>
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;

/// Size of a u64
const SIZE_UINT64: usize = mem::size_of::<u64>();

/// Raw data extracted from the KSU Signing Block
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawData {
    /// Size of the data
    /// u64
    pub size: usize,

    /// ID of the data
    pub id: u32,

    /// Data
    pub data: Vec<u8>,
}

impl RawData {
    /// Create a new RawData
    pub const fn new(id: u32, data: Vec<u8>) -> Self {
        let size = mem::size_of::<u32>() + data.len();
        Self { size, id, data }
    }

    /// Serialize to u8
    fn to_u8(&self) -> Vec<u8> {
        [
            (self.size as u64).to_le_bytes().to_vec(),
            self.id.to_le_bytes().to_vec(),
            self.data.to_vec(),
        ]
        .concat()
    }
}

/// Value of the KSU Signing Block
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValueSigningBlock {
    /// Base Signing Block
    BaseSigningBlock(RawData),

    /// Signature Scheme V2
    SignatureSchemeV2Block(SignatureSchemeV2),

    /// Source Stamp
    SourceStampBlock(SourceStamp),

    /// ELF Section Info
    #[cfg(feature = "elf")]
    ElfSectionInfoBlock(ElfSectionInfo),
}

impl ValueSigningBlock {
    /// Create a new ValueSigningBlock::SignatureSchemeV2Block
    pub const fn new_v2(signers: SignersV2) -> Self {
        Self::SignatureSchemeV2Block(SignatureSchemeV2::new(signers))
    }

    /// Create a new ValueSigningBlock::SourceStampBlock
    pub const fn new_source_stamp(stamp_block: StampBlock) -> Self {
        Self::SourceStampBlock(SourceStamp::new(stamp_block))
    }

    /// ID of the value
    pub const fn id(&self) -> u32 {
        match self {
            Self::BaseSigningBlock(ref block) => block.id,
            Self::SignatureSchemeV2Block(ref scheme) => scheme.id,
            Self::SourceStampBlock(ref stamp) => stamp.id,
            #[cfg(feature = "elf")]
            Self::ElfSectionInfoBlock(ref info) => info.id,
        }
    }

    /// Size of the inner value
    pub const fn inner_size(&self) -> usize {
        match self {
            Self::BaseSigningBlock(ref block) => block.size,
            Self::SignatureSchemeV2Block(ref scheme) => scheme.size,
            Self::SourceStampBlock(ref stamp) => stamp.size,
            #[cfg(feature = "elf")]
            Self::ElfSectionInfoBlock(ref info) => info.size,
        }
    }

    /// Size of the value
    pub const fn size(&self) -> usize {
        // size of the inner value + size of u64
        self.inner_size() + mem::size_of::<u64>()
    }

    /// Parse the value
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let pair_size = data.read_size_u64()?;
        print_string!("Pair size: {} bytes", pair_size);

        let pair_id = data.read_u32()?;
        print_string!(
            "Pair ID: {} {}",
            pair_id,
            MagicNumberDecoder::Normal(pair_id)
        );

        let value_length = match pair_size.checked_sub(4) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "Error: pair_size {} is less than 4 (pair_id size)",
                    pair_size
                ));
            }
        };
        let block_value = &mut data.as_slice(value_length)?;

        print_string!("Pair Content:");
        let block_to_add = match pair_id {
            SIGNATURE_SCHEME_V2_BLOCK_ID => Self::SignatureSchemeV2Block(SignatureSchemeV2::parse(
                pair_size,
                pair_id,
                block_value,
            )?),
            SOURCE_STAMP_BLOCK_ID => {
                Self::SourceStampBlock(SourceStamp::parse(pair_size, pair_id, block_value)?)
            }
            #[cfg(feature = "elf")]
            ELF_SECTION_INFO_BLOCK_ID => {
                Self::ElfSectionInfoBlock(ElfSectionInfo::parse(pair_size, pair_id, block_value)?)
            }
            VERITY_PADDING_BLOCK_ID => {
                add_space!(4);
                print_string!("Padding Block of {} bytes", block_value.len());
                Self::BaseSigningBlock(RawData {
                    size: pair_size,
                    id: pair_id,
                    data: block_value.to_vec(),
                })
            }
            _ => Self::BaseSigningBlock(RawData {
                size: pair_size,
                id: pair_id,
                data: block_value.to_vec(),
            }),
        };
        Ok(block_to_add)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        match self {
            Self::SignatureSchemeV2Block(scheme) => scheme.to_u8(),
            Self::SourceStampBlock(stamp) => stamp.to_u8(),
            #[cfg(feature = "elf")]
            Self::ElfSectionInfoBlock(info) => info.to_u8(),
            Self::BaseSigningBlock(block) => block.to_u8(),
        }
    }
}

/// KSU Signing Block
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SigningBlock {
    /// Offset of the start of the block in the file
    pub file_offset_start: usize,

    /// Offset of the end of the block in the file
    pub file_offset_end: usize,

    /// Size of block - at the start of the block
    pub size_of_block_start: usize,

    /// content_size
    pub content_size: usize,

    /// Content of the block
    pub content: Vec<ValueSigningBlock>,

    /// Size of block - at the end of the block
    pub size_of_block_end: usize,

    /// Magic string
    pub magic: [u8; 16],
}

impl SigningBlock {
    /// Create a new SigningBlock without padding
    pub fn new(content: Vec<ValueSigningBlock>) -> Self {
        let content_size = content.iter().fold(0, |acc, x| acc + x.size());
        let size = content_size + SIZE_UINT64 + MAGIC_LEN;
        let total_size = SIZE_UINT64 + size;
        Self {
            file_offset_start: 0,
            file_offset_end: total_size,
            size_of_block_start: size,
            content_size,
            content,
            size_of_block_end: size,
            magic: *MAGIC,
        }
    }

    /// Recalculate the size fields based on current content
    pub fn recalculate_size(&mut self) {
        self.content_size = self.content.iter().fold(0, |acc, x| acc + x.size());
        let size = self.content_size + SIZE_UINT64 + MAGIC_LEN;
        self.size_of_block_start = size;
        self.size_of_block_end = size;
        self.file_offset_end = self.file_offset_start + SIZE_UINT64 + size;
    }

    /// Get mutable reference to content blocks
    pub const fn content_mut(&mut self) -> &mut Vec<ValueSigningBlock> {
        &mut self.content
    }

    /// Create a new SigningBlock
    /// # Errors
    /// Return an error appends during creation of the block
    pub fn new_with_padding(content: Vec<ValueSigningBlock>) -> Result<Self, std::io::Error> {
        for c in &content {
            if c.id() == VERITY_PADDING_BLOCK_ID {
                return Err(std::io::Error::other("Error: Padding block already exists"));
            }
        }
        let initial_content_size = content.iter().fold(0, |acc, x| acc + x.size());
        let almost_full_size = SIZE_UINT64 + initial_content_size + SIZE_UINT64 + MAGIC_LEN;
        // padding content to match 4096 bytes multiple
        let padding_block = match almost_full_size % 4096 {
            0 => Vec::new(),
            v => {
                let padding_size = match (4096_usize)
                    .checked_sub(v + mem::size_of::<u32>() + mem::size_of::<u64>())
                {
                    Some(v) => v,
                    None => {
                        return Err(std::io::Error::other(
                            format!(
                                "Error: remaining size {} is too low to add padding block - try to manually pad the inner block",
                                4096 - v - mem::size_of::<u32>() - mem::size_of::<u64>()
                            ),
                        ));
                    }
                };
                vec![ValueSigningBlock::BaseSigningBlock(RawData::new(
                    VERITY_PADDING_BLOCK_ID,
                    vec![0; padding_size],
                ))]
            }
        };
        let new_content = [content, padding_block].concat();
        // Recalculate content_size after adding padding block
        let content_size = new_content.iter().fold(0, |acc, x| acc + x.size());
        let size = content_size + SIZE_UINT64 + MAGIC_LEN;
        let total_size = SIZE_UINT64 + size;
        debug_assert!(total_size.is_multiple_of(4096));
        Ok(Self {
            file_offset_start: 0,
            file_offset_end: total_size,
            size_of_block_start: size,
            content_size,
            content: new_content,
            size_of_block_end: size,
            magic: *MAGIC,
        })
    }

    /// Extract the KSU Signing Block from the Module file
    /// # Errors
    /// Return an error appends during decoding
    pub fn from_reader<R: Read + Seek>(
        mut reader: R,
        file_len: usize,
        end_offset: usize,
    ) -> Result<Self, std::io::Error> {
        // Read a window from the end of file into memory for efficient searching
        // Max signing block size is typically limited; use a reasonable window size
        const MAX_WINDOW_SIZE: usize = 16 * 1024 * 1024; // 16 MB max window
        let search_len = file_len.saturating_sub(end_offset);
        let window_size = search_len.min(MAX_WINDOW_SIZE);

        if window_size < MAGIC_LEN + SIZE_UINT64 {
            return Err(std::io::Error::other(
                "File too small to contain signing block",
            ));
        }

        // Read the tail window into memory
        let window_start = file_len - window_size;
        reader.seek(SeekFrom::Start(window_start as u64))?;
        let mut window = vec![0u8; window_size];
        reader.read_exact(&mut window)?;

        // Search backwards in memory for the magic number
        // Start searching from (window_size - end_offset - MAGIC_LEN) position
        let search_start = window_size.saturating_sub(end_offset + MAGIC_LEN);
        for pos in (0..=search_start).rev() {
            let magic_slice = match window.get(pos..pos + MAGIC_LEN) {
                Some(s) => s,
                None => continue,
            };

            if magic_slice == MAGIC {
                // Found magic, read block size from before the magic
                let size_pos = match pos.checked_sub(SIZE_UINT64) {
                    Some(p) => p,
                    None => continue, // Not enough space for size field
                };

                let size_slice = match window.get(size_pos..size_pos + SIZE_UINT64) {
                    Some(s) => s,
                    None => continue,
                };

                let block_size = u64::from_le_bytes(create_fixed_buffer_8(size_slice)) as usize;

                // Calculate start position of the full block
                let block_end_in_window = pos + MAGIC_LEN;
                let block_start_in_window = match block_end_in_window.checked_sub(block_size + SIZE_UINT64) {
                    Some(v) => v,
                    None => {
                        return Err(std::io::Error::other(format!(
                            "Error: block size {} is larger than available data",
                            block_size
                        )));
                    }
                };

                // Extract the full block from the window
                let vec_full_block = match window.get(block_start_in_window..block_end_in_window) {
                    Some(s) => s.to_vec(),
                    None => {
                        return Err(std::io::Error::other(
                            "Error: cannot extract full block from window",
                        ));
                    }
                };

                let file_offset_start = window_start + block_start_in_window;
                let file_offset_end = window_start + block_end_in_window;

                print_string!("--- Start of Signature Block ---");
                let mut sig = match Self::parse_full_block(&vec_full_block) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "Error parsing full block: {}",
                            e
                        )));
                    }
                };
                sig.file_offset_start = file_offset_start;
                sig.file_offset_end = file_offset_end;
                print_string!("--- End of Signature Block ---");
                return Ok(sig);
            }
        }

        Err(std::io::Error::other(format!(
            "from_reader(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
            MAGIC,
            String::from_utf8_lossy(MAGIC)
        )))
    }

    /// Parse the KSU Signing Block from a byte array
    /// # Errors
    /// Return an error appends during decoding
    fn parse_full_block(data: &[u8]) -> Result<Self, String> {
        if data.len() < SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN {
            return Err(format!(
                "Error: data length {} is less than {} (size of u64 + size of u64 + size of magic number)",
                data.len(),
                SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN
            ));
        }
        let magic = match data.get(data.len() - MAGIC_LEN..data.len()) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "Error: data length {} is less than {} (size of magic number)",
                    data.len(),
                    MAGIC_LEN
                ));
            }
        };
        if magic != MAGIC {
            return Err(format!(
                "parse_full_block(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
                MAGIC,
                String::from_utf8_lossy(MAGIC)
            ));
        }
        let start_block_size = match data.get(..8) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "Error: data length {} is less than {} (size of u64)",
                    data.len(),
                    SIZE_UINT64
                ));
            }
        };
        let start_block_size = u64::from_le_bytes(create_fixed_buffer_8(start_block_size)) as usize;
        let end_size =
            match data.get((data.len() - MAGIC_LEN - SIZE_UINT64)..data.len() - MAGIC_LEN) {
                Some(v) => v,
                None => {
                    return Err(format!(
                        "Error: data length {} is less than {} (size of u64)",
                        data.len(),
                        SIZE_UINT64
                    ));
                }
            };
        let end_block_size = u64::from_le_bytes(create_fixed_buffer_8(end_size)) as usize;
        debug_assert_eq!(start_block_size, end_block_size);
        if start_block_size != end_block_size {
            return Err(format!(
                "Error: start_block_size {} is different from end_block_size {}",
                start_block_size, end_block_size
            ));
        }
        let content_size = end_block_size - SIZE_UINT64 - MAGIC_LEN;
        let inner_content = match data.get(8..data.len() - MAGIC_LEN - SIZE_UINT64) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "Error: data length {} is less than {} (size of u64)",
                    data.len(),
                    SIZE_UINT64
                ));
            }
        };
        let content = match Self::extract_values(&mut MyReader::new(inner_content)) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Error extracting values: {}", e));
            }
        };
        Ok(Self {
            magic: MAGIC.to_owned(),
            file_offset_start: 0,
            file_offset_end: data.len(),
            content_size,
            content,
            size_of_block_end: end_block_size,
            size_of_block_start: start_block_size,
        })
    }

    /// Extract the KSU Signing Block from the Module file
    /// # Errors
    /// Return an error appends during decoding
    pub fn from_u8(data: &[u8]) -> Result<Self, String> {
        if data.len() < SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN {
            return Err(format!(
                "Error: data length {} is less than {} (size of magic number)",
                data.len(),
                MAGIC_LEN
            ));
        }
        for idx in MAGIC_LEN..data.len() {
            let start_magic = data.len() - idx;
            let end_magic = start_magic + MAGIC_LEN;
            let magic = match data.get(start_magic..end_magic) {
                Some(v) => v,
                None => {
                    return Err(format!(
                        "Error: start_magic {} is less than {} (size of magic number)",
                        start_magic, MAGIC_LEN
                    ));
                }
            };
            if magic == MAGIC {
                let size_part = match data.get(start_magic - SIZE_UINT64..start_magic) {
                    Some(v) => v,
                    None => {
                        return Err(format!(
                            "Error: start_magic {} is less than {} (size of u64)",
                            start_magic, SIZE_UINT64
                        ));
                    }
                };
                let size = u64::from_le_bytes(create_fixed_buffer_8(size_part)) as usize;
                let start_full_block = match start_magic.checked_sub(size - MAGIC_LEN + SIZE_UINT64)
                {
                    Some(v) => v,
                    None => {
                        return Err(format!(
                            "Error: start_magic {} is less than {} (size of u64)",
                            start_magic, SIZE_UINT64
                        ));
                    }
                };
                let full_block = match data.get(start_full_block..end_magic) {
                    Some(v) => v,
                    None => {
                        return Err(format!(
                            "Error: start_magic {} is less than {} (size of u64)",
                            start_magic, SIZE_UINT64
                        ));
                    }
                };
                let sig = Self::parse_full_block(full_block)?;
                return Ok(sig);
            }
        }
        Err(format!(
            "from_u8(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
            MAGIC,
            String::from_utf8_lossy(MAGIC)
        ))
    }

    /// Extract the values from the KSU Signing Block
    /// # Errors
    /// Return an error appends during decoding
    fn extract_values(data: &mut MyReader) -> Result<Vec<ValueSigningBlock>, String> {
        let mut blocks = Vec::new();
        while data.get_pos() < data.len() {
            blocks.push(ValueSigningBlock::parse(data)?);
        }
        Ok(blocks)
    }

    /// Serialize to u8 the content
    pub fn content_to_u8(&self) -> Vec<u8> {
        self.content
            .iter()
            .flat_map(|b| b.to_u8())
            .collect::<Vec<u8>>()
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        [
            (self.size_of_block_start as u64).to_le_bytes().to_vec(),
            self.content_to_u8(),
            (self.size_of_block_end as u64).to_le_bytes().to_vec(),
            self.magic.to_vec(),
        ]
        .concat()
    }

    /// Tiny shortcut to get the full size of the block
    pub const fn get_full_size(&self) -> usize {
        // size of the block + size of u64 (8 bytes)
        self.size_of_block_start + mem::size_of::<u64>()
    }

    /// Offset the block by a certain amount
    pub const fn offset_by(&mut self, offset: usize) {
        self.file_offset_start += offset;
        self.file_offset_end += offset;
    }
}
