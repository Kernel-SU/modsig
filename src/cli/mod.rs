//! Command-line interface for ksusig

use clap::{Parser, Subcommand};

#[cfg(feature = "verify")]
pub mod cert;
pub mod digest;
#[cfg(feature = "verify")]
pub mod info;
#[cfg(feature = "keystore")]
pub mod sign;
#[cfg(feature = "verify")]
pub mod verify;

/// KSU Module signing tool
#[derive(Parser)]
#[command(name = "ksusig")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(Subcommand)]
pub enum Commands {
    /// Sign a module (requires keystore feature)
    #[cfg(feature = "keystore")]
    Sign(Box<sign::SignArgs>),

    /// Verify module signature (requires verify feature)
    #[cfg(feature = "verify")]
    Verify(verify::VerifyArgs),

    /// Display signing block information (requires verify feature)
    #[cfg(feature = "verify")]
    Info(info::InfoArgs),

    /// Calculate digest of signable regions
    Digest(digest::DigestArgs),
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Execute command
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            #[cfg(feature = "keystore")]
            Commands::Sign(args) => sign::execute(*args),
            #[cfg(feature = "verify")]
            Commands::Verify(args) => verify::execute(args),
            #[cfg(feature = "verify")]
            Commands::Info(args) => info::execute(args),
            Commands::Digest(args) => digest::execute(args),
        }
    }
}
