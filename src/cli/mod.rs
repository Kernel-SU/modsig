//! Command-line interface for modsig

use clap::{Parser, Subcommand};

pub mod info;
pub mod sign;
pub mod verify;

/// KSU Module signing tool
#[derive(Parser)]
#[command(name = "modsig")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(Subcommand)]
pub enum Commands {
    /// Sign a module
    Sign(Box<sign::SignArgs>),

    /// Verify module signature
    Verify(verify::VerifyArgs),

    /// Display signing block information
    Info(info::InfoArgs),
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Execute command
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            Commands::Sign(args) => sign::execute(*args),
            Commands::Verify(args) => verify::execute(args),
            Commands::Info(args) => info::execute(args),
        }
    }
}
