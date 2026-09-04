use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// Exit codes are stable and documented: 0 valid, 1 verification failed,
/// 2 malformed input / CLI usage, 3 unsupported protocol/version.
const EXIT_VALID: u8 = 0;
const EXIT_USAGE: u8 = 2;

#[derive(Parser)]
#[command(name = "ap2", about = "Inspect and verify AP2 artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print ap2-rs version and the pinned AP2 spec/upstream revision.
    Version,
    /// Inspect an AP2 artifact without verifying it.
    Inspect { artifact: String },
    /// Verify an AP2 artifact.
    Verify {
        artifact: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Verify a Checkout Mandate against its signed Checkout JWT.
    VerifyCheckout {
        #[arg(long)]
        mandate: String,
        #[arg(long)]
        checkout: String,
    },
    /// Verify a Payment Mandate against its bound Checkout JWT.
    VerifyPayment {
        #[arg(long)]
        mandate: String,
        #[arg(long)]
        checkout: String,
    },
    /// Inspect a Checkout or Payment Receipt.
    InspectReceipt { receipt: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Version => {
            println!("ap2-cli {}", env!("CARGO_PKG_VERSION"));
            println!("AP2 spec version    {}", ap2_core::AP2_SPEC_VERSION);
            println!("AP2 upstream commit {}", ap2_core::AP2_UPSTREAM_COMMIT);
            ExitCode::from(EXIT_VALID)
        }
        _ => {
            eprintln!("not yet implemented");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
