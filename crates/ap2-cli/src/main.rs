use ap2_credentials::Jwk;
use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// Exit codes are stable and documented: 0 valid, 1 verification failed,
/// 2 malformed input / CLI usage, 3 unsupported protocol/version.
const EXIT_VALID: u8 = 0;
const EXIT_USAGE: u8 = 2;

/// Clock skew tolerance for exp/iat checks.
const DEFAULT_LEEWAY_SECONDS: i64 = 60;

/// Errors reading CLI input files (paths, JWK JSON) -- distinct from
/// verification failures.
#[derive(Debug, thiserror::Error)]
enum CliInputError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid JWK in {path}: {source}")]
    InvalidJwk {
        path: String,
        source: serde_json::Error,
    },
}

fn read_trimmed(path: &str) -> Result<String, CliInputError> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|source| CliInputError::Io {
            path: path.to_string(),
            source,
        })
}

fn read_jwk(path: &str) -> Result<Jwk, CliInputError> {
    let contents = std::fs::read_to_string(path).map_err(|source| CliInputError::Io {
        path: path.to_string(),
        source,
    })?;
    serde_json::from_str(&contents).map_err(|source| CliInputError::InvalidJwk {
        path: path.to_string(),
        source,
    })
}

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
        /// Path to the User/Agent's JWK.
        #[arg(long)]
        user_key: String,
        /// Path to the Merchant's JWK.
        #[arg(long)]
        merchant_key: String,
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

fn run_verify_checkout(
    mandate: &str,
    checkout: &str,
    user_key: &str,
    merchant_key: &str,
) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((
            read_trimmed(mandate)?,
            read_trimmed(checkout)?,
            read_jwk(user_key)?,
            read_jwk(merchant_key)?,
        ))
    })();
    let (mandate_str, checkout_str, user_jwk, merchant_jwk) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;

    match ap2_verify::verify_checkout_mandate(
        &mandate_str,
        &checkout_str,
        &user_jwk,
        &merchant_jwk,
        now,
        DEFAULT_LEEWAY_SECONDS,
    ) {
        Ok(verified) => {
            println!("checkout mandate: OK");
            println!("checkout_hash: {}", verified.checkout_hash);
            println!("iat: {:?}", verified.iat);
            println!("exp: {:?}", verified.exp);
            println!(
                "checkout claims:\n{}",
                serde_json::to_string_pretty(&verified.checkout_claims).unwrap()
            );
            ExitCode::from(EXIT_VALID)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(e.exit_code())
        }
    }
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
        Command::VerifyCheckout {
            mandate,
            checkout,
            user_key,
            merchant_key,
        } => run_verify_checkout(&mandate, &checkout, &user_key, &merchant_key),
        _ => {
            eprintln!("not yet implemented");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
