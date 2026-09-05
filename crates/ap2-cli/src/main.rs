use ap2_credentials::{sha256_base64url, Jwk};
use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// Exit codes are stable and documented: 0 valid, 1 verification failed,
/// 2 malformed input / CLI usage, 3 unsupported protocol/version.
const EXIT_VALID: u8 = 0;
const EXIT_VERIFICATION_FAILED: u8 = 1;
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
        /// Path to the User/Agent's JWK.
        #[arg(long)]
        user_key: String,
        /// Path to the Merchant's JWK.
        #[arg(long)]
        merchant_key: String,
    },
    /// Verify a `~~`-joined dSD-JWT delegation chain (e.g. an Open Checkout
    /// Mandate delegating to a Checkout Mandate).
    VerifyChain {
        chain: String,
        /// Path to the root hop's verifying JWK.
        #[arg(long)]
        root_key: String,
        #[arg(long)]
        aud: String,
        #[arg(long)]
        nonce: String,
    },
    /// Verify an Open Checkout Mandate + Checkout Mandate delegation chain,
    /// including checkout constraint policy (allowed merchants, line items).
    VerifyCheckoutChain {
        chain: String,
        #[arg(long)]
        root_key: String,
        #[arg(long)]
        aud: String,
        #[arg(long)]
        nonce: String,
        /// Path to the merchant-signed Checkout JWT to check constraints
        /// against and bind via checkout_hash.
        #[arg(long)]
        checkout: String,
    },
    /// Verify an Open Payment Mandate + Payment Mandate delegation chain,
    /// including payment constraint policy (amount range, budget, ...).
    VerifyPaymentChain {
        chain: String,
        #[arg(long)]
        root_key: String,
        #[arg(long)]
        aud: String,
        #[arg(long)]
        nonce: String,
        /// Digest of the associated Open Checkout Mandate, for
        /// PaymentReference constraints.
        #[arg(long)]
        open_checkout_hash: Option<String>,
        /// Cumulative amount already spent under this mandate (minor
        /// units), for Budget constraints.
        #[arg(long)]
        total_amount: Option<i64>,
        /// Number of times this mandate has already been used, for
        /// AgentRecurrence constraints.
        #[arg(long)]
        total_uses: Option<u32>,
    },
    /// Verify a Checkout Receipt's signature (a plain JWT, not an SD-JWT).
    VerifyCheckoutReceipt {
        receipt: String,
        #[arg(long)]
        issuer_key: String,
        /// Expected `reference` (hash of the closed mandate it binds to).
        #[arg(long)]
        reference: Option<String>,
    },
    /// Verify a Payment Receipt's signature (a plain JWT, not an SD-JWT).
    VerifyPaymentReceipt {
        receipt: String,
        #[arg(long)]
        issuer_key: String,
        #[arg(long)]
        reference: Option<String>,
    },
    /// Inspect a Checkout or Payment Receipt.
    InspectReceipt { receipt: String },
}

/// Current time as a Unix timestamp, for exp/iat checks.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
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

    let now = now_unix();

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

fn run_verify_chain(chain_path: &str, root_key_path: &str, aud: &str, nonce: &str) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((read_trimmed(chain_path)?, read_jwk(root_key_path)?))
    })();
    let (chain, root_key) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match ap2_verify::verify_chain(
        &chain,
        &root_key,
        now_unix(),
        DEFAULT_LEEWAY_SECONDS,
        aud,
        nonce,
    ) {
        Ok(payloads) => {
            println!("chain: OK ({} effective payload(s))", payloads.len());
            for (i, payload) in payloads.into_iter().enumerate() {
                let value = serde_json::Value::Object(payload);
                println!("[{i}] {}", serde_json::to_string_pretty(&value).unwrap());
            }
            ExitCode::from(EXIT_VALID)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn run_verify_checkout_chain(
    chain_path: &str,
    root_key_path: &str,
    aud: &str,
    nonce: &str,
    checkout_path: &str,
) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((
            read_trimmed(chain_path)?,
            read_jwk(root_key_path)?,
            read_trimmed(checkout_path)?,
        ))
    })();
    let (chain, root_key, checkout_jwt) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let payloads = match ap2_verify::verify_chain(
        &chain,
        &root_key,
        now_unix(),
        DEFAULT_LEEWAY_SECONDS,
        aud,
        nonce,
    ) {
        Ok(payloads) => payloads,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(e.exit_code());
        }
    };

    let mandate_chain = match ap2_verify::CheckoutMandateChain::parse(payloads) {
        Ok(mandate_chain) => mandate_chain,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(e.exit_code());
        }
    };

    let expected_checkout_hash = sha256_base64url(&checkout_jwt);
    let violations = mandate_chain.verify(Some(&expected_checkout_hash), Some(&checkout_jwt));

    if violations.is_empty() {
        println!("checkout chain: OK");
        ExitCode::from(EXIT_VALID)
    } else {
        for violation in &violations {
            eprintln!("{violation}");
        }
        ExitCode::from(EXIT_VERIFICATION_FAILED)
    }
}

fn run_verify_payment(
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

    match ap2_verify::verify_payment_mandate(
        &mandate_str,
        &checkout_str,
        &user_jwk,
        &merchant_jwk,
        now_unix(),
        DEFAULT_LEEWAY_SECONDS,
    ) {
        Ok(verified) => {
            let payee = &verified.payment_mandate.payee.name;
            let amount = &verified.payment_mandate.payment_amount;
            println!("payment mandate: OK");
            println!("transaction_id: {}", verified.transaction_id);
            println!("iat: {:?}", verified.iat);
            println!("exp: {:?}", verified.exp);
            println!("payee: {payee}");
            println!("payment_amount: {} {}", amount.amount, amount.currency);
            ExitCode::from(EXIT_VALID)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(e.exit_code())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_verify_payment_chain(
    chain_path: &str,
    root_key_path: &str,
    aud: &str,
    nonce: &str,
    open_checkout_hash: Option<&str>,
    total_amount: Option<i64>,
    total_uses: Option<u32>,
) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((read_trimmed(chain_path)?, read_jwk(root_key_path)?))
    })();
    let (chain, root_key) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let payloads = match ap2_verify::verify_chain(
        &chain,
        &root_key,
        now_unix(),
        DEFAULT_LEEWAY_SECONDS,
        aud,
        nonce,
    ) {
        Ok(payloads) => payloads,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(e.exit_code());
        }
    };

    let mandate_chain = match ap2_verify::PaymentMandateChain::parse(payloads) {
        Ok(mandate_chain) => mandate_chain,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(e.exit_code());
        }
    };

    // Only built when the caller actually supplied usage data -- absent
    // context correctly surfaces as "missing context" violations for any
    // recurrence/budget constraint that needs it.
    let context =
        (total_amount.is_some() || total_uses.is_some()).then(|| ap2_verify::MandateContext {
            total_amount: total_amount.unwrap_or(0),
            total_uses: total_uses.unwrap_or(0),
        });

    let violations = mandate_chain.verify(open_checkout_hash, context.as_ref());

    if violations.is_empty() {
        println!("payment chain: OK");
        ExitCode::from(EXIT_VALID)
    } else {
        for violation in &violations {
            eprintln!("{violation}");
        }
        ExitCode::from(EXIT_VERIFICATION_FAILED)
    }
}

fn run_verify_checkout_receipt(
    receipt_path: &str,
    issuer_key_path: &str,
    reference: Option<&str>,
) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((read_trimmed(receipt_path)?, read_jwk(issuer_key_path)?))
    })();
    let (receipt_jwt, issuer_key) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match ap2_verify::verify_checkout_receipt(&receipt_jwt, &issuer_key, reference) {
        Ok(receipt) => {
            println!("checkout receipt: OK");
            println!("status: {:?}", receipt.status());
            println!("iss: {}", receipt.iss);
            println!("reference: {}", receipt.reference);
            ExitCode::from(EXIT_VALID)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn run_verify_payment_receipt(
    receipt_path: &str,
    issuer_key_path: &str,
    reference: Option<&str>,
) -> ExitCode {
    let inputs = (|| -> Result<_, CliInputError> {
        Ok((read_trimmed(receipt_path)?, read_jwk(issuer_key_path)?))
    })();
    let (receipt_jwt, issuer_key) = match inputs {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match ap2_verify::verify_payment_receipt(&receipt_jwt, &issuer_key, reference) {
        Ok(receipt) => {
            println!("payment receipt: OK");
            println!("status: {:?}", receipt.status());
            println!("iss: {}", receipt.iss);
            println!("reference: {}", receipt.reference);
            println!("payment_id: {}", receipt.payment_id);
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
        Command::VerifyChain {
            chain,
            root_key,
            aud,
            nonce,
        } => run_verify_chain(&chain, &root_key, &aud, &nonce),
        Command::VerifyCheckoutChain {
            chain,
            root_key,
            aud,
            nonce,
            checkout,
        } => run_verify_checkout_chain(&chain, &root_key, &aud, &nonce, &checkout),
        Command::VerifyPayment {
            mandate,
            checkout,
            user_key,
            merchant_key,
        } => run_verify_payment(&mandate, &checkout, &user_key, &merchant_key),
        Command::VerifyPaymentChain {
            chain,
            root_key,
            aud,
            nonce,
            open_checkout_hash,
            total_amount,
            total_uses,
        } => run_verify_payment_chain(
            &chain,
            &root_key,
            &aud,
            &nonce,
            open_checkout_hash.as_deref(),
            total_amount,
            total_uses,
        ),
        Command::VerifyCheckoutReceipt {
            receipt,
            issuer_key,
            reference,
        } => run_verify_checkout_receipt(&receipt, &issuer_key, reference.as_deref()),
        Command::VerifyPaymentReceipt {
            receipt,
            issuer_key,
            reference,
        } => run_verify_payment_receipt(&receipt, &issuer_key, reference.as_deref()),
        _ => {
            eprintln!("not yet implemented");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
