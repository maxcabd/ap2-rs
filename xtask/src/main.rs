//! Developer automation for ap2-rs.
//!
//! `cargo xtask sync-spec`      - fetch the pinned AP2 schemas into spec/schemas/.
//! `cargo xtask check-drift`    - report (non-blocking) whether upstream main
//!                                 has moved past the pinned commit.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct UpstreamPin {
    repository: String,
    commit: String,
    #[serde(default)]
    schema_paths: Vec<String>,
}

/// Paths are relative to `code/sdk/schemas/ap2/` in the upstream repository,
/// and to `spec/schemas/ap2/` locally.
const DEFAULT_SCHEMA_PATHS: &[&str] = &[
    "checkout_mandate.json",
    "checkout_receipt.json",
    "open_checkout_mandate.json",
    "open_payment_mandate.json",
    "payment_mandate.json",
    "payment_receipt.json",
    "types/amount.json",
    "types/item.json",
    "types/jwk.json",
    "types/merchant.json",
    "types/payment_instrument.json",
    "types/pisp.json",
    "types/receipt_status.json",
];

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("xtask should live one level below the workspace root")
        .to_path_buf()
}

fn load_pin(root: &Path) -> Result<UpstreamPin> {
    let path = root.join("spec/upstream.json");
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut pin: UpstreamPin =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if pin.schema_paths.is_empty() {
        pin.schema_paths = DEFAULT_SCHEMA_PATHS.iter().map(|s| s.to_string()).collect();
    }
    Ok(pin)
}

fn repo_owner_and_name(repository_url: &str) -> Result<(String, String)> {
    let trimmed = repository_url.trim_end_matches('/');
    let mut parts = trimmed.rsplit('/');
    let name = parts.next().context("malformed repository URL")?;
    let owner = parts.next().context("malformed repository URL")?;
    Ok((owner.to_string(), name.to_string()))
}

fn sync_spec() -> Result<()> {
    let root = workspace_root();
    let pin = load_pin(&root)?;
    let (owner, name) = repo_owner_and_name(&pin.repository)?;
    let schemas_dir = root.join("spec/schemas/ap2");

    let mut changed = Vec::new();
    let mut unchanged = 0usize;

    for rel_path in &pin.schema_paths {
        let url = format!(
            "https://raw.githubusercontent.com/{owner}/{name}/{commit}/code/sdk/schemas/ap2/{rel_path}",
            commit = pin.commit,
        );
        let body = ureq::get(&url)
            .call()
            .with_context(|| format!("fetching {url}"))?
            .into_string()
            .with_context(|| format!("reading response body for {url}"))?;

        let dest = schemas_dir.join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        let previous = fs::read_to_string(&dest).ok();
        if previous.as_deref() != Some(body.as_str()) {
            fs::write(&dest, &body).with_context(|| format!("writing {}", dest.display()))?;
            changed.push(rel_path.clone());
        } else {
            unchanged += 1;
        }
    }

    println!(
        "sync-spec: pinned commit {} ({}/{})",
        pin.commit, owner, name
    );
    println!("  unchanged: {unchanged}");
    if changed.is_empty() {
        println!("  changed:   none");
    } else {
        println!("  changed:   {}", changed.len());
        for c in &changed {
            println!("    - {c}");
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct CommitInfo {
    sha: String,
}

fn check_drift() -> Result<()> {
    let root = workspace_root();
    let pin = load_pin(&root)?;
    let (owner, name) = repo_owner_and_name(&pin.repository)?;

    let url = format!("https://api.github.com/repos/{owner}/{name}/commits/main");
    let info: CommitInfo = ureq::get(&url)
        .set("User-Agent", "ap2-rs-xtask")
        .call()
        .with_context(|| format!("fetching {url}"))?
        .into_json()
        .context("parsing GitHub commit response")?;

    if info.sha == pin.commit {
        println!("check-drift: up to date with upstream main ({})", info.sha);
    } else {
        println!("check-drift: NON-BLOCKING NOTICE");
        println!("  pinned commit: {}", pin.commit);
        println!("  upstream main: {}", info.sha);
        println!("  ap2-rs is pinned behind upstream main. This is expected and");
        println!("  intentional (main is not treated as immutable) but review");
        println!("  the diff before deciding whether to move the pin.");
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("sync-spec") => sync_spec(),
        Some("check-drift") => check_drift(),
        other => {
            eprintln!("usage: cargo xtask <sync-spec|check-drift>");
            if let Some(other) = other {
                eprintln!("unknown subcommand: {other}");
            }
            std::process::exit(2);
        }
    }
}
