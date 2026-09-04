# ap2-rs

Type-safe, spec-driven Rust implementation of the [Agentic Payment Protocol (AP2)](https://github.com/google-agentic-commerce/AP2), interoperable with the official Google reference implementation.

Status: early scaffold, not yet functional. Not a wallet, payment processor, or agent framework.

AP2 spec version `0.2`, pinned at commit [`e1ea56d`](https://github.com/google-agentic-commerce/AP2/commit/e1ea56db72a6385bce3e5c1112b3a56ce60acb43). See [`spec/upstream.json`](spec/upstream.json).

## Layout

- `crates/ap2-core` protocol types
- `crates/ap2-credentials` JWT/SD-JWT mechanics
- `crates/ap2-verify` deterministic verification
- `crates/ap2-cli` the `ap2` CLI
- `xtask` spec sync tooling

```bash
cargo build --workspace
cargo test --workspace
cargo xtask sync-spec
cargo xtask check-drift
```

## License

Apache-2.0. See [LICENSE](LICENSE).
