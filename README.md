# cryptopals

Practicing Rust and Crypto with https://cryptopals.com/

## Solutions

- Set1 and the beginning of set2 are implemented in [main.rs](./src/main.rs)
  and related modules,
- Subsequent sets are implemented in [their respective directories](./src/set3).

## Usage

Run the whole test suite:

```
cargo test
```

For a specific test:

```
cargo test test_diffie_hellman -- --nocapture
```
