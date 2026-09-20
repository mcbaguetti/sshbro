# sshbro

A tiny local SSH key manager written in Rust.

## Scope of the first MVP

- Manages key pairs in `~/.ssh/sshbro/`.
- `list` shows managed pairs, comments, and SHA-256 fingerprints from the public key.
- `add` copies an existing private key and matching `.pub` file into the managed directory.
- `remove` deletes a managed pair after confirmation.
- `generate` creates a managed Ed25519 key pair with a chosen name.
- `show` displays the paths, comment, and fingerprint for one key.
- `export` prints a public key ready to paste into a service or `authorized_keys`.
- `agent add` and `agent remove` load or unload a managed key through `ssh-add`.
- On Unix, the managed directory is `0700` and private keys are `0600`.

This version does not touch `authorized_keys`, `known_hosts`, or existing
`~/.ssh` files outside its managed `~/.ssh/sshbro/` directory.

## Usage

```text
cargo run -- list
cargo run -- add ~/.ssh/`keypair_name`
cargo run -- generate `keypair_name`
cargo run -- show `keypair_name`
cargo run -- export `keypair_name`
cargo run -- agent add `keypair_name`
cargo run -- agent remove `keypair_name`
cargo run -- remove `keypair_name`
```

`add` expects a matching public key next to the private key, for example:

```text
~/.ssh/keypair_name
~/.ssh/keypair_name.pub
```

`generate` uses the system `ssh-keygen` command, while `agent` uses the system
`ssh-add` command. `ssh-agent` must be running for the agent commands to work.
