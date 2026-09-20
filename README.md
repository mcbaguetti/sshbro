# sshbro

A tiny local SSH key manager written in Rust.

## Scope of the first MVP

- Manages key pairs in `~/.ssh/sshbro/`.
- `list` shows managed pairs, comments, and SHA-256 fingerprints from the public key.
- `add` copies an existing private key and matching `.pub` file into the managed directory.
- `remove` (aliases `delete`, `rm`) deletes a managed pair after confirmation.
- `generate` (alias `gen`) creates a managed Ed25519 key pair with a chosen name.
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
cargo run -- generate `keypair_name`   # or: cargo run -- gen `keypair_name`
cargo run -- generate `keypair_name` --no-passphrase
cargo run -- show `keypair_name`
cargo run -- export `keypair_name`
cargo run -- export `keypair_name` user@203.0.113.10
cargo run -- agent add `keypair_name`
cargo run -- agent remove `keypair_name`
cargo run -- agent status
cargo run -- remove `keypair_name`     # aliases: delete, rm
```

`add` expects a matching public key next to the private key, for example:

```text
~/.ssh/keypair_name
~/.ssh/keypair_name.pub
```

`export keypair_name` prints the public key. Add a remote SSH destination to
install it in that account's `~/.ssh/authorized_keys` file:

```text
cargo run -- export keypair_name user@203.0.113.10
```

This requires the system `ssh` command and an existing way to authenticate to
the remote account. The remote account must allow that login and use a
Unix-like shell with `mktemp`, `grep`, and standard SSH file permissions.

`generate` uses the system `ssh-keygen` command and prompts for a key
passphrase plus confirmation by default. Use `--no-passphrase` only when an
unencrypted private key is intentional. `agent` uses the system `ssh-add`
command; it prompts for that same key passphrase before loading the key.

## ssh-agent requirement

The `agent add` and `agent remove` commands require the system `ssh-add`
program and a running `ssh-agent`. Verify the agent is available before using
those commands:

```text
ssh-add -l
```

`sshbro agent status` reports whether the agent is reachable and lists its
loaded keys. On Windows, `agent add`, `agent remove`, and `agent status` first
try to start the OpenSSH agent service automatically. If that fails, follow the
Windows setup instructions below.

On Windows, enable and start the built-in OpenSSH agent service from an
elevated PowerShell once:

```powershell
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

If `ssh-add` is not found, install the OpenSSH Client optional feature.
On macOS and most Linux distributions, start an agent for the current shell
when needed:

```sh
eval "$(ssh-agent -s)"
```

Help for the entire CLI and each command:

```text
cargo run -- --help
cargo run -- generate --help
cargo run -- agent --help
# Equivalent form: cargo run -- help generate
```
