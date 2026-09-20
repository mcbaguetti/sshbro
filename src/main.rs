use clap::{Parser, Subcommand};
use ssh_key::PublicKey;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Parser)]
#[command(name = "sshbro", version, about = "A small SSH key manager")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List managed SSH key pairs.
    List,

    /// Add an existing private/public key pair.
    Add {
        /// Path to the private key, e.g. ~/.ssh/id_ed25519
        private_key: PathBuf,
    },

    /// Generate a new Ed25519 SSH key pair.
    #[command(alias = "gen")]
    Generate {
        /// Key name without the .pub suffix.
        name: String,

        /// Generate an unencrypted private key without prompting.
        #[arg(long)]
        no_passphrase: bool,
    },

    /// Show details for a managed SSH key pair.
    Show {
        /// Key name without the .pub suffix.
        name: String,
    },

    /// Print a managed public key in OpenSSH format.
    Export {
        /// Key name without the .pub suffix.
        name: String,

        /// Remote SSH destination, for example user@203.0.113.10.
        destination: Option<String>,
    },

    /// Manage a key loaded in ssh-agent.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// Remove a managed key pair by name, e.g. id_ed25519.
    #[command(alias = "delete", alias = "rm")]
    Remove {
        /// Key name without the .pub suffix.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Show whether ssh-agent is available and list loaded keys.
    Status,

    /// Load a managed private key into ssh-agent.
    Add {
        /// Key name without the .pub suffix.
        name: String,
    },

    /// Remove a managed private key from ssh-agent.
    Remove {
        /// Key name without the .pub suffix.
        name: String,
    },
}

#[derive(Debug)]
struct KeyInfo {
    name: String,
    private_path: PathBuf,
    public_path: PathBuf,
    fingerprint: Option<String>,
    comment: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let dir = managed_dir()?;
    ensure_managed_dir(&dir)?;

    match cli.command {
        Command::List => list_keys(&dir)?,
        Command::Add { private_key } => add_key(&dir, &private_key)?,
        Command::Generate {
            name,
            no_passphrase,
        } => generate_key(&dir, &name, no_passphrase)?,
        Command::Show { name } => show_key(&dir, &name)?,
        Command::Export { name, destination } => export_key(&dir, &name, destination.as_deref())?,
        Command::Agent { command } => match command {
            AgentCommand::Status => agent_status()?,
            AgentCommand::Add { name } => agent_add(&dir, &name)?,
            AgentCommand::Remove { name } => agent_remove(&dir, &name)?,
        },
        Command::Remove { name } => remove_key(&dir, &name)?,
    }

    Ok(())
}

fn paths_for_key(dir: &Path, name: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    if !is_safe_name(name) {
        return Err("invalid key name; use a simple filename without path separators".into());
    }

    Ok((dir.join(name), dir.join(format!("{name}.pub"))))
}

fn generate_key(
    dir: &Path,
    name: &str,
    no_passphrase: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (private_path, public_path) = paths_for_key(dir, name)?;
    if private_path.exists() || public_path.exists() {
        return Err(format!("a managed key named '{name}' already exists").into());
    }

    let mut command = ProcessCommand::new("ssh-keygen");
    command
        .args(["-q", "-t", "ed25519", "-f"])
        .arg(&private_path)
        .args(["-C", name]);
    if no_passphrase {
        command.args(["-N", ""]);
    }

    let status = command
        .status()
        .map_err(|err| format!("could not run ssh-keygen: {err}"))?;

    if !status.success() {
        return Err(format!("ssh-keygen failed while generating '{name}'").into());
    }

    restrict_private_permissions(&private_path)?;
    println!("Generated {name}");
    println!("  private: {}", private_path.display());
    println!("  public:  {}", public_path.display());
    Ok(())
}

fn show_key(dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (private_path, public_path) = paths_for_key(dir, name)?;
    if !private_path.is_file() || !public_path.is_file() {
        return Err(format!("managed key not found: {name}").into());
    }

    let (fingerprint, comment) = read_public_info(&public_path);
    println!("{name}");
    println!("  private: {}", private_path.display());
    println!("  public:  {}", public_path.display());
    if let Some(comment) = comment.filter(|comment| !comment.is_empty()) {
        println!("  comment: {comment}");
    }
    if let Some(fingerprint) = fingerprint {
        println!("  fingerprint: {fingerprint}");
    }
    Ok(())
}

fn export_key(
    dir: &Path,
    name: &str,
    destination: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, public_path) = paths_for_key(dir, name)?;
    if !public_path.is_file() {
        return Err(format!("managed public key not found: {name}").into());
    }

    let contents = fs::read_to_string(&public_path)?;
    let public_key = contents
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or("public key file is empty")?;
    let public_key = public_key.trim();
    PublicKey::from_openssh(public_key)?;

    if let Some(destination) = destination {
        install_public_key(destination, public_key)?;
        println!("Installed {name} on {destination}");
    } else {
        println!("{public_key}");
    }
    Ok(())
}

fn install_public_key(
    destination: &str,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if destination.is_empty()
        || destination.starts_with('-')
        || destination
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("invalid destination; use a value such as user@203.0.113.10".into());
    }

    // The public key is passed over standard input, never interpolated into the remote shell command.
    // A temporary file lets the remote side compare it before appending, preventing duplicate entries.
    const INSTALL_COMMAND: &str = "set -eu; temp=$(mktemp); trap 'rm -f \"$temp\"' EXIT; cat > \"$temp\"; mkdir -p \"$HOME/.ssh\"; chmod 700 \"$HOME/.ssh\"; touch \"$HOME/.ssh/authorized_keys\"; chmod 600 \"$HOME/.ssh/authorized_keys\"; grep -qxF -f \"$temp\" \"$HOME/.ssh/authorized_keys\" || cat \"$temp\" >> \"$HOME/.ssh/authorized_keys\"";

    let mut child = ProcessCommand::new("ssh")
        .arg(destination)
        .arg(INSTALL_COMMAND)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run ssh: {err}"))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or("could not open ssh standard input")?;
    writeln!(stdin, "{public_key}")?;
    drop(child.stdin.take());

    let status = child.wait()?;
    if !status.success() {
        return Err(format!("could not install the key on {destination}").into());
    }

    Ok(())
}

fn agent_add(dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_agent_available()?;
    run_ssh_add(dir, name, false)
}

fn agent_remove(dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_agent_available()?;
    run_ssh_add(dir, name, true)
}

fn agent_status() -> Result<(), Box<dyn std::error::Error>> {
    ensure_agent_available()?;
    let output = ProcessCommand::new("ssh-add")
        .arg("-l")
        .output()
        .map_err(|err| format!("could not run ssh-add: {err}"))?;

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.to_ascii_lowercase().contains("no identities") {
        println!("ssh-agent is running; no keys are loaded.");
        return Ok(());
    }

    Err(format!("could not determine ssh-agent status: {}", stderr.trim()).into())
}

fn ensure_agent_available() -> Result<(), Box<dyn std::error::Error>> {
    let output = ProcessCommand::new("ssh-add")
        .arg("-l")
        .output()
        .map_err(|err| format!("could not run ssh-add: {err}"))?;

    if !agent_unreachable(&output) {
        return Ok(());
    }

    #[cfg(windows)]
    {
        println!("ssh-agent is not running; trying to start the Windows service...");
        let _ = ProcessCommand::new("sc.exe")
            .args(["start", "ssh-agent"])
            .output();

        let retry = ProcessCommand::new("ssh-add")
            .arg("-l")
            .output()
            .map_err(|err| format!("could not run ssh-add after starting ssh-agent: {err}"))?;
        if !agent_unreachable(&retry) {
            return Ok(());
        }

        return Err(
            "ssh-agent is not available. Start the Windows OpenSSH Authentication Agent service, then try again."
                .into(),
        );
    }

    #[cfg(not(windows))]
    {
        Err(
            "ssh-agent is not available. Start one in this shell with: eval \"$(ssh-agent -s)\""
                .into(),
        )
    }
}

fn agent_unreachable(output: &std::process::Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stderr.contains("could not open a connection")
        || stderr.contains("not a valid authentication agent")
        || stderr.contains("error connecting to agent")
}

fn run_ssh_add(dir: &Path, name: &str, remove: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (private_path, _) = paths_for_key(dir, name)?;
    if !private_path.is_file() {
        return Err(format!("managed private key not found: {name}").into());
    }

    let mut command = ProcessCommand::new("ssh-add");
    if remove {
        command.arg("-d");
    }
    let status = command
        .arg(&private_path)
        .status()
        .map_err(|err| format!("could not run ssh-add: {err}"))?;

    if !status.success() {
        return Err(format!("ssh-add failed for '{name}'; make sure ssh-agent is running").into());
    }

    println!(
        "{} {name} {} ssh-agent",
        if remove { "Removed" } else { "Added" },
        if remove { "from" } else { "to" }
    );
    Ok(())
}

fn managed_dir() -> Result<PathBuf, &'static str> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".ssh").join("sshbro"))
}

fn ensure_managed_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;

    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    Ok(())
}

fn list_keys(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = Vec::new();

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "pub") {
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                let private_path = dir.join(name);
                if private_path.is_file() {
                    let (fingerprint, comment) = read_public_info(&path);
                    keys.push(KeyInfo {
                        name: name.to_owned(),
                        private_path,
                        public_path: path,
                        fingerprint,
                        comment,
                    });
                }
            }
        }
    }

    keys.sort_by(|a, b| a.name.cmp(&b.name));

    if keys.is_empty() {
        println!("No managed SSH keys.");
        println!("Directory: {}", dir.display());
        return Ok(());
    }

    for key in keys {
        println!("{}", key.name);
        println!("  private: {}", key.private_path.display());
        println!("  public:  {}", key.public_path.display());
        if let Some(comment) = key.comment {
            if !comment.is_empty() {
                println!("  comment: {comment}");
            }
        }
        if let Some(fingerprint) = key.fingerprint {
            println!("  fingerprint: {fingerprint}");
        }
        println!();
    }

    Ok(())
}

fn read_public_info(path: &Path) -> (Option<String>, Option<String>) {
    let Ok(contents) = fs::read_to_string(path) else {
        return (None, None);
    };

    let Some(line) = contents.lines().find(|line| !line.trim().is_empty()) else {
        return (None, None);
    };

    let Ok(public_key) = PublicKey::from_openssh(line.trim()) else {
        return (None, None);
    };

    let fingerprint = public_key.fingerprint(Default::default()).to_string();
    let comment = public_key.comment().to_owned();
    (Some(fingerprint), Some(comment))
}

fn add_key(dir: &Path, source: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !source.is_file() {
        return Err(format!("private key does not exist: {}", source.display()).into());
    }

    let name = source
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("private key has no usable file name")?;

    if !is_safe_name(name) || name.ends_with(".pub") {
        return Err("add expects a simple private-key filename, not a .pub file".into());
    }

    let public_source = source.with_file_name(format!("{name}.pub"));
    if !public_source.is_file() {
        return Err(format!("public key file is missing: {}", public_source.display()).into());
    }

    let destination_private = dir.join(name);
    let destination_public = dir.join(format!("{name}.pub"));

    if destination_private.exists() || destination_public.exists() {
        return Err(format!("a managed key named '{name}' already exists").into());
    }

    fs::copy(source, &destination_private)?;
    if let Err(err) = fs::copy(&public_source, &destination_public) {
        let _ = fs::remove_file(&destination_private);
        return Err(err.into());
    }

    restrict_private_permissions(&destination_private)?;

    println!("Added {name}");
    Ok(())
}

fn restrict_private_permissions(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn remove_key(dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_safe_name(name) {
        return Err("invalid key name; use a simple filename without path separators".into());
    }

    let private_path = dir.join(name);
    let public_path = dir.join(format!("{name}.pub"));

    if !private_path.is_file() && !public_path.is_file() {
        return Err(format!("managed key not found: {name}").into());
    }

    print!("Remove '{name}' and its public key? [y/N] ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Cancelled.");
        return Ok(());
    }

    if private_path.is_file() {
        fs::remove_file(private_path)?;
    }
    if public_path.is_file() {
        fs::remove_file(public_path)?;
    }

    println!("Removed {name}");
    Ok(())
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && Path::new(name).file_name().and_then(|s| s.to_str()) == Some(name)
}
