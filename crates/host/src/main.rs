use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::{Parser, Subcommand};
use iroh::EndpointId;
use tokio::net::UnixListener;
use tracing::{error, info};

use phonetpm::agekey::{Identity, Recipient};
use phonetpm::config::{self, Config};
use phonetpm::control;
use phonetpm::proto::{KeyInfo, KeyKind, Request, Response};
use phonetpm::sshagent::{self, Agent};
use phonetpm::transport::{self, Phone};

#[derive(Parser)]
#[command(version, about = "Use your phone's hardware keys as an ssh-agent and age identity")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pair this host with a phone (approve the request on the phone).
    Pair {
        /// The phone's endpoint id, as shown in the app.
        phone: EndpointId,
    },
    /// Run the daemon serving the ssh-agent and control sockets.
    Daemon,
    /// List the phone's keys (requires a running daemon).
    Keys,
    /// Print an age identity file for the given key id or label.
    Identity { key: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::Pair { phone } => runtime()?.block_on(pair(phone)),
        Cmd::Daemon => runtime()?.block_on(daemon()),
        Cmd::Keys => keys(),
        Cmd::Identity { key } => identity(&key),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let name = if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).trim().to_owned()
    } else {
        String::new()
    };
    if name.is_empty() { "host".to_owned() } else { name }
}

async fn pair(phone_id: EndpointId) -> Result<()> {
    let secret = config::load_or_create_secret()?;
    let host_name = hostname();
    config::save_config(&Config { phone: phone_id.to_string(), host_name: host_name.clone() })?;
    let endpoint = transport::bind(secret).await?;
    println!("this host: {}", endpoint.id());
    println!("connecting to phone {phone_id}; approve the pairing request on the phone...");
    let phone = Phone::new(endpoint, phone_id);
    let resp = phone.request(&Request::Pair { host_name }).await;
    phone.endpoint().close().await;
    match resp? {
        Response::Paired => {
            println!("paired.");
            println!();
            println!("Next:");
            println!("  phonetpm daemon &");
            println!("  export SSH_AUTH_SOCK={}", config::agent_sock_path().display());
            Ok(())
        }
        Response::Denied => bail!("pairing denied on the phone"),
        other => bail!("unexpected response to Pair: {other:?}"),
    }
}

/// Removes a stale socket file, refusing if another daemon still answers on it.
fn reclaim_socket(path: &Path) -> Result<()> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!("another phonetpm daemon is listening on {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => std::fs::remove_file(path).with_context(|| format!("removing {}", path.display())),
    }
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    reclaim_socket(path)?;
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn daemon() -> Result<()> {
    let cfg = config::load_config()?;
    let phone_id = cfg.phone_id()?;
    let secret = config::load_secret()?;
    let endpoint = transport::bind(secret).await?;
    info!(host = %endpoint.id(), phone = %phone_id, "endpoint bound");
    let phone = Arc::new(Phone::new(endpoint, phone_id));

    let dir = config::ensure_runtime_dir()?;
    let agent_path = dir.join(config::AGENT_SOCK);
    let control_path = dir.join(config::CONTROL_SOCK);
    let agent_listener = bind_socket(&agent_path)?;
    let control_listener = bind_socket(&control_path)?;
    info!(agent = %agent_path.display(), control = %control_path.display(), "listening");

    let agent = Arc::new(Agent::new(phone.clone()));
    let agent_task = tokio::spawn(sshagent::serve(agent_listener, agent));
    let control_task = tokio::spawn(control::serve(control_listener, phone.clone()));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
        _ = sigterm.recv() => info!("SIGTERM received"),
        r = agent_task => error!("agent listener stopped: {r:?}"),
        r = control_task => error!("control listener stopped: {r:?}"),
    }
    let _ = std::fs::remove_file(&agent_path);
    let _ = std::fs::remove_file(&control_path);
    phone.endpoint().close().await;
    Ok(())
}

fn list_keys() -> Result<Vec<KeyInfo>> {
    match control::Client::connect()?.request(&Request::ListKeys)? {
        Response::Keys(keys) => Ok(keys),
        Response::Denied => bail!("phone denied the request; is this host paired?"),
        Response::Error(e) => bail!("daemon: {e}"),
        other => bail!("unexpected response to ListKeys: {other:?}"),
    }
}

fn keys() -> Result<()> {
    let keys = list_keys()?;
    if keys.is_empty() {
        println!("no keys on the phone");
    }
    for key in keys {
        match key.kind {
            KeyKind::Ssh => {
                let point = sshagent::spki_to_point(&key.public_key)?;
                let blob = BASE64_STANDARD.encode(sshagent::key_blob(&point));
                println!("{} {blob} {}", sshagent::KEY_TYPE, key.label);
            }
            KeyKind::Age => {
                let recipient = Recipient::from_spki(&key.public_key)?;
                println!("{}  {} ({})", recipient.encode(), key.label, key.id);
            }
        }
    }
    Ok(())
}

fn identity(wanted: &str) -> Result<()> {
    let keys = list_keys()?;
    let key = keys
        .iter()
        .find(|k| k.id == wanted)
        .or_else(|| keys.iter().find(|k| k.label == wanted))
        .ok_or_else(|| anyhow!("no key with id or label {wanted:?}; see `phonetpm keys`"))?;
    if key.kind != KeyKind::Age {
        bail!("key {wanted:?} is an SSH key, not an age key");
    }
    let recipient = Recipient::from_spki(&key.public_key)?;
    let identity = Identity::new(recipient.clone(), key.id.clone());
    println!("# phonetpm key: {} ({})", key.label, key.id);
    println!("# public key: {}", recipient.encode());
    println!("{}", identity.encode());
    Ok(())
}
