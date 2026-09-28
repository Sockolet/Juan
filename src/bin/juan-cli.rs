use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use juan::{
    archive::Format,
    capture::CaptureStore,
    har::ExportMode,
    proxy::{self, ProxyConfig},
    saz,
};

#[cfg(windows)]
use juan::windows::system;

const HELP: &str = concat!(
    "Juan ",
    env!("CARGO_PKG_VERSION"),
    " - HTTP(S) debugging proxy

USAGE
  juan-cli capture [OPTIONS]
  juan-cli inspect <input.har|input.saz> [--export <output.har|output.saz>] [--full]
  juan-cli cert export <new-file.pem>
  juan-cli cert trust
  juan-cli cert remove
  juan-cli cert reset
  juan-cli proxy restore

CAPTURE OPTIONS
  --port <port>          Loopback port (default: 8866)
  --https                Decrypt HTTPS using the local CA (does NOT install trust)
  --system-proxy         Explicitly route proxy-aware Windows apps through Juan
  --duration <seconds>   Stop after a bounded capture period; otherwise Ctrl+C
  --export <file>        Export retained sessions as .har or .saz when capture stops
  --full                Include sensitive headers and retained bodies in the export
  --full-har            Backward-compatible alias for --full
  -h, --help             Show this help

Completed sessions are emitted as JSON lines on stdout; diagnostics use stderr.
HTTP and HTTPS forwarding is streamed. Capture storage is bounded to 1,000
sessions, 1 MB per body and 64 MB of total body bytes. Paused/evicted content is
not recoverable. No traffic is written to disk unless you request an export.
SAZ import/export supports unencrypted Stored/Deflate archives. The inspect
command also reads HAR 1.2 (128 MiB input limit). HAR bodies are browser-exported
representations, not wire capture. HAR-origin SAZ export is not supported. The inspect
command is offline: it does not start a listener, recover proxy settings, or
change certificate trust, and can run alongside the desktop.

HTTPS decryption requires explicit client trust in Juan's unique local CA.
Use only for traffic you are authorized to inspect. Bodies and URLs may contain
credentials. Sanitized exports omit bodies and common credential fields,
but still need human review before sharing.

This is an explicit proxy, not a packet sniffer. Apps must use its proxy address.
HTTP/3, TLS pinning, mTLS decryption, NTLM/Negotiate inspection and upstream
proxy chaining are not supported.
"
);

fn main() {
    if let Err(error) = run() {
        eprintln!("Juan: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        print!("{HELP}");
        return Ok(());
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("Juan {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args[0] == "inspect" {
        return inspect_archive(&args[1..]);
    }
    #[cfg(windows)]
    let _instance = system::SingleInstance::acquire()?;
    #[cfg(windows)]
    if let Some(message) = system::recover_proxy()? {
        eprintln!("{message}");
    }
    match args[0].as_str() {
        "capture" => {
            if args[1..]
                .iter()
                .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
            {
                print!("{HELP}");
                return Ok(());
            }
            let options = parse_capture(&args[1..])?;
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("Create proxy runtime")?
                .block_on(capture(options))
        }
        #[cfg(windows)]
        "cert" => certificate_command(&args[1..]),
        #[cfg(windows)]
        "proxy" if args.get(1).map(String::as_str) == Some("restore") && args.len() == 2 => {
            println!("Proxy recovery is complete; no pending Juan settings remain.");
            Ok(())
        }
        _ => bail!("Unknown command. Use juan-cli --help."),
    }
}

struct Options {
    port: u16,
    https: bool,
    system_proxy: bool,
    duration: Option<Duration>,
    export: Option<PathBuf>,
    mode: ExportMode,
}

fn parse_capture(args: &[String]) -> Result<Options> {
    let mut options = Options {
        port: 8866,
        https: false,
        system_proxy: false,
        duration: None,
        export: None,
        mode: ExportMode::Sanitized,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                options.port = args
                    .next()
                    .context("--port requires a number")?
                    .parse()
                    .context("Port must be 1 through 65535")?;
                ensure!(options.port != 0, "Port must not be zero");
            }
            "--https" => options.https = true,
            "--system-proxy" => options.system_proxy = true,
            "--duration" => {
                let seconds = args
                    .next()
                    .context("--duration requires seconds")?
                    .parse::<u64>()
                    .context("Duration must be a positive whole number of seconds")?;
                let duration = Duration::from_secs(seconds);
                ensure!(
                    seconds > 0 && std::time::Instant::now().checked_add(duration).is_some(),
                    "Invalid capture duration"
                );
                options.duration = Some(duration);
            }
            "--export" => {
                options.export = Some(PathBuf::from(
                    args.next().context("--export requires a filename")?,
                ))
            }
            "--full" | "--full-har" => options.mode = ExportMode::Full,
            _ => bail!("Unknown capture option '{arg}'"),
        }
    }
    ensure!(
        options.mode != ExportMode::Full || options.export.is_some(),
        "--full requires --export"
    );
    Ok(options)
}

async fn capture(options: Options) -> Result<()> {
    let store = Arc::new(CaptureStore::default());
    let mut config = ProxyConfig {
        listen: ([127, 0, 0, 1], options.port).into(),
        ..ProxyConfig::default()
    };
    if options.https {
        #[cfg(windows)]
        {
            let ca = system::load_or_create_ca()?;
            eprintln!("HTTPS decryption enabled. CA SHA-256: {}", ca.fingerprint());
            eprintln!("No certificate trust has been installed by this command.");
            config.certificate = Some(ca);
        }
        #[cfg(not(windows))]
        bail!("Persistent HTTPS interception currently requires Windows");
    }
    let handle = proxy::start(config, store.clone()).await?;
    #[cfg(windows)]
    let mut lease = if options.system_proxy {
        match system::ProxyLease::enable(handle.address()) {
            Ok(lease) => Some(lease),
            Err(error) => {
                handle.shutdown().await?;
                return Err(error);
            }
        }
    } else {
        None
    };
    #[cfg(not(windows))]
    ensure!(
        !options.system_proxy,
        "Windows system proxy integration is unavailable on this platform"
    );
    eprintln!(
        "Juan is listening on http://{}. Press Ctrl+C to stop.",
        handle.address()
    );
    let mut printed = BTreeSet::new();
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(signal);
    let deadline = async {
        if let Some(duration) = options.duration {
            tokio::time::sleep(duration).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(deadline);
    let capture_result = loop {
        tokio::select! {
            result = &mut signal => break result.context("Wait for Ctrl+C"),
            _ = &mut deadline => break Ok(()),
            _ = timer.tick() => {
                if let Err(error) = emit_sessions(&store, &mut printed) { break Err(error); }
                if !handle.running() { break Err(anyhow::anyhow!("The proxy listener stopped unexpectedly")); }
            }
        }
    };
    #[cfg(windows)]
    let restoration = if let Some(lease) = lease.as_mut() {
        lease.restore().map(|message| eprintln!("{message}"))
    } else {
        Ok(())
    };
    let stopped = handle.shutdown().await;
    let emitted = emit_sessions(&store, &mut printed);
    let exported = if let Some(path) = &options.export {
        Format::from_path(path)
            .export(path, &store.all_sessions(), options.mode)
            .map(|()| eprintln!("Saved {}.", path.display()))
    } else {
        Ok(())
    };
    let snapshot = store.snapshot();
    eprintln!(
        "Stopped. {} sessions retained; {} evicted; {} body bytes retained.",
        snapshot.sessions.len(),
        snapshot.evicted,
        snapshot.retained_bytes
    );
    #[cfg(windows)]
    restoration.context("Windows proxy restoration failed; run juan-cli proxy restore or restore Windows proxy settings manually")?;
    stopped?;
    exported?;
    emitted?;
    capture_result
}

fn inspect_archive(args: &[String]) -> Result<()> {
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{HELP}");
        return Ok(());
    }
    let input = PathBuf::from(
        args.first()
            .context("inspect requires an input .har or .saz filename")?,
    );
    let mut output = None;
    let mut mode = ExportMode::Sanitized;
    let mut args = args[1..].iter();
    while let Some(option) = args.next() {
        match option.as_str() {
            "--export" => {
                output = Some(PathBuf::from(
                    args.next().context("--export requires a filename")?,
                ))
            }
            "--full" | "--full-har" => mode = ExportMode::Full,
            _ => bail!("Unknown inspect option '{option}'"),
        }
    }
    ensure!(
        mode != ExportMode::Full || output.is_some(),
        "--full requires --export"
    );
    let imported = juan::archive::load(&input, saz::Limits::default())?;
    for warning in &imported.warnings {
        eprintln!("Archive: {warning}");
    }
    let store = CaptureStore::default();
    store.replace_from_archive(imported.sessions)?;
    emit_sessions(&store, &mut BTreeSet::new())?;
    if let Some(path) = output {
        Format::from_path(&path).export(&path, &store.all_sessions(), mode)?;
        eprintln!("Saved {}.", path.display());
    }
    eprintln!(
        "Opened {} archived sessions without starting a proxy.",
        store.snapshot().sessions.len()
    );
    Ok(())
}

fn emit_sessions(store: &CaptureStore, printed: &mut BTreeSet<u64>) -> Result<()> {
    let snapshot = store.snapshot();
    if let Some(first) = snapshot.sessions.first() {
        printed.retain(|id| *id >= first.id);
    }
    let mut stdout = io::stdout().lock();
    for session in snapshot.sessions {
        if session.complete && printed.insert(session.id) {
            let mut row = serde_json::json!({
                "id": session.id,
                "method": session.method,
                "url": session.url,
                "status": session.status,
                "bytes": session.bytes,
                "elapsedMs": session.elapsed_ms,
                "proxyError": session.failed,
            });
            if let Some(har) = &session.har {
                row["har"] = serde_json::to_value(har)?;
                row["elapsedMs"] = if har.time >= 0.0 {
                    serde_json::json!(har.time)
                } else {
                    serde_json::Value::Null
                };
                row["proxyError"] = serde_json::json!(false);
                row["sourceError"] = serde_json::json!(session.failed);
            }
            serde_json::to_writer(&mut stdout, &row)?;
            stdout.write_all(b"\n")?;
        }
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(windows)]
fn certificate_command(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("export") if args.len() == 2 => {
            let ca = system::load_or_create_ca()?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[1])
                .context("Create public CA export (choose a new filename)")?;
            output.write_all(ca.pem().as_bytes())?;
            output.sync_all()?;
            println!(
                "Exported public CA to {}. No private key was exported and no trust was installed.",
                args[1]
            );
            Ok(())
        }
        Some("trust") if args.len() == 1 => {
            let ca = system::load_or_create_ca()?;
            eprintln!("CA SHA-256: {}", ca.fingerprint());
            confirm(
                "Trust permits HTTPS interception for apps using your Windows user trust store. Type TRUST to continue:",
                "TRUST",
            )?;
            system::trust_certificate(&ca)?;
            println!("Trusted Juan's CA for the current Windows user only.");
            Ok(())
        }
        Some("remove") if args.len() == 1 => {
            let der = system::stored_ca_der()?.context("There is no local Juan CA")?;
            confirm(
                "Remove trust in this Juan CA? Type REMOVE to continue:",
                "REMOVE",
            )?;
            let removed = system::untrust_certificate(&der)?;
            println!(
                "{}",
                if removed {
                    "Removed trust in Juan's CA."
                } else {
                    "This Juan CA was not trusted."
                }
            );
            Ok(())
        }
        Some("reset") if args.len() == 1 => {
            confirm(
                "Delete Juan's local CA key? Remove trust first. Type RESET to continue:",
                "RESET",
            )?;
            system::reset_ca()?;
            println!("Local CA reset. A new unique CA will be generated when requested.");
            Ok(())
        }
        _ => bail!("Use cert export <new-file.pem>, cert trust, cert remove, or cert reset."),
    }
}

#[cfg(windows)]
fn confirm(message: &str, expected: &str) -> Result<()> {
    eprintln!("{message}");
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    ensure!(
        answer.trim() == expected,
        "Cancelled without changing certificate trust"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_options_are_errors() {
        for args in [
            vec!["--port", "0"],
            vec!["--duration", "0"],
            vec!["--full-har"],
            vec!["--unknown"],
        ] {
            assert!(
                parse_capture(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err()
            );
        }
    }
}
