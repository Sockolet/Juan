use std::{
    fs,
    io::{Read, Write},
    mem::size_of,
    net::SocketAddr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::*, Networking::WinInet::*, Security::Cryptography::*,
    Storage::FileSystem::MoveFileW, System::Threading::CreateMutexW,
};
use zeroize::{Zeroize, Zeroizing};

use crate::certificate::{CaMaterial, CertificateAuthority};

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn windows_error(action: &str) -> anyhow::Error {
    anyhow::Error::new(std::io::Error::last_os_error()).context(action.to_owned())
}

pub struct SingleInstance(Vec<HANDLE>);

impl SingleInstance {
    pub fn acquire() -> Result<Self> {
        Self::acquire_named(&[
            "Local\\Widdler.DebugProxy.SingleInstance",
            "Local\\Juan.DebugProxy.SingleInstance",
        ])
    }

    fn acquire_named(names: &[&str]) -> Result<Self> {
        let mut instance = Self(Vec::new());
        // SAFETY: The named handle is kept alive for the process lifetime; no raw handle escapes.
        unsafe {
            for name in names {
                let handle = CreateMutexW(null(), 0, wide(name).as_ptr());
                if handle.is_null() {
                    return Err(windows_error("Create Juan instance guard"));
                }
                if GetLastError() == ERROR_ALREADY_EXISTS {
                    CloseHandle(handle);
                    bail!(
                        "Juan or a legacy Widdler instance is already running in this Windows session. Save and close it before starting another instance."
                    );
                }
                instance.0.push(handle);
            }
        }
        Ok(instance)
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: This object exclusively owns these valid mutex handles.
        unsafe {
            for handle in self.0.drain(..) {
                CloseHandle(handle);
            }
        }
    }
}

pub fn data_directory() -> Result<PathBuf> {
    let parent =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not available")?);
    migrate_legacy_data(&parent)
}

fn migrate_legacy_data(parent: &Path) -> Result<PathBuf> {
    let directory = parent.join("Juan");
    let legacy = parent.join("Widdler");
    let files = ["root-ca.dpapi", "proxy-restore.dpapi"];
    for file in files {
        ensure!(
            !(legacy.join(file).try_exists()? && directory.join(file).try_exists()?),
            "Both Juan and legacy Widdler have {file}. Automatic migration stopped to preserve both states; resolve the duplicate before continuing."
        );
    }
    fs::create_dir_all(&directory).context("Create Juan's per-user data directory")?;
    for file in files {
        let source = legacy.join(file);
        if source.try_exists()? {
            let target = directory.join(file);
            let source_name: Vec<_> = source.as_os_str().encode_wide().chain(Some(0)).collect();
            let target_name: Vec<_> = target.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: Both terminated path buffers live through this synchronous, non-overwriting move.
            if unsafe { MoveFileW(source_name.as_ptr(), target_name.as_ptr()) } == 0 {
                return Err(windows_error(&format!(
                    "Migrate legacy {file} to Juan without overwriting existing state"
                )));
            }
        }
    }
    Ok(directory)
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    crypt(data, false)
}

pub fn unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(crypt(data, true)?))
}

fn crypt(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data
            .len()
            .try_into()
            .context("Protected data is too large")?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: DPAPI reads input and allocates output with LocalAlloc. We copy, zero, and free it once.
    unsafe {
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                wide("Juan local configuration").as_ptr(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(windows_error(if decrypt {
                "Decrypt per-user DPAPI data"
            } else {
                "Protect per-user DPAPI data"
            }));
        }
        let allocation = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let bytes = allocation.to_vec();
        allocation.zeroize();
        LocalFree(output.pbData.cast());
        Ok(bytes)
    }
}

fn read_protected(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::File::open(path).with_context(|| format!("Open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "Protected configuration exceeds the 1 MB limit"
    );
    unprotect(&bytes)
}

fn write_protected_new(path: &Path, plaintext: &[u8]) -> Result<()> {
    let bytes = protect(plaintext)?;
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("Missing configuration directory")?)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Create protected configuration {}", path.display()))?;
    Ok(())
}

pub fn load_or_create_ca() -> Result<Arc<CertificateAuthority>> {
    let path = data_directory()?.join("root-ca.dpapi");
    if path.try_exists()? {
        let bytes = read_protected(&path)?;
        let material: CaMaterial =
            serde_json::from_slice(&bytes).context("Read stored local CA")?;
        return Ok(Arc::new(CertificateAuthority::from_material(&material)?));
    }
    let ca = CertificateAuthority::generate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(&ca.material())?);
    write_protected_new(&path, &bytes)?;
    Ok(Arc::new(ca))
}

pub fn stored_ca_der() -> Result<Option<Vec<u8>>> {
    let path = data_directory()?.join("root-ca.dpapi");
    if !path.try_exists()? {
        return Ok(None);
    }
    let bytes = read_protected(&path)?;
    let material: CaMaterial = serde_json::from_slice(&bytes).context("Read stored local CA")?;
    Ok(Some(material.certificate_der.clone()))
}

pub fn reset_ca() -> Result<()> {
    if let Some(der) = stored_ca_der()? {
        ensure!(
            !certificate_is_trusted(&der)?,
            "Remove this CA from the current-user trust store before resetting it"
        );
        fs::remove_file(data_directory()?.join("root-ca.dpapi"))
            .context("Remove protected local CA")?;
    }
    Ok(())
}

struct RootStore(HCERTSTORE);

impl RootStore {
    fn open() -> Result<Self> {
        // SAFETY: Only the current user's existing ROOT store is opened, never the machine store.
        unsafe {
            let handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                wide("ROOT").as_ptr().cast(),
            );
            if handle.is_null() {
                return Err(windows_error("Open current-user certificate trust store"));
            }
            Ok(Self(handle))
        }
    }

    fn find(&self, der: &[u8]) -> Result<*mut CERT_CONTEXT> {
        // SAFETY: Enumeration frees the previous context. A matching returned context belongs to the caller.
        unsafe {
            let mut previous = null_mut();
            loop {
                let context = CertEnumCertificatesInStore(self.0, previous);
                if context.is_null() {
                    let error = GetLastError();
                    if error == CRYPT_E_NOT_FOUND as u32 || error == ERROR_NO_MORE_FILES {
                        return Ok(null_mut());
                    }
                    return Err(windows_error("Enumerate current-user certificates"));
                }
                let encoded = std::slice::from_raw_parts(
                    (*context).pbCertEncoded,
                    (*context).cbCertEncoded as usize,
                );
                if encoded == der {
                    return Ok(context);
                }
                previous = context;
            }
        }
    }
}

impl Drop for RootStore {
    fn drop(&mut self) {
        // SAFETY: All outstanding certificate contexts are freed before the store owner is dropped.
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}

pub fn certificate_is_trusted(der: &[u8]) -> Result<bool> {
    let store = RootStore::open()?;
    let context = store.find(der)?;
    if context.is_null() {
        return Ok(false);
    }
    // SAFETY: find returned an owned context; release it without changing trust.
    unsafe {
        CertFreeCertificateContext(context);
    }
    Ok(true)
}

pub fn trust_certificate(ca: &CertificateAuthority) -> Result<()> {
    let store = RootStore::open()?;
    // SAFETY: The caller explicitly requested trust. No private key is imported into this store.
    unsafe {
        if CertAddEncodedCertificateToStore(
            store.0,
            X509_ASN_ENCODING,
            ca.der().as_ptr(),
            ca.der().len().try_into()?,
            CERT_STORE_ADD_USE_EXISTING,
            null_mut(),
        ) == 0
        {
            return Err(windows_error("Trust Juan's CA for the current user"));
        }
    }
    ensure!(
        certificate_is_trusted(ca.der())?,
        "The certificate installation could not be verified in the current-user trust store"
    );
    Ok(())
}

pub fn untrust_certificate(der: &[u8]) -> Result<bool> {
    let store = RootStore::open()?;
    let context = store.find(der)?;
    if context.is_null() {
        return Ok(false);
    }
    // SAFETY: Delete only an exact DER match, not all certificates with a matching friendly name.
    unsafe {
        if CertDeleteCertificateFromStore(context) == 0 {
            return Err(windows_error(
                "Remove Juan's CA from the current-user trust store",
            ));
        }
    }
    Ok(true)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ProxySettings {
    flags: u32,
    server: String,
    bypass: String,
    pac_url: String,
}

impl ProxySettings {
    fn query() -> Result<Self> {
        let mut options = [
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_FLAGS_UI,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                ..Default::default()
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
                ..Default::default()
            },
        ];
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            dwOptionCount: options.len() as u32,
            pOptions: options.as_mut_ptr(),
            ..Default::default()
        };
        let mut size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
        // SAFETY: WinINet allocates NUL-terminated option strings using GlobalAlloc, even on partial failure.
        unsafe {
            let ok = InternetQueryOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
                &mut size,
            );
            let error = (ok == 0).then(|| windows_error("Read Windows proxy settings"));
            let mut values = Vec::new();
            for option in &options[1..] {
                let pointer = option.Value.pszValue;
                if pointer.is_null() {
                    values.push(String::new());
                } else {
                    let mut length = 0;
                    while *pointer.add(length) != 0 {
                        length += 1;
                    }
                    values.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                        pointer, length,
                    )));
                    GlobalFree(pointer.cast());
                }
            }
            if let Some(error) = error {
                return Err(error);
            }
            Ok(Self {
                flags: options[0].Value.dwValue,
                server: values[0].clone(),
                bypass: values[1].clone(),
                pac_url: values[2].clone(),
            })
        }
    }

    fn apply(&self) -> Result<()> {
        let mut server = wide(&self.server);
        let mut bypass = wide(&self.bypass);
        let mut pac = wide(&self.pac_url);
        let mut options = [
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_FLAGS,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    dwValue: self.flags,
                },
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: server.as_mut_ptr(),
                },
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: bypass.as_mut_ptr(),
                },
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: pac.as_mut_ptr(),
                },
            },
        ];
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            dwOptionCount: options.len() as u32,
            pOptions: options.as_mut_ptr(),
            ..Default::default()
        };
        // SAFETY: All buffers remain alive until this synchronous API call returns.
        unsafe {
            if InternetSetOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                (&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast(),
                size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            ) == 0
            {
                return Err(windows_error("Update Windows proxy settings"));
            }
        }
        notify_proxy_change()
    }
}

fn notify_proxy_change() -> Result<()> {
    // SAFETY: Notify WinINet consumers to discard cached per-user proxy configuration.
    unsafe {
        for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
            if InternetSetOptionW(null(), option, null(), 0) == 0 {
                return Err(windows_error(
                    "Notify applications of changed proxy settings",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Backup {
    version: u8,
    previous: ProxySettings,
    installed: ProxySettings,
}

#[derive(Debug, PartialEq, Eq)]
enum Restoration {
    Restore,
    AlreadyRestored,
    StillRouted,
    PreserveExternal,
}

fn restoration(current: &ProxySettings, backup: &Backup) -> Restoration {
    if current == &backup.installed {
        Restoration::Restore
    } else if current == &backup.previous {
        Restoration::AlreadyRestored
    } else if current.flags & PROXY_TYPE_PROXY != 0
        && current.server.split(';').any(|current| {
            backup
                .installed
                .server
                .split(';')
                .any(|installed| same_proxy_endpoint(current, installed))
        })
    {
        Restoration::StillRouted
    } else {
        Restoration::PreserveExternal
    }
}

fn same_proxy_endpoint(first: &str, second: &str) -> bool {
    let endpoint = |value: &str| {
        value
            .rsplit('=')
            .next()
            .unwrap_or(value)
            .trim()
            .parse::<http::uri::Authority>()
            .ok()
    };
    let (Some(first), Some(second)) = (endpoint(first), endpoint(second)) else {
        return false;
    };
    let local = |host: &str| {
        host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    };
    first.port_u16().is_some()
        && first.port_u16() == second.port_u16()
        && (first.host().eq_ignore_ascii_case(second.host())
            || (local(first.host()) && local(second.host())))
}

pub struct ProxyLease {
    path: PathBuf,
    active: bool,
}

impl ProxyLease {
    pub fn enable(address: SocketAddr) -> Result<Self> {
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Windows proxy requires a running loopback listener"
        );
        let path = data_directory()?.join("proxy-restore.dpapi");
        ensure!(
            !path.try_exists()?,
            "A previous proxy restoration is pending. Recover it before enabling Windows proxy."
        );
        let previous = ProxySettings::query()?;
        ensure!(
            previous.flags & (PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL) == 0,
            "An existing proxy or PAC script is configured. Juan does not chain upstream proxies and will not overwrite it. Configure an individual test application instead."
        );
        let installed = ProxySettings {
            flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
            server: format!("http={address};https={address}"),
            bypass: String::new(),
            pac_url: String::new(),
        };
        let backup = Backup {
            version: 1,
            previous,
            installed,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&backup)?);
        write_protected_new(&path, &bytes)?;
        if let Err(error) = backup.installed.apply() {
            if let Err(rollback) = backup.previous.apply() {
                bail!(
                    "Enable Windows proxy failed: {error:#}. Restoration also failed: {rollback:#}. Recovery data remains at {}",
                    path.display()
                );
            }
            fs::remove_file(&path).context("Remove rolled-back proxy backup")?;
            return Err(error);
        }
        Ok(Self { path, active: true })
    }

    pub fn restore(&mut self) -> Result<String> {
        if !self.active {
            return Ok("Windows proxy was already restored.".into());
        }
        let message = restore_path(&self.path)?;
        self.active = false;
        Ok(message)
    }
}

impl Drop for ProxyLease {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.restore()
        {
            eprintln!(
                "Juan could not restore Windows proxy settings: {error:#}. Recovery data remains at {}",
                self.path.display()
            );
        }
    }
}

fn restore_path(path: &Path) -> Result<String> {
    let bytes = read_protected(path)?;
    let backup: Backup = serde_json::from_slice(&bytes).context("Read proxy recovery data")?;
    ensure!(backup.version == 1, "Unsupported proxy recovery format");
    let current = ProxySettings::query()?;
    let message = match restoration(&current, &backup) {
        Restoration::Restore => {
            backup.previous.apply()?;
            "Restored the previous Windows proxy settings."
        }
        Restoration::AlreadyRestored => {
            notify_proxy_change()?;
            "Windows proxy settings were already restored."
        }
        Restoration::StillRouted => {
            bail!(
                "Windows proxy settings were edited outside Juan but still point to its listener. To avoid disconnecting your apps, restore the appropriate settings in Windows Settings > Network & internet > Proxy, then retry Stop or recovery. External edits were not overwritten."
            );
        }
        Restoration::PreserveExternal => {
            "Windows proxy settings changed outside Juan; those changes were preserved."
        }
    };
    fs::remove_file(path).context("Remove completed proxy recovery record")?;
    Ok(message.to_owned())
}

pub fn recover_proxy() -> Result<Option<String>> {
    let path = data_directory()?.join("proxy-restore.dpapi");
    if !path.try_exists()? {
        return Ok(None);
    }
    restore_path(&path).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_and_tamper_detection() {
        let plaintext = b"ephemeral test material, not a real key";
        let encrypted = protect(plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);
        assert_eq!(unprotect(&encrypted).unwrap().as_slice(), plaintext);
        let mut damaged = encrypted;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(unprotect(&damaged).is_err());
    }

    #[test]
    fn restoration_never_clobbers_external_changes() {
        let previous = ProxySettings {
            flags: 9,
            server: String::new(),
            bypass: "<local>".into(),
            pac_url: String::new(),
        };
        let installed = ProxySettings {
            flags: 3,
            server: "http=127.0.0.1:8866;https=127.0.0.1:8866".into(),
            bypass: String::new(),
            pac_url: String::new(),
        };
        let backup = Backup {
            version: 1,
            previous: previous.clone(),
            installed: installed.clone(),
        };
        assert_eq!(restoration(&installed, &backup), Restoration::Restore);
        assert_eq!(
            restoration(&previous, &backup),
            Restoration::AlreadyRestored
        );
        let external = ProxySettings {
            server: "corporate:8080".into(),
            ..installed
        };
        assert_eq!(
            restoration(&external, &backup),
            Restoration::PreserveExternal
        );
    }

    #[test]
    fn protected_files_are_atomic_and_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.dpapi");
        write_protected_new(&path, b"first").unwrap();
        assert!(write_protected_new(&path, b"second").is_err());
        assert_eq!(read_protected(&path).unwrap().as_slice(), b"first");
    }

    #[test]
    fn external_bypass_edits_cannot_leave_a_stopped_listener_as_the_system_proxy() {
        let previous = ProxySettings {
            flags: PROXY_TYPE_DIRECT,
            server: String::new(),
            bypass: String::new(),
            pac_url: String::new(),
        };
        let installed = ProxySettings {
            flags: PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT,
            server: "http=127.0.0.1:8866;https=127.0.0.1:8866".into(),
            ..previous.clone()
        };
        let backup = Backup {
            version: 1,
            previous,
            installed: installed.clone(),
        };
        let mut edited = ProxySettings {
            bypass: "<local>".into(),
            ..installed
        };
        assert_eq!(restoration(&edited, &backup), Restoration::StillRouted);
        edited.server = "localhost:8866".into();
        assert_eq!(restoration(&edited, &backup), Restoration::StillRouted);
        edited.server = "localhost:9999".into();
        assert_eq!(restoration(&edited, &backup), Restoration::PreserveExternal);
        edited.server = "localhost:8866".into();
        edited.flags = PROXY_TYPE_DIRECT;
        assert_eq!(restoration(&edited, &backup), Restoration::PreserveExternal);
    }

    #[test]
    fn legacy_state_migrates_without_reissuing_keys_or_touching_captures() {
        let parent = tempfile::tempdir().unwrap();
        let legacy = parent.path().join("Widdler");
        fs::create_dir(&legacy).unwrap();
        write_protected_new(&legacy.join("root-ca.dpapi"), b"legacy key material").unwrap();
        write_protected_new(
            &legacy.join("proxy-restore.dpapi"),
            b"legacy recovery state",
        )
        .unwrap();
        fs::write(legacy.join("capture.har"), b"existing evidence").unwrap();
        let protected = fs::read(legacy.join("root-ca.dpapi")).unwrap();
        let current = migrate_legacy_data(parent.path()).unwrap();
        assert_eq!(current, parent.path().join("Juan"));
        assert_eq!(fs::read(current.join("root-ca.dpapi")).unwrap(), protected);
        assert_eq!(
            read_protected(&current.join("root-ca.dpapi"))
                .unwrap()
                .as_slice(),
            b"legacy key material"
        );
        assert_eq!(
            read_protected(&current.join("proxy-restore.dpapi"))
                .unwrap()
                .as_slice(),
            b"legacy recovery state"
        );
        assert!(!legacy.join("root-ca.dpapi").exists());
        assert_eq!(
            fs::read(legacy.join("capture.har")).unwrap(),
            b"existing evidence"
        );
        assert_eq!(migrate_legacy_data(parent.path()).unwrap(), current);
    }

    #[test]
    fn conflicting_brand_state_is_never_overwritten_or_partly_migrated() {
        let parent = tempfile::tempdir().unwrap();
        let legacy = parent.path().join("Widdler");
        let current = parent.path().join("Juan");
        fs::create_dir(&legacy).unwrap();
        fs::create_dir(&current).unwrap();
        fs::write(legacy.join("root-ca.dpapi"), b"old key").unwrap();
        fs::write(current.join("root-ca.dpapi"), b"new key").unwrap();
        fs::write(legacy.join("proxy-restore.dpapi"), b"old recovery").unwrap();
        assert!(migrate_legacy_data(parent.path()).is_err());
        assert_eq!(fs::read(legacy.join("root-ca.dpapi")).unwrap(), b"old key");
        assert_eq!(fs::read(current.join("root-ca.dpapi")).unwrap(), b"new key");
        assert!(legacy.join("proxy-restore.dpapi").exists());
        assert!(!current.join("proxy-restore.dpapi").exists());
    }

    #[test]
    fn instance_guard_coordinates_legacy_names_and_releases_partial_acquisition() {
        let unique = tempfile::tempdir().unwrap();
        let suffix = unique.path().file_name().unwrap().to_string_lossy();
        let legacy = format!("Local\\Juan.TestLegacy.{suffix}");
        let current = format!("Local\\Juan.TestCurrent.{suffix}");
        let held = SingleInstance::acquire_named(&[&legacy]).unwrap();
        assert!(SingleInstance::acquire_named(&[&current, &legacy]).is_err());
        drop(held);
        let both = SingleInstance::acquire_named(&[&current, &legacy]).unwrap();
        assert!(SingleInstance::acquire_named(&[&legacy]).is_err());
        drop(both);
        SingleInstance::acquire_named(&[&current, &legacy]).unwrap();
    }
}
