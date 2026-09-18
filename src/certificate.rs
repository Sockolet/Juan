use std::{collections::VecDeque, sync::Arc};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{ServerConfig, crypto::ring, pki_types::PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct CaMaterial {
    pub certificate_der: Vec<u8>,
    pub key_pem: String,
}

impl Drop for CaMaterial {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    der: Vec<u8>,
    expires: OffsetDateTime,
    cache: Mutex<VecDeque<CachedLeaf>>,
}

struct CachedLeaf {
    host: String,
    expires: OffsetDateTime,
    config: Arc<ServerConfig>,
}

impl CertificateAuthority {
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Juan Local Debugging CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Juan");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        let expires = params.not_after;
        let key = KeyPair::generate().context("Generate a unique local CA key")?;
        let certificate = params.self_signed(&key)?;
        Ok(Self {
            issuer: Issuer::new(params, key),
            der: certificate.der().to_vec(),
            expires,
            cache: Mutex::new(VecDeque::new()),
        })
    }

    pub fn from_material(material: &CaMaterial) -> Result<Self> {
        let key = KeyPair::from_pem(&material.key_pem).context("Read protected CA key")?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&material.certificate_der)
            .map_err(|error| anyhow::anyhow!("Read local CA certificate: {error}"))?;
        ensure!(
            certificate.validity().is_valid(),
            "The local CA is expired or not yet valid. Remove its trust and reset the CA before decrypting HTTPS."
        );
        ensure!(certificate.is_ca(), "The stored certificate is not a CA");
        ensure!(
            certificate.public_key().raw == key.subject_public_key_info(),
            "The stored CA certificate does not match its private key"
        );
        let expires =
            OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp())?;
        let der = material.certificate_der.clone();
        let issuer = Issuer::from_ca_cert_der(&der.clone().into(), key)?;
        Ok(Self {
            issuer,
            der,
            expires,
            cache: Mutex::new(VecDeque::new()),
        })
    }

    pub fn material(&self) -> CaMaterial {
        CaMaterial {
            certificate_der: self.der.clone(),
            key_pem: self.issuer.key().serialize_pem(),
        }
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> String {
        let encoded = STANDARD.encode(&self.der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn expires(&self) -> OffsetDateTime {
        self.expires
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        ensure!(
            self.expires > OffsetDateTime::now_utc(),
            "The local CA has expired; HTTPS interception is unavailable"
        );
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        rustls::pki_types::ServerName::try_from(host.clone())
            .context("Invalid CONNECT server name")?;
        let mut cache = self.cache.lock();
        let now = OffsetDateTime::now_utc();
        if let Some(leaf) = cache
            .iter()
            .find(|leaf| leaf.host == host && leaf.expires > now + Duration::minutes(1))
        {
            return Ok(leaf.config.clone());
        }
        cache.retain(|leaf| leaf.host != host && leaf.expires > now);
        let mut params = CertificateParams::new(vec![host.clone()])?;
        params.distinguished_name.push(DnType::CommonName, &host);
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = (OffsetDateTime::now_utc() + Duration::days(7)).min(self.expires);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate()?;
        let certificate = params.signed_by(&key, &self.issuer)?;
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.len() >= 128 {
            cache.pop_front();
        }
        cache.push_back(CachedLeaf {
            host,
            expires: params.not_after,
            config: config.clone(),
        });
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ca_is_unique_and_can_be_reloaded() {
        let first = CertificateAuthority::generate().unwrap();
        let second = CertificateAuthority::generate().unwrap();
        assert_ne!(first.fingerprint(), second.fingerprint());
        let loaded = CertificateAuthority::from_material(&first.material()).unwrap();
        assert_eq!(first.der(), loaded.der());
        assert_eq!(first.fingerprint(), loaded.fingerprint());
    }

    #[test]
    fn mismatched_keys_are_rejected() {
        let first = CertificateAuthority::generate().unwrap();
        let second = CertificateAuthority::generate().unwrap();
        let mut material = first.material();
        material.key_pem = second.material().key_pem.clone();
        assert!(CertificateAuthority::from_material(&material).is_err());
    }

    #[test]
    fn caches_host_certificates_and_supports_ip_sans() {
        let ca = CertificateAuthority::generate().unwrap();
        let first = ca.server_config("example.test").unwrap();
        let same = ca.server_config("EXAMPLE.TEST").unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        ca.server_config("127.0.0.1").unwrap();
        ca.server_config("[::1]").unwrap();
        assert!(ca.server_config("not a host").is_err());
    }

    #[test]
    fn expired_cached_leaf_is_renewed_without_changing_the_root() {
        let ca = CertificateAuthority::generate().unwrap();
        let first = ca.server_config("example.test").unwrap();
        ca.cache.lock()[0].expires = OffsetDateTime::now_utc() - Duration::minutes(1);
        let next = ca.server_config("example.test").unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
        assert_eq!(ca.cache.lock().len(), 1);
    }
}
