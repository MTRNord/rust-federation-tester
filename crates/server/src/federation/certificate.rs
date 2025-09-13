use crate::response::Certificate;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Extract certificate information from a CertificateDer for federation reporting
pub fn extract_certificate_info(
    cert_der: &rustls_pki_types::CertificateDer<'_>,
) -> Option<Certificate> {
    let cert_bytes = cert_der.as_ref();
    let (_, x509_cert) = X509Certificate::from_der(cert_bytes).ok()?;

    let subject_cn = x509_cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let issuer_cn = x509_cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let mut hasher = Sha256::new();
    hasher.update(cert_bytes);
    let fingerprint = format!("{:X}", hasher.finalize());

    let mut dns_names = Vec::new();
    if let Ok(extensions_map) = x509_cert.extensions_map()
        && let Some(san_ext) =
            extensions_map.get(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        && let ParsedExtension::SubjectAlternativeName(san_general_names) =
            san_ext.parsed_extension()
    {
        for name in &san_general_names.general_names {
            if let GeneralName::DNSName(dns_name) = name {
                dns_names.push(dns_name.to_string());
            }
        }
    }

    Some(Certificate {
        subject_common_name: subject_cn,
        issuer_common_name: issuer_cn,
        sha256fingerprint: fingerprint,
        dnsnames: if dns_names.is_empty() {
            None
        } else {
            Some(dns_names)
        },
    })
}
