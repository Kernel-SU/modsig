//! Helpers for printing certificate details

use x509_cert::{der::Decode, Certificate};

/// Describe certificate with basic fields; fall back to byte size on parse error.
pub fn describe_certificate(cert_der: &[u8]) -> String {
    match Certificate::from_der(cert_der) {
        Ok(cert) => {
            let subject = format!("{:?}", cert.tbs_certificate.subject);
            let issuer = format!("{:?}", cert.tbs_certificate.issuer);
            let validity = &cert.tbs_certificate.validity;
            let not_before = format!("{:?}", validity.not_before);
            let not_after = format!("{:?}", validity.not_after);
            format!(
                "subject={} | issuer={} | not_before={} | not_after={}",
                subject, issuer, not_before, not_after
            )
        }
        Err(_) => format!("certificate: {} bytes (failed to parse DER)", cert_der.len()),
    }
}

/// Describe a certificate chain for printing.
pub fn describe_chain(chain: &[Vec<u8>]) -> Vec<String> {
    chain
        .iter()
        .enumerate()
        .map(|(idx, cert)| format!("Chain[{}]: {} bytes; {}", idx, cert.len(), describe_certificate(cert)))
        .collect()
}
