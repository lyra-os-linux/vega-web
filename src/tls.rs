use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use axum_server::tls_rustls::RustlsConfig;

/// Garante que existe um par certificado/chave autoassinado em `tls_dir`,
/// gerando um na primeira execução. O aviso de certificado não confiável no
/// navegador é esperado (uso somente-LAN, sem CA pública) — ver
/// docs/vega-web-privacidade.md.
pub async fn ensure_self_signed(
    tls_dir: &Path,
    alt_names: &[String],
) -> std::io::Result<RustlsConfig> {
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate(tls_dir, &cert_path, &key_path, alt_names)?;
    }

    RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(std::io::Error::other)
}

fn generate(
    tls_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    alt_names: &[String],
) -> std::io::Result<()> {
    fs::create_dir_all(tls_dir)?;

    let names = if alt_names.is_empty() {
        vec!["localhost".to_string()]
    } else {
        alt_names.to_vec()
    };

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).map_err(std::io::Error::other)?;

    write_private(cert_path, cert.pem().as_bytes())?;
    write_private(key_path, signing_key.serialize_pem().as_bytes())?;
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
