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
    external: bool,
) -> std::io::Result<RustlsConfig> {
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");
    let names_path = tls_dir.join("self-signed-names");

    if !cert_path.exists() || !key_path.exists() {
        generate(tls_dir, &cert_path, &key_path, &names_path, alt_names)?;
    } else if !external {
        let expected = normalized_names(alt_names).join("\n") + "\n";
        match fs::read_to_string(&names_path) {
            Ok(current) if current == expected => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "certificado autoassinado incompatível com VEGA_WEB_TLS_NAMES; remova cert.pem/key.pem para regenerar com segurança",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "certificado existente sem metadados; defina VEGA_WEB_TLS_EXTERNAL=true para certificado administrado externamente ou regenere-o",
                ));
            }
            Err(error) => return Err(error),
        }
    }

    RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(std::io::Error::other)
}

fn generate(
    tls_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    names_path: &Path,
    alt_names: &[String],
) -> std::io::Result<()> {
    fs::create_dir_all(tls_dir)?;

    let names = normalized_names(alt_names);
    let names_metadata = names.join("\n") + "\n";

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).map_err(std::io::Error::other)?;

    write_private(cert_path, cert.pem().as_bytes())?;
    write_private(key_path, signing_key.serialize_pem().as_bytes())?;
    fs::write(names_path, names_metadata)?;
    Ok(())
}

fn normalized_names(alt_names: &[String]) -> Vec<String> {
    let mut names: Vec<String> = alt_names
        .iter()
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        names.push("localhost".into());
    }
    names.sort();
    names.dedup();
    names
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn names_are_deterministic() {
        assert_eq!(
            normalized_names(&["HOST.local".into(), "host.local".into(), "10.0.0.2".into()]),
            vec!["10.0.0.2", "host.local"]
        );
    }

    #[tokio::test]
    async fn generated_certificate_has_private_permissions_and_detects_name_change() {
        let dir = std::env::temp_dir().join(format!("vega-tls-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ensure_self_signed(&dir, &["server.local".into(), "10.0.0.2".into()], false)
            .await
            .unwrap();
        for name in ["cert.pem", "key.pem"] {
            let mode = fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let error = ensure_self_signed(&dir, &["other.local".into()], false)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        fs::remove_dir_all(dir).unwrap();
    }
}
