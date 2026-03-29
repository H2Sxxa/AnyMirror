use std::{
    fs,
    path::Path,
};

use anyhow::Result;
use axum::{Router, extract::Request};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;

#[derive(Clone)]
pub struct TlsIntercepted;

pub async fn serve_app_tls(app: Router, listen_addr: std::net::SocketAddr, domains: Vec<String>) -> Result<()> {
    let config = get_or_generate_cert_config(&domains).await?;

    tracing::info!("TLS interception server listening on {}", listen_addr);

    // We inject TlsIntercepted into the request extensions
    let app_with_flag = app.layer(axum::middleware::map_request(|mut req: Request| async move {
        req.extensions_mut().insert(TlsIntercepted);
        req
    }));

    axum_server::bind_rustls(listen_addr, config)
        .serve(app_with_flag.into_make_service())
        .await?;

    Ok(())
}

async fn get_or_generate_cert_config(domains: &[String]) -> Result<RustlsConfig> {
    let cert_path = Path::new("anymirror.crt");
    let key_path = Path::new("anymirror.key");

    if cert_path.exists() && key_path.exists() {
        return Ok(RustlsConfig::from_pem_file(cert_path, key_path).await?);
    }

    tracing::info!("Generating new self-signed certificate for TLS interception...");

    let cert = generate_simple_self_signed(domains.to_vec())?;
    let pem_cert = cert.cert.pem();
    let pem_key = cert.signing_key.serialize_pem();

    fs::write(cert_path, pem_cert)?;
    fs::write(key_path, pem_key)?;

    tracing::info!("Saved self-signed certificate to anymirror.crt and anymirror.key. You must trust anymirror.crt in your system/JVM for TLS interception to work.");

    Ok(RustlsConfig::from_pem_file(cert_path, key_path).await?)
}

