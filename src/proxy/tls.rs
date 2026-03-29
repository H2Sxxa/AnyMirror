use anyhow::{Context, Result};
use axum::{Router, extract::Request};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use rcgen::generate_simple_self_signed;
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tower::Service;

#[derive(Clone)]
pub struct TlsIntercepted;

pub async fn serve_app_tls(
    app: Router,
    listen_addr: std::net::SocketAddr,
    domains: Vec<String>,
) -> Result<()> {
    let tls_config = get_or_generate_cert_config(&domains).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // We inject TlsIntercepted into the request extensions directly in the router clone here
    let app = app.layer(axum::middleware::map_request(
        |mut req: Request| async move {
            req.extensions_mut().insert(TlsIntercepted);
            req
        },
    ));

    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("TLS interception server listening on {}", listen_addr);

    // Hyper 1.x / axum 0.8 style pure TCP loop
    loop {
        let (tcp, _remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("Failed to accept TLS connection: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    // This error is perfectly normal (e.g. client cancels, scanner probes)
                    // You can keep it as debug or trace to not clutter logs
                    tracing::debug!("TLS handshake failed: {}", e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let hyper_service =
                hyper::service::service_fn(move |req: Request<Incoming>| app.clone().call(req));

            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                // Disconnecting abruptly happens
                tracing::debug!("Error serving TLS connection: {:?}", err);
            }
        });
    }
}

async fn get_or_generate_cert_config(domains: &[String]) -> Result<ServerConfig> {
    let cert_path = Path::new("anymirror.crt");
    let key_path = Path::new("anymirror.key");

    if !cert_path.exists() || !key_path.exists() {
        tracing::info!("Generating new self-signed certificate for TLS interception...");

        let cert = generate_simple_self_signed(domains.to_vec())?;
        let pem_cert = cert.cert.pem();
        let pem_key = cert.signing_key.serialize_pem();

        fs::write(cert_path, pem_cert)?;
        fs::write(key_path, pem_key)?;

        tracing::info!(
            "Saved self-signed certificate to anymirror.crt and anymirror.key. You must trust anymirror.crt in your system/JVM for TLS interception to work."
        );
    }

    // Load certs using standard rustls-pemfile
    let cert_file = fs::File::open(cert_path).context("cannot open cert file")?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse pem cert")?;

    let key_file = fs::File::open(key_path).context("cannot open key file")?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to read private key")?
        .context("no private key found")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .context("failed to build rustls ServerConfig")?;

    Ok(config)
}
