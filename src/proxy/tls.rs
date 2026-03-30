use anyhow::{anyhow, Context, Result};
use axum::{extract::Request, middleware::map_request, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::sign::any_supported_type;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::{collections::HashMap, io::Cursor};
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use tokio_rustls::TlsAcceptor;
use tower::Service;

#[derive(Clone, Debug)]
pub struct TlsIntercepted;

/// Dynamic certificate resolver that generates certificates on-the-fly for SNI hostnames
#[derive(Clone, Debug)]
struct DynamicCertResolver {
    ca_cert_pem: String,
    ca_key_pem: String,
    /// Cache of generated certificates
    cache: Arc<Mutex<HashMap<String, Arc<CertifiedKey>>>>,
}

impl DynamicCertResolver {
    fn new(ca_cert_pem: String, ca_key_pem: String) -> Self {
        Self {
            ca_cert_pem,
            ca_key_pem,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_generate_cert(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        // Check cache first
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("certificate cache lock poisoned"))?;
            if let Some(cert) = cache.get(hostname) {
                return Ok(cert.clone());
            }
        }

        let ca_key =
            KeyPair::from_pem(&self.ca_key_pem).context("failed to parse CA private key PEM")?;
        let ca_issuer = Issuer::new(build_ca_params()?, ca_key);

        let mut leaf_params = CertificateParams::new(vec![hostname.to_string()])
            .context("failed to build leaf cert params")?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        let leaf_key = KeyPair::generate().context("failed to generate leaf key")?;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .context("failed to issue leaf cert with CA")?;
        let leaf_cert_pem = leaf_cert.pem();
        let key_pem = leaf_key.serialize_pem();

        let full_chain_pem = format!("{}\n{}", leaf_cert_pem, self.ca_cert_pem);
        let mut cert_reader = Cursor::new(full_chain_pem.as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse generated cert")?;

        let mut key_reader = Cursor::new(key_pem.as_bytes());
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .context("failed to read private key")?
            .context("no private key found")?;

        // Use any_supported_type to handle all key types generically
        let signing_key =
            any_supported_type(&private_key).context("unsupported or invalid private key")?;

        let certified_key = Arc::new(CertifiedKey::new(certs, signing_key));

        // Cache it
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("certificate cache lock poisoned"))?;
            cache.insert(hostname.to_string(), certified_key.clone());
        }

        Ok(certified_key)
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Extract SNI hostname from client hello
        let hostname = client_hello.server_name().map(|sni| sni.to_string())?;

        match self.get_or_generate_cert(&hostname) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::warn!("Failed to generate certificate for {}: {}", hostname, e);
                None
            }
        }
    }
}

pub async fn serve_app_tls(app: Router, listen_addr: SocketAddr) -> Result<()> {
    // Generate or load CA certificate
    let (ca_cert_pem, ca_key_pem) = get_or_generate_ca_cert()?;

    // Create dynamic certificate resolver
    let cert_resolver = DynamicCertResolver::new(ca_cert_pem, ca_key_pem);

    // Create server config with dynamic resolver
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver));

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // We inject TlsIntercepted into the request extensions directly in the router clone here
    let app = app.layer(map_request(|mut req: Request| async move {
        req.extensions_mut().insert(TlsIntercepted);
        req
    }));

    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(
        "TLS interception server listening on {} (dynamic certificate mode)",
        listen_addr
    );

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
            let hyper_service = service_fn(move |req: Request<Incoming>| app.clone().call(req));

            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                // Disconnecting abruptly happens
                tracing::debug!("Error serving TLS connection: {:?}", err);
            }
        });
    }
}

fn get_or_generate_ca_cert() -> Result<(String, String)> {
    let cert_path = Path::new("anymirror_ca.crt");
    let key_path = Path::new("anymirror_ca.key");

    if cert_path.exists() && key_path.exists() {
        // Load existing CA
        let cert_pem = fs::read_to_string(cert_path).context("failed to read CA cert")?;
        let key_pem = fs::read_to_string(key_path).context("failed to read CA key")?;

        tracing::info!("Loaded existing CA certificate from anymirror_ca.crt");
        return Ok((cert_pem, key_pem));
    }

    // Generate new CA certificate
    tracing::info!("Generating new CA certificate for dynamic TLS interception...");

    let ca_params = build_ca_params()?;
    let ca_key = KeyPair::generate().context("failed to generate CA key")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to self-sign CA cert")?;

    let cert_pem = ca_cert.pem();
    let key_pem = ca_key.serialize_pem();

    fs::write(cert_path, &cert_pem).context("failed to write CA cert file")?;
    fs::write(key_path, &key_pem).context("failed to write CA key file")?;

    tracing::info!(
        "Saved CA certificate to anymirror_ca.crt and anymirror_ca.key. Trust anymirror_ca.crt to avoid certificate warnings."
    );

    Ok((cert_pem, key_pem))
}

fn build_ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec!["anymirror-ca".to_string()])
        .context("failed to build CA params")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "AnyMirror CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}
