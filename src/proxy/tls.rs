use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Mutex;
use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow};
use axum::{Router, extract::Request, middleware::map_request};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig, SignatureScheme,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tower::Service;

const SERVER_ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

#[derive(Clone, Debug)]
pub struct TlsIntercepted;

#[derive(Clone, Debug)]
pub struct TlsInterceptService {
    state: Arc<TlsInterceptState>,
}

#[derive(Debug)]
struct TlsInterceptState {
    ca_cert_pem: String,
    ca_key_pem: String,
    cache: Mutex<HashMap<String, HostCertifiedKeys>>,
}

#[derive(Debug, Clone)]
struct HostCertifiedKeys {
    ecdsa: Arc<CertifiedKey>,
    rsa: Arc<CertifiedKey>,
}

#[derive(Clone, Debug)]
struct DynamicCertResolver {
    service: TlsInterceptService,
}

#[derive(Debug)]
struct FixedCertResolver {
    service: TlsInterceptService,
    hostname: String,
}

impl TlsInterceptService {
    pub fn new() -> Result<Self> {
        let (ca_cert_pem, ca_key_pem) = get_or_generate_ca_cert()?;
        Ok(Self {
            state: Arc::new(TlsInterceptState {
                ca_cert_pem,
                ca_key_pem,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn listener_server_config(&self) -> ServerConfig {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DynamicCertResolver {
                service: self.clone(),
            }));
        config.alpn_protocols = SERVER_ALPN_PROTOCOLS
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        config
    }

    pub fn host_server_config(&self, hostname: &str) -> Result<ServerConfig> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCertResolver {
                service: self.clone(),
                hostname: hostname.to_string(),
            }));
        config.alpn_protocols = SERVER_ALPN_PROTOCOLS
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        Ok(config)
    }

    fn certified_key_for_host(
        &self,
        hostname: &str,
        signature_schemes: &[SignatureScheme],
    ) -> Result<Arc<CertifiedKey>> {
        let certified_keys = self.host_certified_keys(hostname)?;
        let selected_key_algorithm =
            select_certified_key_algorithm(&certified_keys, signature_schemes);
        tracing::debug!(
            hostname,
            ?signature_schemes,
            selected_key_algorithm,
            "Selected TLS interception certificate"
        );
        Ok(select_certified_key(&certified_keys, signature_schemes))
    }

    fn host_certified_keys(&self, hostname: &str) -> Result<HostCertifiedKeys> {
        {
            let cache = self
                .state
                .cache
                .lock()
                .map_err(|_| anyhow!("certificate cache lock poisoned"))?;
            if let Some(certified_keys) = cache.get(hostname) {
                return Ok(certified_keys.clone());
            }
        }

        let ca_key = KeyPair::from_pem(&self.state.ca_key_pem)
            .context("failed to parse CA private key PEM")?;
        let ca_issuer = Issuer::new(build_ca_params()?, ca_key);
        let certified_keys = HostCertifiedKeys {
            ecdsa: Arc::new(build_leaf_certified_key(
                hostname,
                &self.state.ca_cert_pem,
                &ca_issuer,
                LeafKeyAlgorithm::Ecdsa,
            )?),
            rsa: Arc::new(build_leaf_certified_key(
                hostname,
                &self.state.ca_cert_pem,
                &ca_issuer,
                LeafKeyAlgorithm::Rsa,
            )?),
        };

        {
            let mut cache = self
                .state
                .cache
                .lock()
                .map_err(|_| anyhow!("certificate cache lock poisoned"))?;
            cache.insert(hostname.to_string(), certified_keys.clone());
        }

        Ok(certified_keys)
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let hostname = client_hello
            .server_name()
            .map(|server_name| server_name.to_string())?;

        match self
            .service
            .certified_key_for_host(&hostname, client_hello.signature_schemes())
        {
            Ok(certified_key) => Some(certified_key),
            Err(error) => {
                tracing::warn!("Failed to generate certificate for {}: {}", hostname, error);
                None
            }
        }
    }
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        match self
            .service
            .certified_key_for_host(&self.hostname, client_hello.signature_schemes())
        {
            Ok(certified_key) => Some(certified_key),
            Err(error) => {
                tracing::warn!(
                    "Failed to resolve certificate for {}: {}",
                    self.hostname,
                    error
                );
                None
            }
        }
    }
}

pub async fn serve_app_tls_with_listener(
    service: TlsInterceptService,
    app: Router,
    listener: TcpListener,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let app = attach_tls_marker(app);
    let listen_addr = listener
        .local_addr()
        .context("failed to read TLS listen address")?;
    tracing::info!(
        "TLS interception server listening on {} (dynamic certificate mode)",
        listen_addr
    );

    let acceptor = TlsAcceptor::from(Arc::new(service.listener_server_config()));
    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let accept_result = tokio::select! {
            _ = &mut shutdown => {
                tracing::info!(
                    active_connections = graceful.count(),
                    "TLS interception server stopping; draining active connections"
                );
                break;
            }
            maybe_finished = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                match maybe_finished {
                    Some(Ok(())) => continue,
                    Some(Err(error)) => {
                        tracing::warn!(?error, "TLS connection task finished with error during runtime");
                        continue;
                    }
                    None => continue,
                }
            }
            result = listener.accept() => result
        };

        let (tcp, _remote_addr) = match accept_result {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!(?error, "Failed to accept TLS connection");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();
        let server = server.clone();
        let watcher = graceful.watcher();

        connection_tasks.spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("TLS handshake failed: {}", error);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let hyper_service =
                service_fn(move |request: Request<Incoming>| app.clone().call(request));
            let connection = server.serve_connection(io, hyper_service).into_owned();
            let connection = watcher.watch(connection);

            if let Err(error) = connection.await {
                tracing::debug!("Error serving TLS connection: {:?}", error);
            }
        });
    }

    graceful.shutdown().await;
    tracing::info!("TLS interception server finished draining active connections");

    while let Some(result) = connection_tasks.join_next().await {
        if let Err(error) = result {
            tracing::warn!(?error, "TLS connection task failed during shutdown drain");
        }
    }

    Ok(())
}

pub async fn serve_app_tls_stream<S, F, Fut>(
    service: TlsInterceptService,
    stream: S,
    hostname: &str,
    handler: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<axum::response::Response, Infallible>> + Send + 'static,
{
    let config = Arc::new(service.host_server_config(hostname)?);
    let acceptor = TlsAcceptor::from(config);
    tracing::info!(hostname, "Starting explicit HTTPS interception handshake");
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => {
            tracing::info!(hostname, "Completed explicit HTTPS interception handshake");
            stream
        }
        Err(error) => {
            tracing::warn!(
                hostname,
                error = %error,
                "Explicit HTTPS interception handshake failed"
            );
            return Err(error).with_context(|| {
                format!("failed to complete TLS interception handshake for `{hostname}`")
            });
        }
    };
    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let io = TokioIo::new(tls_stream);
    let hyper_service = service_fn(handler);

    server
        .serve_connection(io, hyper_service)
        .await
        .map_err(|error| anyhow!("failed to serve intercepted TLS stream: {error}"))?;

    Ok(())
}

fn attach_tls_marker(app: Router) -> Router {
    app.layer(map_request(|mut request: Request| async move {
        request.extensions_mut().insert(TlsIntercepted);
        request
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafKeyAlgorithm {
    Ecdsa,
    Rsa,
}

fn build_leaf_certified_key(
    hostname: &str,
    ca_cert_pem: &str,
    ca_issuer: &Issuer<'_, KeyPair>,
    algorithm: LeafKeyAlgorithm,
) -> Result<CertifiedKey> {
    let mut leaf_params = CertificateParams::new(vec![hostname.to_string()])
        .context("failed to build leaf cert params")?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = match algorithm {
        LeafKeyAlgorithm::Ecdsa => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("failed to generate ECDSA leaf key")?,
        LeafKeyAlgorithm::Rsa => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
            .context("failed to generate RSA leaf key")?,
    };
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, ca_issuer)
        .context("failed to issue leaf cert with CA")?;
    let leaf_cert_pem = leaf_cert.pem();
    let key_pem = leaf_key.serialize_pem();

    let full_chain_pem = format!("{leaf_cert_pem}\n{ca_cert_pem}");
    let certs = CertificateDer::pem_slice_iter(full_chain_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse generated cert")?;
    let private_key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("failed to read private key")?;
    let signing_key =
        any_supported_type(&private_key).context("unsupported or invalid private key")?;

    Ok(CertifiedKey::new(certs, signing_key))
}

fn select_certified_key(
    certified_keys: &HostCertifiedKeys,
    signature_schemes: &[SignatureScheme],
) -> Arc<CertifiedKey> {
    match select_certified_key_algorithm(certified_keys, signature_schemes) {
        "rsa" => certified_keys.rsa.clone(),
        "ecdsa" => certified_keys.ecdsa.clone(),
        _ => certified_keys.rsa.clone(),
    }
}

fn select_certified_key_algorithm(
    certified_keys: &HostCertifiedKeys,
    signature_schemes: &[SignatureScheme],
) -> &'static str {
    if certified_keys
        .rsa
        .key
        .choose_scheme(signature_schemes)
        .is_some()
    {
        return "rsa";
    }

    if certified_keys
        .ecdsa
        .key
        .choose_scheme(signature_schemes)
        .is_some()
    {
        return "ecdsa";
    }

    "rsa-fallback"
}

fn get_or_generate_ca_cert() -> Result<(String, String)> {
    let cert_path = Path::new("anymirror_ca.crt");
    let key_path = Path::new("anymirror_ca.key");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read_to_string(cert_path).context("failed to read CA cert")?;
        let key_pem = fs::read_to_string(key_path).context("failed to read CA key")?;

        tracing::info!("Loaded existing CA certificate from anymirror_ca.crt");
        return Ok((cert_pem, key_pem));
    }

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
