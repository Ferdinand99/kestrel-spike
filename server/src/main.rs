//! Keen Kestrel spike server. See ../README.md.

mod difs;
mod envelope;
mod symbolicate;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::difs::{AssembleItem, DifStore};
use crate::symbolicate::{SymcacheProvider, has_native_frames, symbolicate_event};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct AppState {
    capture_dir: PathBuf,
    store: DifStore,
    counter: AtomicU64,
}

type St = State<Arc<AppState>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => {
            println!("kestrel-spike {VERSION}");
            Ok(())
        }
        Some("symbolicate") => cli_symbolicate(&args[1..]),
        None | Some("serve") => serve(),
        Some(other) => {
            eprintln!(
                "usage: kestrel-spike [serve | --version | symbolicate <event.json|envelope> [--dif PATH]... [--data-dir DIR] [--out FILE]]"
            );
            bail!("unknown command {other}")
        }
    }
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

#[tokio::main]
async fn serve() -> Result<()> {
    let capture_dir = env_path("CAPTURE_DIR", "captures");
    std::fs::create_dir_all(&capture_dir)?;
    let store = DifStore::new(env_path("DATA_DIR", "data"))?;
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".into());
    eprintln!(
        "kestrel-spike {VERSION} on {bind}, CAPTURE_DIR={}, DATA_DIR={}",
        capture_dir.display(),
        store.root().display()
    );
    let state = Arc::new(AppState {
        capture_dir,
        store,
        counter: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/{project_id}/envelope/", post(envelope))
        .route("/api/{project_id}/envelope", post(envelope))
        .route("/api/0/", get(auth_info))
        .route(
            "/api/0/organizations/{org}/chunk-upload/",
            get(chunk_options).post(chunk_upload),
        )
        .route(
            "/api/0/projects/{org}/{project}/files/difs/assemble/",
            post(assemble),
        )
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> Response {
    eprintln!("error {status}: {msg}");
    (status, Json(json!({"detail": msg.to_string()}))).into_response()
}

fn headers_json(method: &Method, uri: &Uri, headers: &HeaderMap) -> Value {
    let h: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    json!({"method": method.as_str(), "uri": uri.to_string(), "headers": h})
}

/// `X-Sentry-Auth: Sentry sentry_key=...` or `?sentry_key=`. Any key is accepted.
fn sentry_key(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let from_header = headers
        .get("x-sentry-auth")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.trim_start_matches("Sentry ")
                .split(',')
                .filter_map(|kv| kv.trim().split_once('='))
                .find(|(k, _)| *k == "sentry_key")
                .map(|(_, v)| v.to_string())
        });
    from_header.or_else(|| {
        uri.query()?
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "sentry_key")
            .map(|(_, v)| v.to_string())
    })
}

async fn envelope(
    State(st): St,
    Path(project_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let n = st.counter.fetch_add(1, Ordering::SeqCst);
    let stem = st.capture_dir.join(format!("{}-{n:04}", now_millis()));
    let _ = std::fs::write(stem.with_extension("envelope"), &body);
    let _ = std::fs::write(
        stem.with_extension("headers.json"),
        serde_json::to_vec_pretty(&headers_json(&method, &uri, &headers)).unwrap_or_default(),
    );

    let Some(key) = sentry_key(&uri, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "missing sentry_key");
    };
    let encoding = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok());
    let data = match envelope::decode_body(encoding, &body) {
        Ok(d) => d,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let env = match envelope::parse(&data) {
        Ok(e) => e,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let types: Vec<&str> = env.items.iter().map(|i| i.ty()).collect();
    eprintln!(
        "envelope #{n} project={project_id} key={key} bytes={} items={types:?}",
        body.len()
    );

    let mut event_id = env
        .header
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    for item in env.items.iter().filter(|i| i.ty() == "event") {
        let event: Value = match serde_json::from_slice(&item.payload) {
            Ok(v) => v,
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("event json: {e}")),
        };
        let id = event
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| event_id.clone())
            .unwrap_or_else(|| format!("noid-{n}"));
        let _ = std::fs::write(
            st.capture_dir.join(format!("{id}.event.json")),
            serde_json::to_vec_pretty(&event).unwrap_or_default(),
        );
        if has_native_frames(&event) {
            let st2 = st.clone();
            let id2 = id.clone();
            let res = tokio::task::spawn_blocking(move || {
                let provider = SymcacheProvider {
                    data_dir: Some(st2.store.root().to_path_buf()),
                    ..Default::default()
                };
                let report = symbolicate_event(&event, &provider);
                eprintln!(
                    "event {id2}: symbolicated {}/{} frames using {} symcache(s)",
                    report["frames_symbolicated"],
                    report["frames_total"],
                    report["symcaches_found"].as_array().map_or(0, Vec::len)
                );
                std::fs::write(
                    st2.capture_dir.join(format!("{id2}.symbolicated.json")),
                    serde_json::to_vec_pretty(&report)?,
                )
            })
            .await;
            if let Err(e) = res.map_err(anyhow::Error::from).and_then(|r| Ok(r?)) {
                eprintln!("event {id}: symbolication failed: {e:#}");
            }
        }
        event_id = Some(id);
    }
    Json(json!({"id": event_id})).into_response()
}

async fn auth_info() -> Json<Value> {
    Json(json!({
        "version": "0",
        "auth": {"scopes": ["org:read", "project:read", "project:write", "project:releases"]},
        "user": {"id": "1", "name": "spike", "email": "spike@kestrel.invalid"},
    }))
}

async fn chunk_options(Path(org): Path<String>) -> Json<Value> {
    Json(json!({
        "url": format!("/api/0/organizations/{org}/chunk-upload/"),
        "chunkSize": 8 * 1024 * 1024,
        "chunksPerRequest": 64,
        "maxFileSize": 2u64 * 1024 * 1024 * 1024,
        "maxRequestSize": 32 * 1024 * 1024,
        "maxWait": 60,
        "concurrency": 4,
        "hashAlgorithm": "sha1",
        "compression": ["gzip"],
        "accept": ["debug_files", "release_files", "pdbs", "sources", "bcsymbolmaps", "il2cpp", "portablepdbs", "artifact_bundles", "proguard"],
    }))
}

async fn chunk_upload(State(st): St, mut mp: Multipart) -> Response {
    let mut count = 0;
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        };
        let field_name = field.name().unwrap_or("").to_string();
        let Some(checksum) = field.file_name().map(str::to_string) else {
            return err(StatusCode::BAD_REQUEST, "chunk without filename/checksum");
        };
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        };
        let data = match field_name.as_str() {
            "file_gzip" => match envelope::decode_body(Some("gzip"), &data) {
                Ok(d) => d,
                Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            },
            _ => data.to_vec(),
        };
        if let Err(e) = st.store.store_chunk(&checksum, &data) {
            return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }
        count += 1;
    }
    eprintln!("chunk-upload: stored {count} chunk(s)");
    StatusCode::OK.into_response()
}

async fn assemble(
    State(st): St,
    Path((org, project)): Path<(String, String)>,
    Json(req): Json<BTreeMap<String, AssembleItem>>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || st.store.assemble_all(&req)).await;
    match res {
        Ok(v) => {
            eprintln!("assemble {org}/{project}: {v}");
            Json(v).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn fallback(method: Method, uri: Uri) -> Response {
    eprintln!("unhandled {method} {uri}");
    if method == Method::GET {
        Json(json!([])).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `kestrel-spike symbolicate <event.json | .envelope> [--dif PATH]... [--data-dir DIR] [--out FILE]`
fn cli_symbolicate(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut out = None;
    let mut provider = SymcacheProvider::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dif" => {
                let p = PathBuf::from(it.next().context("--dif needs a path")?);
                let n = provider.add_difs(&p)?;
                eprintln!("{}: {n} symcache(s)", p.display());
            }
            "--data-dir" => {
                provider.data_dir =
                    Some(PathBuf::from(it.next().context("--data-dir needs a path")?))
            }
            "--out" => out = Some(PathBuf::from(it.next().context("--out needs a path")?)),
            other if input.is_none() => input = Some(PathBuf::from(other)),
            other => bail!("unexpected argument {other}"),
        }
    }
    let input = input.context("missing <event.json|envelope>")?;
    let raw = envelope::decode_sniff(&std::fs::read(&input)?)?;
    let event: Value = match serde_json::from_slice::<Value>(&raw) {
        Ok(v) if v.get("event_id").is_some() || v.get("debug_meta").is_some() => v,
        _ => {
            let env = envelope::parse(&raw).context("neither event JSON nor envelope")?;
            let item = env
                .items
                .iter()
                .find(|i| i.ty() == "event")
                .context("envelope has no event item")?;
            serde_json::from_slice(&item.payload)?
        }
    };
    let report = symbolicate_event(&event, &provider);
    let text = serde_json::to_string_pretty(&report)?;
    match out {
        Some(p) => std::fs::write(p, text)?,
        None => println!("{text}"),
    }
    eprintln!(
        "symbolicated {}/{} frames",
        report["frames_symbolicated"], report["frames_total"]
    );
    Ok(())
}
