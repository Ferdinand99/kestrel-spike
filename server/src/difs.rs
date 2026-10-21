//! Debug information files (DIFs): sentry-cli chunk upload bookkeeping, file assembly and
//! conversion of each contained object to a SymCache.
//!
//! Layout under `$DATA_DIR`:
//! - `chunks/<sha1>`               uploaded chunks
//! - `files/<sha1>`                assembled files
//! - `files/<sha1>.result.json`    cached assemble response for that file
//! - `difs/<debug_id>/symcache`    one SymCache per object (architecture)
//! - `difs/<debug_id>/meta.json`   what produced it

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use symbolic_common::DebugId;
use symbolic_debuginfo::Archive;
use symbolic_symcache::SymCacheConverter;

#[derive(Debug, Deserialize)]
pub struct AssembleItem {
    pub name: String,
    #[serde(default)]
    pub debug_id: Option<String>,
    #[serde(default)]
    pub chunks: Vec<String>,
}

pub struct SymcacheOut {
    pub debug_id: DebugId,
    pub arch: String,
    pub has_debug_info: bool,
    pub has_symbols: bool,
    pub has_unwind_info: bool,
    pub bytes: Vec<u8>,
}

/// Convert every object inside a (possibly fat) object file to a SymCache.
pub fn symcaches_from_bytes(data: &[u8]) -> Result<Vec<SymcacheOut>> {
    let archive = Archive::parse(data).context("not a known object file")?;
    let mut out = Vec::new();
    for obj in archive.objects() {
        let obj = obj.context("object in archive")?;
        if !obj.has_debug_info() && !obj.has_symbols() {
            continue;
        }
        let mut conv = SymCacheConverter::new();
        conv.process_object(&obj).context("symcache conversion")?;
        let mut bytes = Vec::new();
        conv.serialize(&mut Cursor::new(&mut bytes))?;
        out.push(SymcacheOut {
            debug_id: obj.debug_id(),
            arch: obj.arch().name().to_string(),
            has_debug_info: obj.has_debug_info(),
            has_symbols: obj.has_symbols(),
            has_unwind_info: obj.has_unwind_info(),
            bytes,
        });
    }
    Ok(out)
}

fn is_sha1(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub struct DifStore {
    root: PathBuf,
}

impl DifStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for d in ["chunks", "files", "difs"] {
            std::fs::create_dir_all(root.join(d))?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn chunk_path(&self, checksum: &str) -> PathBuf {
        self.root.join("chunks").join(checksum.to_ascii_lowercase())
    }

    pub fn symcache_path(&self, id: &DebugId) -> PathBuf {
        self.root.join("difs").join(id.to_string()).join("symcache")
    }

    /// Store one uploaded chunk after verifying its sha1.
    pub fn store_chunk(&self, checksum: &str, data: &[u8]) -> Result<()> {
        if !is_sha1(checksum) {
            bail!("invalid chunk checksum {checksum:?}");
        }
        let actual = sha1_smol::Sha1::from(data).digest().to_string();
        if !actual.eq_ignore_ascii_case(checksum) {
            bail!("chunk checksum mismatch: declared {checksum}, actual {actual}");
        }
        std::fs::write(self.chunk_path(checksum), data)?;
        Ok(())
    }

    /// Handle one entry of `POST .../files/difs/assemble/`. Returns the per-file response
    /// object (`state`, `missingChunks`, `detail`, `dif`) that sentry-cli expects.
    pub fn assemble(&self, checksum: &str, item: &AssembleItem) -> Value {
        match self.try_assemble(checksum, item) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("assemble {checksum} ({}) failed: {e:#}", item.name);
                json!({"state": "error", "missingChunks": [], "detail": format!("{e:#}")})
            }
        }
    }

    fn try_assemble(&self, checksum: &str, item: &AssembleItem) -> Result<Value> {
        if !is_sha1(checksum) || !item.chunks.iter().all(|c| is_sha1(c)) {
            bail!("invalid checksum");
        }
        let checksum = checksum.to_ascii_lowercase();
        let result_path = self
            .root
            .join("files")
            .join(format!("{checksum}.result.json"));
        if let Ok(cached) = std::fs::read(&result_path) {
            return Ok(serde_json::from_slice(&cached)?);
        }

        let missing: Vec<&String> = item
            .chunks
            .iter()
            .filter(|c| !self.chunk_path(c).is_file())
            .collect();
        if item.chunks.is_empty() || !missing.is_empty() {
            return Ok(json!({"state": "not_found", "missingChunks": missing, "detail": null}));
        }

        let mut data = Vec::new();
        for c in &item.chunks {
            data.extend(std::fs::read(self.chunk_path(c))?);
        }
        let actual = sha1_smol::Sha1::from(&data).digest().to_string();
        if actual != checksum {
            bail!("assembled file checksum mismatch: declared {checksum}, actual {actual}");
        }
        std::fs::write(self.root.join("files").join(&checksum), &data)?;

        let caches = symcaches_from_bytes(&data)?;
        if caches.is_empty() {
            bail!("no debug information or symbols found in {}", item.name);
        }
        let mut written = Vec::new();
        for c in &caches {
            let path = self.symcache_path(&c.debug_id);
            // Never let a symbols-only object (e.g. the stripped app binary) overwrite a
            // SymCache built from real DWARF for the same debug id.
            if !c.has_debug_info && path.exists() {
                continue;
            }
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, &c.bytes)?;
            std::fs::write(
                path.with_file_name("meta.json"),
                serde_json::to_vec_pretty(&json!({
                    "name": item.name,
                    "declared_debug_id": item.debug_id,
                    "file_sha1": checksum,
                    "arch": c.arch,
                    "has_debug_info": c.has_debug_info,
                    "has_symbols": c.has_symbols,
                    "symcache_bytes": c.bytes.len(),
                }))?,
            )?;
            eprintln!(
                "symcache {} ({}, debug_info={}) <- {} [{} bytes]",
                c.debug_id,
                c.arch,
                c.has_debug_info,
                item.name,
                c.bytes.len()
            );
            written.push(c.debug_id);
        }

        let first = &caches[0];
        let mut features = Vec::new();
        if first.has_debug_info {
            features.push("debug");
        }
        if first.has_symbols {
            features.push("symtab");
        }
        if first.has_unwind_info {
            features.push("unwind");
        }
        let result = json!({
            "state": "ok",
            "missingChunks": [],
            "detail": null,
            "dif": {
                "uuid": first.debug_id.to_string(),
                "debugId": first.debug_id.to_string(),
                "objectName": item.name,
                "cpuName": first.arch,
                "sha1": checksum,
                "data": {"features": features},
                "symcaches": written.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
            }
        });
        std::fs::write(&result_path, serde_json::to_vec(&result)?)?;
        Ok(result)
    }

    pub fn assemble_all(&self, req: &BTreeMap<String, AssembleItem>) -> Value {
        let mut out = serde_json::Map::new();
        for (checksum, item) in req {
            out.insert(checksum.clone(), self.assemble(checksum, item));
        }
        Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha1(d: &[u8]) -> String {
        sha1_smol::Sha1::from(d).digest().to_string()
    }

    #[test]
    fn chunk_upload_and_assemble_bookkeeping() {
        let dir = tempfile::tempdir().unwrap();
        let store = DifStore::new(dir.path()).unwrap();

        let a = b"first chunk ".to_vec();
        let b = b"second chunk, not an object file".to_vec();
        let whole: Vec<u8> = [a.clone(), b.clone()].concat();
        let (ca, cb, cw) = (sha1(&a), sha1(&b), sha1(&whole));
        let item = AssembleItem {
            name: "Foo.dSYM/Contents/Resources/DWARF/Foo".into(),
            debug_id: None,
            chunks: vec![ca.clone(), cb.clone()],
        };

        // Nothing uploaded yet: both chunks missing.
        let r = store.assemble(&cw, &item);
        assert_eq!(r["state"], "not_found");
        assert_eq!(r["missingChunks"], json!([ca, cb]));

        // Wrong checksum for a chunk is rejected.
        assert!(store.store_chunk(&ca, &b).is_err());
        assert!(store.store_chunk("../../etc/passwd", &a).is_err());

        // Upload one: only the other is missing.
        store.store_chunk(&ca.to_uppercase(), &a).unwrap();
        let r = store.assemble(&cw, &item);
        assert_eq!(r["state"], "not_found");
        assert_eq!(r["missingChunks"], json!([cb]));

        // All present, but the declared file checksum does not match the chunks.
        store.store_chunk(&cb, &b).unwrap();
        let bad = store.assemble(&sha1(b"something else"), &item);
        assert_eq!(bad["state"], "error");
        assert!(
            bad["detail"]
                .as_str()
                .unwrap()
                .contains("checksum mismatch")
        );

        // All present and consistent, but the content is not an object file: error, and the
        // assembled file was still written.
        let r = store.assemble(&cw, &item);
        assert_eq!(r["state"], "error", "{r}");
        assert!(dir.path().join("files").join(&cw).is_file());

        // Whole request shape as sentry-cli sends it.
        let req: BTreeMap<String, AssembleItem> = serde_json::from_value(json!({
            cw.clone(): {"name": "x", "debug_id": "8d5d1ec4-0b3c-3d93-a7b3-1f0b5bfb5e3c", "chunks": [ca, cb]},
            sha1(b"nope"): {"name": "y", "chunks": [sha1(b"missing")]},
        }))
        .unwrap();
        let all = store.assemble_all(&req);
        assert_eq!(all[&cw]["state"], "error");
        assert_eq!(all[sha1(b"nope")]["state"], "not_found");
    }
}
