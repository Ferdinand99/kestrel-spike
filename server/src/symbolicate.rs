//! Native (Apple) event symbolication with SymCaches + Swift demangling.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde_json::{Value, json};
use symbolic_common::{Arch, ByteView, DebugId, InstructionInfo};
use symbolic_demangle::{Demangle, DemangleOptions};
use symbolic_symcache::SymCache;

/// Where SymCaches come from: a `$DATA_DIR` and/or in-memory caches (CLI `--dif`).
#[derive(Default)]
pub struct SymcacheProvider {
    pub data_dir: Option<PathBuf>,
    pub mem: HashMap<DebugId, Vec<u8>>,
}

impl SymcacheProvider {
    fn get(&self, id: &DebugId) -> Option<ByteView<'static>> {
        if let Some(b) = self.mem.get(id) {
            return Some(ByteView::from_vec(b.clone()));
        }
        let dir = self.data_dir.as_ref()?;
        let p = dir.join("difs").join(id.to_string()).join("symcache");
        ByteView::open(p).ok()
    }

    /// Load every object file found under `path` (file or directory, e.g. a `.dSYM` bundle)
    /// into memory as SymCaches.
    pub fn add_difs(&mut self, path: &Path) -> anyhow::Result<usize> {
        let mut n = 0;
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                n += self.add_difs(&entry?.path())?;
            }
            return Ok(n);
        }
        let data = std::fs::read(path)?;
        let Ok(caches) = crate::difs::symcaches_from_bytes(&data) else {
            return Ok(0);
        };
        for c in caches {
            eprintln!(
                "loaded {} ({}, debug_info={}) from {}",
                c.debug_id,
                c.arch,
                c.has_debug_info,
                path.display()
            );
            if c.has_debug_info || !self.mem.contains_key(&c.debug_id) {
                self.mem.insert(c.debug_id, c.bytes);
                n += 1;
            }
        }
        Ok(n)
    }
}

fn parse_addr(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

struct Image {
    debug_id: Option<DebugId>,
    addr: u64,
    size: u64,
    vmaddr: u64,
    name: String,
}

fn images(event: &Value) -> Vec<Image> {
    let Some(list) = event
        .pointer("/debug_meta/images")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|img| {
            let id = img
                .get("debug_id")
                .or_else(|| img.get("uuid"))
                .and_then(Value::as_str)
                .and_then(|s| DebugId::from_str(s).ok());
            Some(Image {
                debug_id: id,
                addr: parse_addr(img.get("image_addr")?)?,
                size: img.get("image_size").and_then(parse_addr).unwrap_or(0),
                vmaddr: img.get("image_vmaddr").and_then(parse_addr).unwrap_or(0),
                name: img
                    .get("code_file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect()
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

/// Does this event carry anything we could symbolicate?
pub fn has_native_frames(event: &Value) -> bool {
    !images(event).is_empty()
        && stacktraces(event)
            .iter()
            .any(|(_, _, st)| st.get("frames").and_then(Value::as_array).is_some())
}

/// (label, crashed, stacktrace)
fn stacktraces(event: &Value) -> Vec<(String, bool, &Value)> {
    let mut out = Vec::new();
    if let Some(values) = event.pointer("/exception/values").and_then(Value::as_array) {
        for (i, exc) in values.iter().enumerate() {
            if let Some(st) = exc.get("stacktrace") {
                let handled = exc
                    .pointer("/mechanism/handled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                out.push((format!("exception[{i}]"), !handled, st));
            }
        }
    }
    if let Some(values) = event.pointer("/threads/values").and_then(Value::as_array) {
        for (i, th) in values.iter().enumerate() {
            if let Some(st) = th.get("stacktrace") {
                let crashed = th.get("crashed").and_then(Value::as_bool).unwrap_or(false);
                let id = th
                    .get("id")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| i.to_string());
                out.push((format!("thread[{id}]"), crashed, st));
            }
        }
    }
    if let Some(st) = event.get("stacktrace") {
        out.push(("stacktrace".into(), false, st));
    }
    out
}

/// Symbolicate all stack traces of an event. Returns a JSON report (not a modified event).
pub fn symbolicate_event(event: &Value, provider: &SymcacheProvider) -> Value {
    let images = images(event);
    let signal = event
        .pointer("/exception/values/0/mechanism/meta/signal/number")
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let device_arch = event
        .pointer("/contexts/device/arch")
        .and_then(Value::as_str)
        .and_then(|a| Arch::from_str(a).ok());

    // Load and parse every SymCache referenced by an image, once.
    let mut views: HashMap<DebugId, ByteView<'static>> = HashMap::new();
    for img in &images {
        if let Some(id) = img.debug_id
            && !views.contains_key(&id)
            && let Some(v) = provider.get(&id)
        {
            views.insert(id, v);
        }
    }
    let caches: HashMap<DebugId, SymCache<'_>> = views
        .iter()
        .filter_map(|(id, v)| match SymCache::parse(v) {
            Ok(c) => Some((*id, c)),
            Err(e) => {
                eprintln!("bad symcache {id}: {e}");
                None
            }
        })
        .collect();

    let mut total = 0usize;
    let mut resolved = 0usize;
    let mut stacks = Vec::new();
    for (label, crashed, st) in stacktraces(event) {
        let Some(frames) = st.get("frames").and_then(Value::as_array) else {
            continue;
        };
        let pc = st
            .get("registers")
            .and_then(|r| r.get("pc").or_else(|| r.get("rip")))
            .and_then(parse_addr);
        let mut out_frames = Vec::new();
        let last = frames.len().saturating_sub(1);
        for (i, frame) in frames.iter().enumerate() {
            total += 1;
            let raw_function = frame.get("function").and_then(Value::as_str);
            let in_app = frame.get("in_app").and_then(Value::as_bool);
            let Some(addr) = frame.get("instruction_addr").and_then(parse_addr) else {
                out_frames.push(json!({"raw_function": raw_function, "function": raw_function, "symbolicated": false, "inlined": false, "in_app": in_app}));
                continue;
            };
            let frame_img = frame.get("image_addr").and_then(parse_addr);
            let img = images
                .iter()
                .find(|im| Some(im.addr) == frame_img)
                .or_else(|| {
                    images
                        .iter()
                        .find(|im| addr >= im.addr && (im.size == 0 || addr < im.addr + im.size))
                });
            let base = json!({
                "instruction_addr": hex(addr),
                "image": img.map(|i| basename(&i.name)),
                "debug_id": img.and_then(|i| i.debug_id).map(|d| d.to_string()),
                "raw_function": raw_function,
                "in_app": in_app,
            });
            let cache = img.and_then(|i| i.debug_id).and_then(|id| caches.get(&id));
            let (Some(img), Some(cache)) = (img, cache) else {
                let mut f = base;
                f["function"] = json!(raw_function);
                f["symbolicated"] = json!(false);
                f["inlined"] = json!(false);
                out_frames.push(f);
                continue;
            };

            // Return addresses point after the call; step back into the call instruction.
            let arch = if cache.arch() != Arch::Unknown {
                cache.arch()
            } else {
                device_arch.unwrap_or(Arch::Arm64)
            };
            let is_top = i == last;
            let caller = InstructionInfo::new(arch, addr)
                .is_crashing_frame(is_top)
                .signal(signal)
                .ip_register_value(if is_top { pc } else { None })
                .caller_address();
            // SymCache addresses are relative to the object's own load (vm) address, so the
            // offset from the runtime image start is what we look up. image_vmaddr is the
            // object's __TEXT vmaddr and needs no further correction here.
            let rel = caller.wrapping_sub(img.addr);

            // lookup() yields innermost (inlined) first; Sentry frame order is caller first.
            let locs: Vec<_> = cache.lookup(rel).collect();
            if locs.is_empty() {
                let mut f = base;
                f["function"] = json!(raw_function);
                f["symbolicated"] = json!(false);
                f["inlined"] = json!(false);
                f["lookup_addr"] = json!(hex(rel));
                out_frames.push(f);
                continue;
            }
            resolved += 1;
            let n = locs.len();
            for (j, loc) in locs.iter().enumerate().rev() {
                let func = loc.function();
                let name = func.name_for_demangling();
                let mut f = base.clone();
                let path = loc.file().map(|f| f.full_path());
                // Swift "simplified UI" form with parameter types (what Sentry displays) plus
                // the fully qualified form with module and return type.
                f["function"] =
                    json!(name.try_demangle(DemangleOptions::complete().return_type(false)));
                f["function_full"] = json!(name.try_demangle(DemangleOptions::complete()));
                f["symbol"] = json!(func.name());
                f["language"] = json!(func.language().name());
                f["filename"] = json!(path.as_deref().map(basename));
                f["abs_path"] = json!(path);
                f["line"] = json!(loc.line());
                f["inlined"] = json!(j + 1 < n);
                f["symbolicated"] = json!(true);
                f["lookup_addr"] = json!(hex(rel));
                f["image_vmaddr"] = json!(hex(img.vmaddr));
                out_frames.push(f);
            }
        }
        stacks.push(json!({"source": label, "crashed": crashed, "frames": out_frames}));
    }

    let exc = event.pointer("/exception/values/0");
    json!({
        "event_id": event.get("event_id"),
        "level": event.get("level"),
        "release": event.get("release"),
        "exception": exc.map(|e| json!({
            "type": e.get("type"),
            "value": e.get("value"),
            "mechanism": e.pointer("/mechanism/type"),
            "handled": e.pointer("/mechanism/handled"),
        })),
        "symcaches_found": caches.keys().map(|k| k.to_string()).collect::<Vec<_>>(),
        "frames_total": total,
        "frames_symbolicated": resolved,
        "stacktraces": stacks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_demangler_is_linked() {
        use symbolic_common::{Language, Name, NameMangling};
        let name = Name::new(
            "$s8mangling9r137577441xySaySiG_tF",
            NameMangling::Mangled,
            Language::Swift,
        );
        // Simplified UI form (what Sentry shows), and the fully qualified form.
        assert_eq!(
            name.try_demangle(DemangleOptions::complete().return_type(false)),
            "r13757744(x: [Int])"
        );
        assert_eq!(
            name.try_demangle(DemangleOptions::complete()),
            "mangling.r13757744(x: Swift.Array<Swift.Int>) -> ()"
        );
    }

    #[test]
    fn unsymbolicated_frames_keep_sdk_names() {
        let event = json!({
            "event_id": "abc",
            "debug_meta": {"images": [
                {"type": "macho", "debug_id": "8d5d1ec4-0b3c-3d93-a7b3-1f0b5bfb5e3c",
                 "image_addr": "0x100000000", "image_size": 4096, "code_file": "/x/App"}
            ]},
            "threads": {"values": [{"id": 0, "crashed": true, "stacktrace": {"frames": [
                {"instruction_addr": "0x100000010", "function": "main"},
                {"instruction_addr": "0x200000010", "function": "libfoo"}
            ]}}]}
        });
        assert!(has_native_frames(&event));
        let r = symbolicate_event(&event, &SymcacheProvider::default());
        let frames = r["stacktraces"][0]["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["image"], "App");
        assert_eq!(frames[0]["function"], "main");
        assert_eq!(frames[0]["symbolicated"], false);
        assert_eq!(frames[1]["image"], Value::Null);
        assert_eq!(r["frames_symbolicated"], 0);
    }
}
