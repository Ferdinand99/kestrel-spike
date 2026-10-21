//! Sentry envelope parsing and request body decoding.
//!
//! Format: <https://develop.sentry.dev/sdk/data-model/envelopes/>
//! `header-json \n (item-header-json \n payload [\n])*`

use std::io::Read;

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[derive(Debug)]
pub struct Item {
    pub header: Value,
    pub payload: Vec<u8>,
}

impl Item {
    pub fn ty(&self) -> &str {
        self.header
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
    }
}

#[derive(Debug)]
pub struct Envelope {
    pub header: Value,
    pub items: Vec<Item>,
}

/// Undo `Content-Encoding` (gzip, deflate, br). Unknown encodings are an error.
pub fn decode_body(encoding: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match encoding.map(|e| e.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("identity") => out.extend_from_slice(body),
        Some("gzip") | Some("x-gzip") => {
            flate2::read::MultiGzDecoder::new(body)
                .read_to_end(&mut out)
                .context("gzip")?;
        }
        Some("deflate") => {
            // HTTP "deflate" is zlib-wrapped, but some clients send raw deflate.
            if flate2::read::ZlibDecoder::new(body)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(body)
                    .read_to_end(&mut out)
                    .context("deflate")?;
            }
        }
        Some("br") => {
            brotli::Decompressor::new(body, 4096)
                .read_to_end(&mut out)
                .context("br")?;
        }
        Some(other) => bail!("unsupported content-encoding {other}"),
    }
    Ok(out)
}

/// Like [`decode_body`] but sniffs gzip magic when no encoding is known (used for capture files).
pub fn decode_sniff(body: &[u8]) -> Result<Vec<u8>> {
    if body.starts_with(&[0x1f, 0x8b]) {
        decode_body(Some("gzip"), body)
    } else {
        Ok(body.to_vec())
    }
}

fn split_line(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[]),
    }
}

pub fn parse(data: &[u8]) -> Result<Envelope> {
    let (header_line, mut rest) = split_line(data);
    let header: Value = serde_json::from_slice(header_line).context("envelope header")?;
    let mut items = Vec::new();
    loop {
        // Tolerate blank lines / trailing newlines between items.
        while let Some((b'\n' | b'\r', r)) = rest.split_first() {
            rest = r;
        }
        if rest.is_empty() {
            break;
        }
        let (item_line, after) = split_line(rest);
        let item_header: Value = serde_json::from_slice(item_line).context("item header")?;
        let payload;
        match item_header.get("length").and_then(Value::as_u64) {
            Some(len) => {
                let len = len as usize;
                if after.len() < len {
                    bail!("item length {len} exceeds remaining {} bytes", after.len());
                }
                payload = after[..len].to_vec();
                rest = &after[len..];
                if let Some((b'\n', r)) = rest.split_first() {
                    rest = r;
                }
            }
            None => {
                let (p, r) = split_line(after);
                payload = p.to_vec();
                rest = r;
            }
        }
        items.push(Item {
            header: item_header,
            payload,
        });
    }
    Ok(Envelope { header, items })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const ENVELOPE: &[u8] = b"{\"event_id\":\"9ec79c33ec9942ab8353589fcb2e04dc\",\"dsn\":\"http://k@127.0.0.1:9000/1\"}\n\
{\"type\":\"attachment\",\"length\":10,\"filename\":\"a.txt\"}\n\
\xef\xbb\xbfHello\r\n\n\
{\"type\":\"event\",\"length\":41}\n\
{\"message\":\"hello\",\"level\":\"error\",\"x\":1}\n\
{\"type\":\"session\"}\n\
{\"started\":\"2020-02-07T14:16:00Z\"}\n";

    fn check(env: &Envelope) {
        assert_eq!(env.header["event_id"], "9ec79c33ec9942ab8353589fcb2e04dc");
        assert_eq!(env.items.len(), 3);
        assert_eq!(env.items[0].ty(), "attachment");
        assert_eq!(env.items[0].payload, b"\xef\xbb\xbfHello\r\n");
        assert_eq!(env.items[1].ty(), "event");
        let ev: Value = serde_json::from_slice(&env.items[1].payload).unwrap();
        assert_eq!(ev["message"], "hello");
        assert_eq!(env.items[2].ty(), "session");
        assert_eq!(
            env.items[2].payload,
            b"{\"started\":\"2020-02-07T14:16:00Z\"}"
        );
    }

    #[test]
    fn parses_plain() {
        check(&parse(&decode_body(None, ENVELOPE).unwrap()).unwrap());
    }

    #[test]
    fn parses_gzip() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(ENVELOPE).unwrap();
        let gz = enc.finish().unwrap();
        check(&parse(&decode_body(Some("gzip"), &gz).unwrap()).unwrap());
        check(&parse(&decode_sniff(&gz).unwrap()).unwrap());
    }

    #[test]
    fn parses_deflate_and_header_only() {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(ENVELOPE).unwrap();
        let z = enc.finish().unwrap();
        check(&parse(&decode_body(Some("deflate"), &z).unwrap()).unwrap());
        let only = parse(b"{}").unwrap();
        assert!(only.items.is_empty());
    }

    #[test]
    fn rejects_short_item() {
        assert!(parse(b"{}\n{\"type\":\"event\",\"length\":99}\n{}").is_err());
    }
}
