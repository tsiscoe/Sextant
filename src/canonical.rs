//! Deterministic canonicalization, LEB128 integer framing, owner-only ACLs, and CWE-150 sanitization.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{SextantError, SextantResult};

/// Sentinel prefix returned by `StrictValueVisitor` when duplicate object keys are encountered.
const DUPLICATE_KEY_SENTINEL: &str = "duplicate JSON object key:";

/// Deserialize JSON strictly, rejecting duplicate object keys at any nesting depth (`SEC-01`).
pub fn parse_strict_json_value(input: &[u8]) -> SextantResult<Value> {
    let mut de = serde_json::Deserializer::from_slice(input);
    let value = StrictValueSeed
        .deserialize(&mut de)
        .map_err(|err| SextantError::CanonicalJsonRequired(err.to_string()))?;
    de.end()
        .map_err(|err| SextantError::CanonicalJsonRequired(err.to_string()))?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any valid JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValueSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "{DUPLICATE_KEY_SENTINEL} '{key}'"
                )));
            }
            let val = map.next_value_seed(StrictValueSeed)?;
            out.insert(key, val);
        }
        Ok(Value::Object(out))
    }
}

/// Serialize a `serde_json::Value` with lexicographically sorted object keys and zero whitespace.
///
/// Sorting keys explicitly via `BTreeMap` guarantees canonical byte output even when Cargo feature
/// unification enables `serde_json/preserve_order` elsewhere in a dependency graph.
pub fn serialize_canonical_value(value: &Value) -> SextantResult<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical_value(value, &mut out)?;
    Ok(out)
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> SextantResult<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(num) => serde_json::to_writer(&mut *out, num)?,
        Value::String(text) => serde_json::to_writer(&mut *out, text)?,
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push(b'{');
            for (idx, (k, v)) in sorted.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, k)?;
                out.push(b':');
                write_canonical_value(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Strictly parse `input` as duplicate-free JSON and emit canonical key-sorted UTF-8 bytes.
pub fn canonicalize_strict_json(input: &[u8]) -> SextantResult<Vec<u8>> {
    let value = parse_strict_json_value(input)?;
    serialize_canonical_value(&value)
}

/// Canonicalize `input` strictly if valid JSON, reject duplicate-key JSON, or preserve raw non-JSON bytes.
pub fn canonicalize_payload_bytes_checked(input: &[u8]) -> SextantResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    match parse_strict_json_value(input) {
        Ok(value) => serialize_canonical_value(&value),
        Err(SextantError::CanonicalJsonRequired(msg)) if msg.contains(DUPLICATE_KEY_SENTINEL) => {
            Err(SextantError::CanonicalJsonRequired(msg))
        }
        Err(_) => Ok(input.to_vec()),
    }
}

/// Compute domain-separated payload digest (`0x01 || bytes` for strict JSON, `0x00 || bytes` for raw, `RESIDUAL-04`).
pub fn hash_payload_bytes(payload: &[u8]) -> [u8; 32] {
    let tag: u8 = if !payload.is_empty() && parse_strict_json_value(payload).is_ok() {
        0x01
    } else {
        0x00
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[tag]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Best-effort canonicalization matching `canonicalize_payload_bytes_checked` for legacy callers.
pub fn canonicalize_payload_bytes(input: &[u8]) -> Vec<u8> {
    canonicalize_payload_bytes_checked(input).unwrap_or_else(|_| input.to_vec())
}

/// Encode an unsigned 64-bit integer using canonical unsigned LEB128 framing.
pub fn encode_leb128_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a canonical unsigned LEB128 `u64`, returning `(value, bytes_consumed)`.
pub fn decode_leb128_u64(input: &[u8]) -> SextantResult<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;

    for (idx, &byte) in input.iter().enumerate() {
        if idx >= 10 {
            return Err(SextantError::InvalidLeb128);
        }
        if idx == 9 && byte > 0x01 {
            return Err(SextantError::InvalidLeb128);
        }
        // Reject overlong non-minimal encodings such as `[0x80, 0x00]` -> `0` (`RESIDUAL-04`).
        if idx > 0 && byte == 0x00 {
            return Err(SextantError::InvalidLeb128);
        }
        let low = u64::from(byte & 0x7f);
        result |= low << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, idx + 1));
        }
        shift += 7;
    }

    Err(SextantError::InvalidLeb128)
}

/// Strip 7-bit/8-bit CSI/OSC ANSI sequences, C0/C1 control chars, and Unicode bidi overrides (CWE-150).
pub fn sanitize_terminal_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{001b}' {
            match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    consume_csi_sequence(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    let _ = chars.next();
                    consume_string_sequence(&mut chars);
                }
                Some(_) => {
                    let _ = chars.next();
                }
                None => {}
            }
            continue;
        }

        // 8-bit C1 CSI (`0x9B`) and string controls (`0x90`, `0x98`, `0x9D`, `0x9E`, `0x9F`).
        if ch == '\u{009b}' {
            consume_csi_sequence(&mut chars);
            continue;
        }
        if matches!(
            ch,
            '\u{0090}' | '\u{0098}' | '\u{009d}' | '\u{009e}' | '\u{009f}'
        ) {
            consume_string_sequence(&mut chars);
            continue;
        }

        if is_bidi_override(ch) {
            continue;
        }

        if ch == '\n' || ch == '\t' || !ch.is_control() {
            out.push(ch);
        }
    }

    out
}

fn consume_csi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for esc_ch in chars.by_ref() {
        if ('@'..='~').contains(&esc_ch) {
            break;
        }
    }
}

fn consume_string_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(ch) = chars.next() {
        if ch == '\u{0007}' || ch == '\u{009c}' {
            break;
        }
        if ch == '\u{001b}' && chars.peek() == Some(&'\\') {
            let _ = chars.next();
            break;
        }
    }
}

fn is_bidi_override(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// Enforce fail-closed owner-only filesystem ACLs (`0700`/`0600` on Unix, `icacls /inheritance:r` on Windows).
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> SextantResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .map_err(|e| SextantError::AclError(format!("chmod {mode:o} failed: {e}")))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(SextantError::AclError(format!(
                "effective mode {applied:o} != {mode:o} on {}",
                path.display()
            )));
        }
    }

    #[cfg(windows)]
    {
        let principal = resolve_windows_owner_principal()?;
        let grant_spec = if is_dir {
            format!("{principal}:(OI)(CI)F")
        } else {
            format!("{principal}:F")
        };
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_spec)
            .output()
            .map_err(|e| {
                SextantError::AclError(format!(
                    "failed to execute icacls on {}: {e}",
                    path.display()
                ))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(SextantError::AclError(format!(
                "icacls failed on {} ({}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            )));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn resolve_windows_owner_principal() -> SextantResult<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !who.is_empty() {
            return Ok(who);
        }
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(SextantError::AclError(
        "unable to resolve Windows owner principal via whoami or USERNAME".to_string(),
    ))
}

/// Shared Serde adapter encoding fixed 64-byte Ed25519 signatures as lowercase hex strings.
pub mod sig_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(sig))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let bytes = hex::decode(raw.trim()).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte signature hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_nested_keys_and_rejects_duplicates() {
        let a = br#"{ "z": 1, "a": { "d": true, "b": [3, 2, 1] } }"#;
        let b = br#"{"a":{"b":[3,2,1],"d":true},"z":1}"#;
        assert_eq!(canonicalize_payload_bytes(a), canonicalize_payload_bytes(b));
        assert_eq!(
            canonicalize_payload_bytes(a),
            br#"{"a":{"b":[3,2,1],"d":true},"z":1}"#
        );

        let dup = br#"{"a":1,"nested":{"k":1,"k":2}}"#;
        assert!(matches!(
            canonicalize_strict_json(dup),
            Err(SextantError::CanonicalJsonRequired(_))
        ));
        assert!(matches!(
            canonicalize_payload_bytes_checked(dup),
            Err(SextantError::CanonicalJsonRequired(_))
        ));
    }

    #[test]
    fn leb128_roundtrip_and_overflow_rejection() {
        for sample in [0u64, 1, 127, 128, 16_384, u64::MAX / 2, u64::MAX] {
            let mut buf = Vec::new();
            encode_leb128_u64(sample, &mut buf);
            let (decoded, used) = decode_leb128_u64(&buf).expect("valid leb128");
            assert_eq!(decoded, sample);
            assert_eq!(used, buf.len());
        }
        let overflow = [0x80u8; 11];
        assert!(decode_leb128_u64(&overflow).is_err());
        let overlong = [0x80u8, 0x00];
        assert!(decode_leb128_u64(&overlong).is_err());
    }

    #[test]
    fn sanitize_terminal_strips_7bit_and_8bit_csi_osc_and_bidi() {
        let dirty = "ok\u{001b}[31mred\u{001b}[0m\u{009b}38;5;196m8bit\u{001b}]0;evil\u{0007}\u{001b}Pdcs\u{001b}\\\u{001b}_apc\u{001b}\\\u{009d}osc\u{009c}\u{202E}txt\x00\n\tok";
        assert_eq!(sanitize_terminal_text(dirty), "okred8bittxt\n\tok");
    }
}
