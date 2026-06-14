//! Bencode (BEP 3) decoder and encoder.
//!
//! Bencode has four types: integers (`i<n>e`), byte strings (`<len>:<bytes>`),
//! lists (`l...e`) and dictionaries (`d<key><val>...e`) whose keys are byte
//! strings sorted in raw byte order. Dictionary keys are kept in a
//! [`BTreeMap<Vec<u8>, Value>`], which sorts by raw bytes — exactly the
//! canonical ordering — so re-encoding a dict is byte-identical to a correctly
//! formed input.
//!
//! For the infohash we must hash the *original* bytes of the `info` dictionary
//! (a re-encode can differ for non-canonical inputs), so [`Decoder`] also
//! exposes its cursor and a manual entry-walk; see `metainfo`.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// A decoded bencode value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    /// Byte string interpreted as UTF-8 (lossy callers should handle `None`).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    /// Look up a key in a dictionary value.
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.as_dict().and_then(|d| d.get(key))
    }
}

fn err(msg: &str) -> Error {
    Error::BadResponse(format!("bencode: {msg}"))
}

/// Streaming bencode decoder over an in-memory buffer.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Largest byte-string / collection we will allocate from a length prefix,
/// to bound memory against a hostile length. Torrent metadata is small; a
/// piece-hash table for a very large torrent is still well under this.
const MAX_ALLOC: usize = 256 * 1024 * 1024;
/// Maximum nesting depth, to bound stack use on hostile input.
const MAX_DEPTH: usize = 256;

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, pos: 0 }
    }

    /// Current cursor offset (used to capture the `info` dict's byte span).
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek(&self) -> Result<u8> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| err("unexpected end"))
    }

    /// Parse one complete value at the cursor.
    pub fn value(&mut self) -> Result<Value> {
        self.value_depth(0)
    }

    fn value_depth(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(err("nesting too deep"));
        }
        match self.peek()? {
            b'i' => self.integer(),
            b'l' => self.list(depth),
            b'd' => self.dict(depth),
            b'0'..=b'9' => Ok(Value::Bytes(self.byte_string()?)),
            other => Err(err(&format!("unexpected byte 0x{other:02x}"))),
        }
    }

    /// Parse a top-level dictionary, returning each entry's key together with
    /// the byte range its value occupies in the buffer. Used to capture the
    /// exact bytes of the `info` dictionary for the infohash (which must hash
    /// the original bytes, not a re-encode).
    pub fn dict_entry_spans(&mut self) -> Result<Vec<(Vec<u8>, std::ops::Range<usize>)>> {
        if self.peek()? != b'd' {
            return Err(err("expected dictionary"));
        }
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(out);
            }
            if !self.peek()?.is_ascii_digit() {
                return Err(err("dict key is not a byte string"));
            }
            let key = self.byte_string()?;
            let start = self.pos;
            let _ = self.value()?;
            let end = self.pos;
            out.push((key, start..end));
        }
    }

    fn integer(&mut self) -> Result<Value> {
        // i<digits>e ; no leading zeros, "-0" invalid (BEP 3).
        self.pos += 1; // 'i'
        let start = self.pos;
        let end = self.find(b'e')?;
        let s = std::str::from_utf8(&self.buf[start..end]).map_err(|_| err("non-utf8 integer"))?;
        if s.is_empty() || s == "-0" || (s.starts_with('0') && s.len() > 1) || (s.starts_with("-0"))
        {
            return Err(err("malformed integer"));
        }
        let n: i64 = s.parse().map_err(|_| err("integer out of range"))?;
        self.pos = end + 1;
        Ok(Value::Int(n))
    }

    /// Parse a `<len>:<bytes>` byte string and return its bytes.
    pub fn byte_string(&mut self) -> Result<Vec<u8>> {
        let colon = self.find(b':')?;
        let len_s =
            std::str::from_utf8(&self.buf[self.pos..colon]).map_err(|_| err("bad length"))?;
        if len_s.is_empty() || (len_s.starts_with('0') && len_s.len() > 1) {
            return Err(err("malformed string length"));
        }
        let len: usize = len_s
            .parse()
            .map_err(|_| err("string length out of range"))?;
        if len > MAX_ALLOC {
            return Err(err("string too large"));
        }
        let start = colon + 1;
        let end = start
            .checked_add(len)
            .ok_or_else(|| err("length overflow"))?;
        if end > self.buf.len() {
            return Err(err("string runs past end"));
        }
        self.pos = end;
        Ok(self.buf[start..end].to_vec())
    }

    fn list(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1; // 'l'
        let mut out = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(Value::List(out));
            }
            out.push(self.value_depth(depth + 1)?);
        }
    }

    fn dict(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1; // 'd'
        let mut map = BTreeMap::new();
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(Value::Dict(map));
            }
            if !self.peek()?.is_ascii_digit() {
                return Err(err("dict key is not a byte string"));
            }
            let key = self.byte_string()?;
            // Keys must be strictly increasing (BEP 3 canonical form).
            if let Some(prev) = &last_key {
                if key <= *prev {
                    return Err(err("dict keys not sorted/unique"));
                }
            }
            let val = self.value_depth(depth + 1)?;
            last_key = Some(key.clone());
            map.insert(key, val);
        }
    }

    fn find(&self, b: u8) -> Result<usize> {
        self.buf[self.pos..]
            .iter()
            .position(|&c| c == b)
            .map(|i| self.pos + i)
            .ok_or_else(|| err("missing terminator"))
    }
}

/// Parse a single bencode value, requiring it to consume the whole input.
pub fn parse(input: &[u8]) -> Result<Value> {
    let mut d = Decoder::new(input);
    let v = d.value()?;
    if !d.at_end() {
        return Err(err("trailing bytes after value"));
    }
    Ok(v)
}

/// Encode a value to bencode bytes.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

pub fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(l) => {
            out.push(b'l');
            for item in l {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Value::Dict(d) => {
            out.push(b'd');
            for (k, val) in d {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_into(val, out);
            }
            out.push(b'e');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_basic_types() {
        for input in [
            &b"i42e"[..],
            b"i-7e",
            b"0:",
            b"4:spam",
            b"li1ei2ee",
            b"d3:bar4:spam3:fooi42ee",
        ] {
            let v = parse(input).expect("parse");
            assert_eq!(encode(&v), input, "round-trip {:?}", input);
        }
    }

    #[test]
    fn parses_nested_dict() {
        let v = parse(b"d3:cow3:moo4:spam4:eggse").unwrap();
        assert_eq!(v.get(b"cow").unwrap().as_str(), Some("moo"));
        assert_eq!(v.get(b"spam").unwrap().as_str(), Some("eggs"));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &b"i03e"[..],      // leading zero
            b"i-0e",           // negative zero
            b"ie",             // empty int
            b"2:a",            // short string
            b"d1:bi1e1:ai2ee", // keys out of order
            b"i42",            // missing terminator
            b"i42ee",          // trailing byte
            b"01:a",           // bad length
        ] {
            assert!(parse(bad).is_err(), "should reject {:?}", bad);
        }
    }

    #[test]
    fn dict_keys_sorted_on_encode() {
        // Insert out of order via the API and confirm canonical output.
        let mut d = BTreeMap::new();
        d.insert(b"foo".to_vec(), Value::Int(1));
        d.insert(b"bar".to_vec(), Value::Int(2));
        assert_eq!(encode(&Value::Dict(d)), b"d3:bari2e3:fooi1ee");
    }
}
