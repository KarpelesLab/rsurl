//! LDAP and LDAPS support.
//!
//! Specs: RFC 4511 (LDAP protocol), RFC 4516 (LDAP URL format),
//! RFC 4513 (LDAP authentication / TLS), RFC 2849 (LDIF).
//!
//! LDAP URLs look like `ldap://host/dn?attrs?scope?filter?extensions`.
//! Protocol messages are BER-encoded. We hand-roll the small amount of BER
//! we need (`purecrypto::der` has helpers for the universal DER subset but
//! does not directly cover APPLICATION-class tags used pervasively by LDAP).
//!
//! Scope of this module: a single Bind + Search + Unbind round-trip. The
//! filter parser handles `(attr=value)` (equality), `(attr=*)` (present),
//! substrings (`(cn=foo*bar*baz)`, RFC 4511 §4.5.1), extensible match
//! (`(attr:rule:=value)`, RFC 4515 §3), and boolean combinations
//! `(&...)`, `(|...)`, `(!...)`.

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::NetConfig;
use crate::tls::connect_over;
use crate::url::Url;

// =============================================================================
// BER tag bytes used by LDAP
// =============================================================================

mod tag {
    // Universal primitive
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const ENUMERATED: u8 = 0x0A;
    // Universal constructed
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    // Class bits (top 2 bits of tag byte)
    pub const CLASS_APPLICATION: u8 = 0x40;
    pub const CLASS_CONTEXT: u8 = 0x80;
    // PC bit
    pub const CONSTRUCTED: u8 = 0x20;

    /// Build an APPLICATION-class tag byte. `constructed` controls the P/C bit.
    /// LDAP uses tags 0..27 so we never need the multi-byte high-tag form.
    pub const fn app(n: u8, constructed: bool) -> u8 {
        CLASS_APPLICATION | if constructed { CONSTRUCTED } else { 0 } | (n & 0x1f)
    }

    /// Build a CONTEXT-class tag byte.
    pub const fn ctx(n: u8, constructed: bool) -> u8 {
        CLASS_CONTEXT | if constructed { CONSTRUCTED } else { 0 } | (n & 0x1f)
    }
}

// LDAP protocol op application tags (RFC 4511 §4)
const APP_BIND_REQUEST: u8 = 0;
const APP_BIND_RESPONSE: u8 = 1;
const APP_UNBIND_REQUEST: u8 = 2;
const APP_SEARCH_REQUEST: u8 = 3;
const APP_SEARCH_RESULT_ENTRY: u8 = 4;
const APP_SEARCH_RESULT_DONE: u8 = 5;
const APP_SEARCH_RESULT_REFERENCE: u8 = 19;

// =============================================================================
// BER writer
// =============================================================================

/// Encode a definite-form length, minimally. Matches DER and what LDAP wants.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut tmp = [0u8; 8];
    let mut n = 0usize;
    let mut l = len;
    while l > 0 {
        tmp[n] = (l & 0xff) as u8;
        l >>= 8;
        n += 1;
    }
    out.push(0x80 | n as u8);
    for i in (0..n).rev() {
        out.push(tmp[i]);
    }
}

/// Write a TLV with the given tag byte and pre-built value.
fn write_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    encode_length(value.len(), out);
    out.extend_from_slice(value);
}

/// Run `f` to write the body, then prepend a TLV header with `tag`.
fn write_constructed(out: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
    let start = out.len();
    out.push(tag);
    // Placeholder for length (we'll patch after).
    out.push(0);
    let body_start = out.len();
    f(out);
    let body_len = out.len() - body_start;
    // Rebuild the header with the correct length, then splice it in.
    if body_len < 0x80 {
        out[start + 1] = body_len as u8;
    } else {
        // Encode the length into a temporary buffer, then insert the extra
        // bytes after the tag byte.
        let mut hdr = Vec::with_capacity(9);
        encode_length(body_len, &mut hdr);
        // Replace the single placeholder byte with the real length bytes.
        out.splice(start + 1..start + 2, hdr.iter().copied());
    }
}

fn write_integer(out: &mut Vec<u8>, v: i64) {
    // Two's-complement, minimal-length encoding per X.690 §8.3.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let first = bytes[0];
        let next = bytes[1];
        // Drop a redundant leading byte: 0x00 if next high bit is 0,
        // or 0xff if next high bit is 1.
        if (first == 0x00 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    write_tlv(out, tag::INTEGER, &bytes);
}

fn write_enumerated(out: &mut Vec<u8>, v: i64) {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let first = bytes[0];
        let next = bytes[1];
        if (first == 0x00 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    write_tlv(out, tag::ENUMERATED, &bytes);
}

fn write_octet_string(out: &mut Vec<u8>, s: &[u8]) {
    write_tlv(out, tag::OCTET_STRING, s);
}

fn write_boolean(out: &mut Vec<u8>, b: bool) {
    write_tlv(out, tag::BOOLEAN, &[if b { 0xff } else { 0x00 }]);
}

// =============================================================================
// BER reader
// =============================================================================

#[derive(Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

struct BerReader<'a> {
    data: &'a [u8],
}

impl<'a> BerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BerReader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read_length(&mut self) -> Result<usize> {
        if self.data.is_empty() {
            return Err(Error::BadResponse("ber: truncated length".into()));
        }
        let first = self.data[0];
        self.data = &self.data[1..];
        if first < 0x80 {
            return Ok(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(Error::BadResponse(
                "ber: indefinite length not allowed".into(),
            ));
        }
        if n > std::mem::size_of::<usize>() {
            return Err(Error::BadResponse("ber: length too large".into()));
        }
        if self.data.len() < n {
            return Err(Error::BadResponse("ber: truncated length bytes".into()));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | self.data[i] as usize;
        }
        self.data = &self.data[n..];
        Ok(len)
    }

    fn read_tlv(&mut self) -> Result<Tlv<'a>> {
        if self.data.is_empty() {
            return Err(Error::BadResponse("ber: truncated tag".into()));
        }
        let tag = self.data[0];
        self.data = &self.data[1..];
        let len = self.read_length()?;
        if self.data.len() < len {
            return Err(Error::BadResponse("ber: truncated value".into()));
        }
        let value = &self.data[..len];
        self.data = &self.data[len..];
        Ok(Tlv { tag, value })
    }

    fn read_expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let tlv = self.read_tlv()?;
        if tlv.tag != tag {
            return Err(Error::BadResponse(format!(
                "ber: expected tag {:#04x}, got {:#04x}",
                tag, tlv.tag
            )));
        }
        Ok(tlv.value)
    }

    fn read_integer_i64(&mut self) -> Result<i64> {
        let v = self.read_expect(tag::INTEGER)?;
        decode_integer_i64(v)
    }

    fn read_enumerated_i64(&mut self) -> Result<i64> {
        let v = self.read_expect(tag::ENUMERATED)?;
        decode_integer_i64(v)
    }

    fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        self.read_expect(tag::OCTET_STRING)
    }
}

fn decode_integer_i64(bytes: &[u8]) -> Result<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Error::BadResponse("ber: bad integer length".into()));
    }
    // Sign-extend from the most significant byte.
    let mut acc: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        acc = (acc << 8) | b as i64;
    }
    Ok(acc)
}

// =============================================================================
// URL parsing per RFC 4516
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    Base,
    OneLevel,
    Subtree,
}

impl Scope {
    fn as_int(&self) -> i64 {
        match self {
            Scope::Base => 0,
            Scope::OneLevel => 1,
            Scope::Subtree => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedUrlQuery {
    dn: String,
    attrs: Vec<String>,
    scope: Scope,
    filter: String,
}

/// Percent-decode a URL component. Invalid escapes are passed through as-is.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            let h1 = hex_val(bytes[i + 1]);
            let h2 = hex_val(bytes[i + 2]);
            if let (Some(h1), Some(h2)) = (h1, h2) {
                out.push((h1 << 4) | h2);
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reject a percent-decoded URL component that contains NUL, CR, LF, or any
/// other ASCII control byte before it's BER-encoded into an LDAP request.
/// BER framing is length-prefixed so embedded control bytes don't break the
/// wire format, but they have no legitimate place in a DN / bind value /
/// filter and rejecting them is cheap defense-in-depth. `what` names the field.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    crate::url::reject_ctl("ldap", what, s)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// Parse the path/query of an LDAP URL. The `path` already starts with `/`.
fn parse_ldap_path(path: &str) -> Result<ParsedUrlQuery> {
    // Strip leading `/`.
    let rest = path.strip_prefix('/').unwrap_or(path);
    // Split on `?` — RFC 4516 uses at most five components.
    let mut parts = rest.splitn(5, '?');
    let dn_raw = parts.next().unwrap_or("");
    let attrs_raw = parts.next().unwrap_or("");
    let scope_raw = parts.next().unwrap_or("");
    let filter_raw = parts.next().unwrap_or("");
    let _extensions = parts.next().unwrap_or("");

    let dn = percent_decode(dn_raw);

    let attrs: Vec<String> = if attrs_raw.is_empty() {
        Vec::new()
    } else {
        attrs_raw
            .split(',')
            .map(|a| percent_decode(a.trim()))
            .filter(|a| !a.is_empty())
            .collect()
    };

    let scope = match scope_raw.to_ascii_lowercase().as_str() {
        "" | "base" => Scope::Base,
        "one" => Scope::OneLevel,
        "sub" => Scope::Subtree,
        other => {
            return Err(Error::BadResponse(format!(
                "ldap url: unknown scope {other:?}"
            )))
        }
    };

    let filter = if filter_raw.is_empty() {
        "(objectClass=*)".to_string()
    } else {
        percent_decode(filter_raw)
    };

    Ok(ParsedUrlQuery {
        dn,
        attrs,
        scope,
        filter,
    })
}

// =============================================================================
// LDAP filter parsing and encoding (RFC 4515 / RFC 4511 §4.5.1.7)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch {
        attr: String,
        value: String,
    },
    /// RFC 4511 §4.5.1 substrings filter. At most one `initial` (leading
    /// segment before the first `*`) and one `final` (trailing segment after
    /// the last `*`); zero or more `any` segments in between.
    Substrings {
        attr: String,
        initial: Option<String>,
        any: Vec<String>,
        final_: Option<String>,
    },
    Present(String),
    /// RFC 4511 §4.5.1 extensibleMatch / RFC 4515 §3 string form
    /// `(attr:dn:rule:=value)`. `matching_rule` is the optional `[1]`
    /// MatchingRuleId (OID or name), `attr_type` the optional `[2]`
    /// AttributeDescription, `match_value` the required `[3]` AssertionValue,
    /// and `dn_attributes` the `[4]` BOOLEAN (only emitted when TRUE).
    ExtensibleMatch {
        matching_rule: Option<String>,
        attr_type: Option<String>,
        match_value: String,
        dn_attributes: bool,
    },
}

/// Maximum nesting depth of `&`/`|`/`!` filter groups. Bounds parser
/// recursion so a maliciously deep filter (e.g. `(!(!(!...)))`) cannot
/// overflow the native stack.
const MAX_FILTER_DEPTH: usize = 64;

struct FilterParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> FilterParser<'a> {
    fn new(s: &'a str) -> Self {
        FilterParser {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn expect(&mut self, c: u8) -> Result<()> {
        match self.bump() {
            Some(x) if x == c => Ok(()),
            Some(x) => Err(Error::BadResponse(format!(
                "filter: expected {:?}, got {:?}",
                c as char, x as char
            ))),
            None => Err(Error::BadResponse(format!(
                "filter: expected {:?}, got EOF",
                c as char
            ))),
        }
    }

    fn parse(&mut self, depth: usize) -> Result<Filter> {
        if depth > MAX_FILTER_DEPTH {
            return Err(Error::BadResponse("ldap: filter nesting too deep".into()));
        }
        self.expect(b'(')?;
        let f = match self.peek() {
            Some(b'&') => {
                self.bump();
                let items = self.parse_list(depth + 1)?;
                Filter::And(items)
            }
            Some(b'|') => {
                self.bump();
                let items = self.parse_list(depth + 1)?;
                Filter::Or(items)
            }
            Some(b'!') => {
                self.bump();
                let inner = self.parse(depth + 1)?;
                Filter::Not(Box::new(inner))
            }
            Some(_) => self.parse_simple()?,
            None => return Err(Error::BadResponse("filter: empty filter".into())),
        };
        self.expect(b')')?;
        Ok(f)
    }

    fn parse_list(&mut self, depth: usize) -> Result<Vec<Filter>> {
        let mut out = Vec::new();
        while self.peek() == Some(b'(') {
            out.push(self.parse(depth)?);
        }
        if out.is_empty() {
            return Err(Error::BadResponse("filter: empty list".into()));
        }
        Ok(out)
    }

    fn parse_simple(&mut self) -> Result<Filter> {
        // Read the description part up to '=' (the value separator). We allow
        // ':' here because the extensible-match form `(attr:dn:rule:=value)`
        // embeds colons before its `:=` operator; `~=`, `>=`, `<=` are still
        // unsupported.
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'=' || c == b')' {
                break;
            }
            // `~=`, `>=`, `<=` aren't supported. A leading `:` (and the colons
            // inside an extensible match) are fine and handled below.
            if c == b'~' || c == b'<' || c == b'>' {
                return Err(Error::BadResponse(format!(
                    "filter: operator {:?} not supported",
                    c as char
                )));
            }
            self.bump();
        }
        let desc = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| Error::BadResponse("filter: non-utf8 attr".into()))?
            .to_string();
        self.expect(b'=')?;
        // Extensible match: the description ends with a `:` (forming the `:=`
        // operator) or contains `:` at all. RFC 4515 §3 string forms:
        //   attr:=value  attr:dn:=value  attr:rule:=value  attr:dn:rule:=value
        //   :rule:=value  :dn:rule:=value
        if desc.contains(':') {
            return self.parse_extensible(&desc);
        }
        let attr = desc;
        let value_raw = self.read_value()?;
        // A bare `*` is the presence filter, NOT a substring match.
        if value_raw == "*" {
            return Ok(Filter::Present(attr));
        }
        if value_raw.contains('*') {
            // Substrings filter (RFC 4511 §4.5.1). Split on `*` into segments.
            // The leading non-empty segment is `initial`; the trailing one is
            // `final`; non-empty interior segments are `any` (in order). Empty
            // segments (from leading/trailing/consecutive `*`) contribute
            // nothing. The equality path does no RFC 4515 de-escaping, so for
            // parity neither do we: every `*` is treated as a wildcard.
            let segments: Vec<&str> = value_raw.split('*').collect();
            let last = segments.len() - 1;
            let mut initial = None;
            let mut any = Vec::new();
            let mut final_ = None;
            for (i, seg) in segments.iter().enumerate() {
                if seg.is_empty() {
                    continue;
                }
                // Each assertion value is BER-encoded into the request; reject
                // embedded control bytes the same as every other filter field.
                reject_ctl(seg, "filter substring segment")?;
                if i == 0 {
                    initial = Some(seg.to_string());
                } else if i == last {
                    final_ = Some(seg.to_string());
                } else {
                    any.push(seg.to_string());
                }
            }
            return Ok(Filter::Substrings {
                attr,
                initial,
                any,
                final_,
            });
        }
        Ok(Filter::EqualityMatch {
            attr,
            value: value_raw,
        })
    }

    /// Read an assertion value up to the closing `)`.
    fn read_value(&mut self) -> Result<String> {
        let vstart = self.pos;
        while let Some(c) = self.peek() {
            if c == b')' {
                break;
            }
            self.bump();
        }
        std::str::from_utf8(&self.bytes[vstart..self.pos])
            .map_err(|_| Error::BadResponse("filter: non-utf8 value".into()))
            .map(|s| s.to_string())
    }

    /// Parse the extensible-match form (RFC 4515 §3). `desc` is the text before
    /// the `=` of the `:=` operator — i.e. everything up to and including the
    /// final `:`. The caller has already consumed the `=`; this reads the value.
    ///
    /// `desc` always ends with the operator's `:` and is split on `:`:
    ///   `cn:`            -> ["cn", ""]            attr only
    ///   `cn:dn:`         -> ["cn", "dn", ""]      attr + dn
    ///   `cn:rule:`       -> ["cn", "rule", ""]    attr + matchingRule
    ///   `cn:dn:rule:`    -> ["cn", "dn", "rule", ""]
    ///   `:rule:`         -> ["", "rule", ""]      no attr, matchingRule
    ///   `:dn:rule:`      -> ["", "dn", "rule", ""]
    /// The first token is the attribute description (empty => none). The final
    /// token is the empty string left of the `:=`. Interior tokens are the
    /// optional `dn` marker and/or the matchingRule, in either supported order.
    fn parse_extensible(&mut self, desc: &str) -> Result<Filter> {
        let mut tokens: Vec<&str> = desc.split(':').collect();
        // The last token is the empty string immediately before `:=`.
        match tokens.last() {
            Some(&"") => {
                tokens.pop();
            }
            _ => {
                // `desc` came from text ending at the `=`; the operator is `:=`
                // so the final segment must be empty. Anything else (e.g. a `:`
                // in the middle of an attribute, which RFC 4515 disallows) is a
                // malformed filter.
                return Err(Error::BadResponse(
                    "filter: malformed extensible match (expected ':=')".into(),
                ));
            }
        }
        if tokens.is_empty() {
            return Err(Error::BadResponse(
                "filter: empty extensible match description".into(),
            ));
        }
        // First token is the attribute type (may be empty => no type).
        let attr_type = {
            let a = tokens.remove(0);
            if a.is_empty() {
                None
            } else {
                Some(a.to_string())
            }
        };
        // Remaining tokens: an optional `dn` marker and an optional matchingRule.
        let mut dn_attributes = false;
        let mut matching_rule: Option<String> = None;
        for tok in tokens {
            if tok == "dn" {
                if dn_attributes {
                    return Err(Error::BadResponse(
                        "filter: duplicate 'dn' in extensible match".into(),
                    ));
                }
                dn_attributes = true;
            } else if tok.is_empty() {
                return Err(Error::BadResponse(
                    "filter: empty token in extensible match".into(),
                ));
            } else if matching_rule.is_some() {
                return Err(Error::BadResponse(
                    "filter: multiple matching rules in extensible match".into(),
                ));
            } else {
                matching_rule = Some(tok.to_string());
            }
        }
        // An extensible match must constrain on something: a type, a rule, or
        // both. `(:dn:=value)` (dn only, no type and no rule) is meaningless.
        if attr_type.is_none() && matching_rule.is_none() {
            return Err(Error::BadResponse(
                "filter: extensible match needs an attribute or matching rule".into(),
            ));
        }
        let match_value = self.read_value()?;
        // Every field is BER-encoded into the request; reject embedded control
        // bytes the same as every other filter field. (Like equality, no RFC
        // 4515 de-escaping is performed.)
        reject_ctl(&match_value, "filter extensible match value")?;
        if let Some(t) = &attr_type {
            reject_ctl(t, "filter extensible match attribute")?;
        }
        if let Some(r) = &matching_rule {
            reject_ctl(r, "filter extensible match rule")?;
        }
        Ok(Filter::ExtensibleMatch {
            matching_rule,
            attr_type,
            match_value,
            dn_attributes,
        })
    }
}

fn parse_filter(s: &str) -> Result<Filter> {
    let mut p = FilterParser::new(s);
    let f = p.parse(0)?;
    if p.pos != p.bytes.len() {
        return Err(Error::BadResponse("filter: trailing garbage".into()));
    }
    Ok(f)
}

/// Encode a Filter into BER per RFC 4511 §4.5.1.7. All filter alternatives
/// are CONTEXT-class tags 0..9.
fn encode_filter(out: &mut Vec<u8>, f: &Filter) {
    match f {
        Filter::And(items) => {
            write_constructed(out, tag::ctx(0, true), |w| {
                for it in items {
                    encode_filter(w, it);
                }
            });
        }
        Filter::Or(items) => {
            write_constructed(out, tag::ctx(1, true), |w| {
                for it in items {
                    encode_filter(w, it);
                }
            });
        }
        Filter::Not(inner) => {
            write_constructed(out, tag::ctx(2, true), |w| {
                encode_filter(w, inner);
            });
        }
        Filter::EqualityMatch { attr, value } => {
            // [3] AttributeValueAssertion -- SEQUENCE { AttributeDescription, AssertionValue }
            write_constructed(out, tag::ctx(3, true), |w| {
                write_octet_string(w, attr.as_bytes());
                write_octet_string(w, value.as_bytes());
            });
        }
        Filter::Substrings {
            attr,
            initial,
            any,
            final_,
        } => {
            // [4] SubstringFilter ::= SEQUENCE {
            //   type AttributeDescription,
            //   substrings SEQUENCE OF CHOICE {
            //     initial [0] AssertionValue,
            //     any     [1] AssertionValue,
            //     final   [2] AssertionValue } }
            write_constructed(out, tag::ctx(4, true), |w| {
                write_octet_string(w, attr.as_bytes());
                write_constructed(w, tag::SEQUENCE, |subs| {
                    if let Some(s) = initial {
                        // initial [0] -- primitive octet string
                        write_tlv(subs, tag::ctx(0, false), s.as_bytes());
                    }
                    for s in any {
                        // any [1] -- primitive octet string
                        write_tlv(subs, tag::ctx(1, false), s.as_bytes());
                    }
                    if let Some(s) = final_ {
                        // final [2] -- primitive octet string
                        write_tlv(subs, tag::ctx(2, false), s.as_bytes());
                    }
                });
            });
        }
        Filter::Present(attr) => {
            // [7] AttributeDescription -- primitive octet string
            write_tlv(out, tag::ctx(7, false), attr.as_bytes());
        }
        Filter::ExtensibleMatch {
            matching_rule,
            attr_type,
            match_value,
            dn_attributes,
        } => {
            // [9] MatchingRuleAssertion ::= SEQUENCE {
            //   matchingRule [1] MatchingRuleId OPTIONAL,
            //   type         [2] AttributeDescription OPTIONAL,
            //   matchValue   [3] AssertionValue,
            //   dnAttributes [4] BOOLEAN DEFAULT FALSE }
            // The outer tag is context [9] constructed (0xA9); the children are
            // primitive context strings in field order. dnAttributes is only
            // emitted when TRUE (DEFAULT FALSE is omitted).
            write_constructed(out, tag::ctx(9, true), |w| {
                if let Some(rule) = matching_rule {
                    // matchingRule [1] -- primitive octet string
                    write_tlv(w, tag::ctx(1, false), rule.as_bytes());
                }
                if let Some(t) = attr_type {
                    // type [2] -- primitive octet string
                    write_tlv(w, tag::ctx(2, false), t.as_bytes());
                }
                // matchValue [3] -- primitive octet string (REQUIRED)
                write_tlv(w, tag::ctx(3, false), match_value.as_bytes());
                if *dn_attributes {
                    // dnAttributes [4] -- BOOLEAN, single 0xFF byte
                    write_tlv(w, tag::ctx(4, false), &[0xff]);
                }
            });
        }
    }
}

// =============================================================================
// Wire I/O — bind / search / unbind
// =============================================================================

const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on a single LDAP message body length decoded from the wire.
/// `read_message` would otherwise `vec![0u8; len]` for an attacker-chosen BER
/// length bounded only by `usize` — an unbounded allocation / DoS vector.
/// 64 MiB matches the crate's other body caps (e.g. `rtsp`, `websocket`).
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Hold either a raw TCP stream or a TLS-wrapped one behind the same code path
/// — the shared transport enum. (LDAPS is implicit here, so the in-place
/// upgrade is unused.)
use crate::net::MaybeTlsStream as Transport;

/// Read exactly one LDAP message off the wire and return its contents as a
/// new Vec (the SEQUENCE body bytes — i.e. messageID, protocolOp, [controls]).
fn read_message(t: &mut Transport) -> Result<Vec<u8>> {
    read_message_from(t)
}

/// Generic body of [`read_message`], parameterized over the reader so it can be
/// unit-tested with an in-memory cursor.
fn read_message_from<R: Read>(t: &mut R) -> Result<Vec<u8>> {
    // Tag byte
    let mut tag_buf = [0u8; 1];
    read_exact(t, &mut tag_buf)?;
    if tag_buf[0] != tag::SEQUENCE {
        return Err(Error::BadResponse(format!(
            "ldap: expected SEQUENCE, got {:#04x}",
            tag_buf[0]
        )));
    }
    // Length
    let mut first = [0u8; 1];
    read_exact(t, &mut first)?;
    let len = if first[0] < 0x80 {
        first[0] as usize
    } else {
        let n = (first[0] & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return Err(Error::BadResponse("ldap: bad length form".into()));
        }
        let mut lb = [0u8; 8];
        read_exact(t, &mut lb[..n])?;
        let mut acc = 0usize;
        for b in &lb[..n] {
            acc = (acc << 8) | *b as usize;
        }
        acc
    };
    if len > MAX_MESSAGE_BYTES {
        return Err(Error::BadResponse(format!(
            "ldap: message length {len} exceeds maximum {MAX_MESSAGE_BYTES}"
        )));
    }
    // Body
    let mut body = vec![0u8; len];
    read_exact(t, &mut body)?;
    Ok(body)
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        filled += n;
    }
    Ok(())
}

fn build_bind_request(message_id: i32, name: &str, password: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE ..., ... }
    write_constructed(&mut msg, tag::SEQUENCE, |w| {
        write_integer(w, message_id as i64);
        // BindRequest ::= [APPLICATION 0] SEQUENCE {
        //   version INTEGER (1..127),
        //   name LDAPDN,
        //   authentication AuthenticationChoice }
        write_constructed(w, tag::app(APP_BIND_REQUEST, true), |b| {
            write_integer(b, 3);
            write_octet_string(b, name.as_bytes());
            // simple [0] OCTET STRING
            write_tlv(b, tag::ctx(0, false), password.as_bytes());
        });
    });
    msg
}

fn build_unbind_request(message_id: i32) -> Vec<u8> {
    let mut msg = Vec::new();
    write_constructed(&mut msg, tag::SEQUENCE, |w| {
        write_integer(w, message_id as i64);
        // UnbindRequest ::= [APPLICATION 2] NULL -- primitive, empty body
        write_tlv(w, tag::app(APP_UNBIND_REQUEST, false), &[]);
    });
    msg
}

fn build_search_request(message_id: i32, q: &ParsedUrlQuery) -> Result<Vec<u8>> {
    let filter = parse_filter(&q.filter)?;
    let mut msg = Vec::new();
    write_constructed(&mut msg, tag::SEQUENCE, |w| {
        write_integer(w, message_id as i64);
        // SearchRequest ::= [APPLICATION 3] SEQUENCE { ... }
        write_constructed(w, tag::app(APP_SEARCH_REQUEST, true), |s| {
            write_octet_string(s, q.dn.as_bytes());
            write_enumerated(s, q.scope.as_int()); // scope
            write_enumerated(s, 0); // derefAliases = neverDerefAliases
            write_integer(s, 100); // sizeLimit
            write_integer(s, 30); // timeLimit
            write_boolean(s, false); // typesOnly
            encode_filter(s, &filter);
            // AttributeSelection ::= SEQUENCE OF LDAPString
            write_constructed(s, tag::SEQUENCE, |a| {
                for attr in &q.attrs {
                    write_octet_string(a, attr.as_bytes());
                }
            });
        });
    });
    Ok(msg)
}

/// Parse the LDAPResult prefix (resultCode, matchedDN, diagnosticMessage)
/// that's at the start of every *Response.
fn parse_ldap_result(body: &[u8]) -> Result<(i64, String)> {
    let mut r = BerReader::new(body);
    let rc = r.read_enumerated_i64()?;
    let _matched_dn = r.read_octet_string()?;
    let diag = r.read_octet_string()?;
    let diag_s = String::from_utf8_lossy(diag).into_owned();
    Ok((rc, diag_s))
}

/// (attribute-name, list-of-values).
type LdapAttr = (String, Vec<Vec<u8>>);
/// One LDAP search-result entry: distinguished name and its attributes.
type SearchEntry = (String, Vec<LdapAttr>);

/// Parse one SearchResultEntry into its DN and attribute list.
fn parse_search_entry(body: &[u8]) -> Result<SearchEntry> {
    let mut r = BerReader::new(body);
    let dn_bytes = r.read_octet_string()?;
    let dn = String::from_utf8_lossy(dn_bytes).into_owned();
    // attributes SEQUENCE OF PartialAttribute
    let attrs_tlv = r.read_expect(tag::SEQUENCE)?;
    let mut ar = BerReader::new(attrs_tlv);
    let mut attributes = Vec::new();
    while !ar.is_empty() {
        // PartialAttribute ::= SEQUENCE { type AttributeDescription, vals SET OF AttributeValue }
        let pa = ar.read_expect(tag::SEQUENCE)?;
        let mut pr = BerReader::new(pa);
        let name_bytes = pr.read_octet_string()?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let vals_tlv = pr.read_expect(tag::SET)?;
        let mut vr = BerReader::new(vals_tlv);
        let mut vals = Vec::new();
        while !vr.is_empty() {
            let v = vr.read_octet_string()?;
            vals.push(v.to_vec());
        }
        attributes.push((name, vals));
    }
    Ok((dn, attributes))
}

/// Append an LDIF representation of a single entry to `out`.
fn write_ldif_entry(out: &mut Vec<u8>, dn: &str, attrs: &[(String, Vec<Vec<u8>>)]) {
    // The `dn` line's *value* is the DN string; `write_ldif_line` already
    // base64-encodes any value with CR/LF/control/high bytes, so a malicious DN
    // can't forge extra LDIF lines. (`dn` itself is a fixed, safe name.)
    write_ldif_line(out, "dn", dn.as_bytes());
    for (name, vals) in attrs {
        // A server-supplied attribute *name* is emitted verbatim and cannot be
        // base64-encoded in LDIF (only values can). If the name carries
        // CR/LF/`:`/control bytes it could forge new LDIF lines downstream
        // (e.g. `cn\nuserPassword`), so drop any attribute whose name isn't a
        // legal LDIF AttributeDescription rather than emit it unescaped.
        if !ldif_name_is_safe(name) {
            continue;
        }
        for v in vals {
            write_ldif_line(out, name, v);
        }
    }
    out.push(b'\n');
}

/// True if `name` is a safe LDIF attribute description: non-empty, ASCII, and
/// free of any character that could break the `name: value` framing (control
/// bytes, `:`, space, or the leading `<` URL form). RFC 2849 attribute
/// descriptions are restricted to letters/digits/`-`/`;`/`.` so this is
/// conservative but never rejects a legitimate name.
fn ldif_name_is_safe(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b';' | b'.'))
}

/// Emit a single `name: value` LDIF line. Uses base64 form (`name:: ...`) when
/// the value is not safe printable ASCII per RFC 2849. Callers must ensure
/// `name` is a safe LDIF attribute description (see [`ldif_name_is_safe`]) —
/// the value, by contrast, is always made safe here.
fn write_ldif_line(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    if ldif_is_safe(value) {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.push(b'\n');
    } else {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b":: ");
        out.extend_from_slice(base64_encode(value).as_bytes());
        out.push(b'\n');
    }
}

fn ldif_is_safe(value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    // RFC 2849: SAFE-INIT-CHAR is %x01-09 / %x0B-0C / %x0E-1F / %x21-39 / %x3B / %x3D-7F
    // SAFE-CHAR adds 0x20. We keep it conservative: ASCII printable except
    // leading space/colon/<, plus no NUL/CR/LF anywhere.
    let first = value[0];
    if first == b' ' || first == b':' || first == b'<' {
        return false;
    }
    for &b in value {
        if b == 0 || b == b'\r' || b == b'\n' || b >= 0x80 {
            return false;
        }
    }
    true
}

/// Tiny RFC 4648 base64 encoder. We don't pull in another dep.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[((b1 & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}

// =============================================================================
// Public entry point
// =============================================================================

/// Bind (anonymous unless userinfo is set), run the search described by
/// `url.path` + query, and return the search results serialized as LDIF.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &NetConfig) -> Result<Vec<u8>> {
    if url.scheme != "ldap" && url.scheme != "ldaps" {
        return Err(Error::UnsupportedScheme(url.scheme.clone()));
    }
    let q = parse_ldap_path(&url.path)?;
    // The DN and filter are percent-decoded from the URL and BER-encoded into
    // the search request; reject embedded control bytes (defense-in-depth — no
    // legitimate DN/filter contains them).
    reject_ctl(&q.dn, "search DN")?;
    reject_ctl(&q.filter, "search filter")?;

    // Split userinfo into user/password.
    let (bind_name, bind_pass) = match url.userinfo.as_deref() {
        None => (String::new(), String::new()),
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (percent_decode(u), percent_decode(p)),
            None => (percent_decode(ui), String::new()),
        },
    };
    // Same for the bind DN / password before they go into the BindRequest.
    reject_ctl(&bind_name, "bind DN")?;
    reject_ctl(&bind_pass, "bind password")?;

    // Connect through the configured transport.
    let sock = cfg.connect(&url.host, url.port)?;
    sock.set_read_timeout(Some(IO_TIMEOUT)).ok();
    sock.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut transport = if url.is_tls() {
        let tls = connect_over(sock, &url.host)?;
        Transport::Tls(Box::new(tls))
    } else {
        Transport::Plain(sock)
    };

    let mut message_id: i32 = 1;

    // BindRequest
    let bind_msg = build_bind_request(message_id, &bind_name, &bind_pass);
    transport.write_all(&bind_msg)?;
    transport.flush()?;
    message_id += 1;

    // BindResponse
    let resp = read_message(&mut transport)?;
    let (_resp_mid, op_tag, op_body) = split_message(&resp)?;
    if op_tag != tag::app(APP_BIND_RESPONSE, true) {
        return Err(Error::BadResponse(format!(
            "ldap: expected BindResponse, got tag {:#04x}",
            op_tag
        )));
    }
    let (rc, diag) = parse_ldap_result(op_body)?;
    if rc != 0 {
        return Err(Error::BadResponse(format!(
            "ldap bind failed: code {rc}: {diag}"
        )));
    }

    // SearchRequest
    let search_msg = build_search_request(message_id, &q)?;
    transport.write_all(&search_msg)?;
    transport.flush()?;
    let search_mid = message_id;
    message_id += 1;

    // Read entries until SearchResultDone.
    let mut out = Vec::new();
    loop {
        let body = read_message(&mut transport)?;
        let (mid, otag, obody) = split_message(&body)?;
        if mid != search_mid as i64 {
            // Ignore messages with a different ID (shouldn't really happen
            // for our serial single-search exchange, but be defensive).
            continue;
        }
        if otag == tag::app(APP_SEARCH_RESULT_ENTRY, true) {
            let (dn, attrs) = parse_search_entry(obody)?;
            write_ldif_entry(&mut out, &dn, &attrs);
            continue;
        }
        if otag == tag::app(APP_SEARCH_RESULT_REFERENCE, true) {
            // Skip referrals; just ignore them for this milestone.
            continue;
        }
        if otag == tag::app(APP_SEARCH_RESULT_DONE, true) {
            let (rc, diag) = parse_ldap_result(obody)?;
            if rc != 0 {
                return Err(Error::BadResponse(format!(
                    "ldap search failed: code {rc}: {diag}"
                )));
            }
            break;
        }
        return Err(Error::BadResponse(format!(
            "ldap: unexpected protocolOp tag {:#04x}",
            otag
        )));
    }

    // UnbindRequest (best-effort — server may close immediately).
    let unbind = build_unbind_request(message_id);
    let _ = transport.write_all(&unbind);
    let _ = transport.flush();

    Ok(out)
}

/// Pull `(messageID, op_tag, op_body)` out of a top-level LDAPMessage's body
/// bytes. The optional Controls field (context [0]) is ignored.
fn split_message(body: &[u8]) -> Result<(i64, u8, &[u8])> {
    let mut r = BerReader::new(body);
    let mid = r.read_integer_i64()?;
    let op = r.read_tlv()?;
    Ok((mid, op.tag, op.value))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_roundtrip_short() {
        let mut buf = Vec::new();
        encode_length(0, &mut buf);
        encode_length(1, &mut buf);
        encode_length(127, &mut buf);
        let mut r = BerReader::new(&buf);
        assert_eq!(r.read_length().unwrap(), 0);
        assert_eq!(r.read_length().unwrap(), 1);
        assert_eq!(r.read_length().unwrap(), 127);
        assert!(r.is_empty());
    }

    #[test]
    fn length_roundtrip_long() {
        for &len in &[128usize, 255, 256, 1024, 65535, 65536, 1 << 20] {
            let mut buf = Vec::new();
            encode_length(len, &mut buf);
            let mut r = BerReader::new(&buf);
            assert_eq!(r.read_length().unwrap(), len, "len={len}");
            assert!(r.is_empty(), "len={len}");
        }
    }

    #[test]
    fn integer_minimal_encoding() {
        // 127 fits in one byte.
        let mut buf = Vec::new();
        write_integer(&mut buf, 127);
        assert_eq!(buf, vec![0x02, 0x01, 0x7f]);
        // 128 needs a leading 0x00 to keep it positive in two's complement.
        let mut buf = Vec::new();
        write_integer(&mut buf, 128);
        assert_eq!(buf, vec![0x02, 0x02, 0x00, 0x80]);
        // -1 is 0xff with one byte.
        let mut buf = Vec::new();
        write_integer(&mut buf, -1);
        assert_eq!(buf, vec![0x02, 0x01, 0xff]);
        // Round-trip.
        for &v in &[0i64, 1, -1, 127, -128, 128, 255, 256, -32768, 32767] {
            let mut buf = Vec::new();
            write_integer(&mut buf, v);
            let mut r = BerReader::new(&buf);
            assert_eq!(r.read_integer_i64().unwrap(), v, "v={v}");
        }
    }

    #[test]
    fn parse_url_simple() {
        let q = parse_ldap_path("/dc=example,dc=com").unwrap();
        assert_eq!(q.dn, "dc=example,dc=com");
        assert!(q.attrs.is_empty());
        assert_eq!(q.scope, Scope::Base);
        assert_eq!(q.filter, "(objectClass=*)");
    }

    #[test]
    fn parse_url_full() {
        let q = parse_ldap_path("/dc=example,dc=com?cn,mail?sub?(cn=alice)").unwrap();
        assert_eq!(q.dn, "dc=example,dc=com");
        assert_eq!(q.attrs, vec!["cn", "mail"]);
        assert_eq!(q.scope, Scope::Subtree);
        assert_eq!(q.filter, "(cn=alice)");
    }

    #[test]
    fn parse_url_percent_decoded() {
        // RFC 4516 says `,` in a DN must be percent-encoded.
        let q = parse_ldap_path("/o=Foo%20Bar?cn?one?(cn=Alice%20Smith)").unwrap();
        assert_eq!(q.dn, "o=Foo Bar");
        assert_eq!(q.scope, Scope::OneLevel);
        assert_eq!(q.filter, "(cn=Alice Smith)");
    }

    #[test]
    fn parse_url_unknown_scope_errors() {
        assert!(parse_ldap_path("/dc=x??weird?(cn=*)").is_err());
    }

    #[test]
    fn parse_filter_equality() {
        let f = parse_filter("(cn=Alice)").unwrap();
        assert_eq!(
            f,
            Filter::EqualityMatch {
                attr: "cn".into(),
                value: "Alice".into()
            }
        );
    }

    #[test]
    fn parse_filter_and() {
        let f = parse_filter("(&(cn=*)(o=ACME))").unwrap();
        match f {
            Filter::And(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Filter::Present("cn".into()));
                assert_eq!(
                    items[1],
                    Filter::EqualityMatch {
                        attr: "o".into(),
                        value: "ACME".into()
                    }
                );
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn parse_filter_or_not() {
        let f = parse_filter("(|(cn=a)(!(cn=b)))").unwrap();
        match f {
            Filter::Or(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], Filter::EqualityMatch { .. }));
                assert!(matches!(items[1], Filter::Not(_)));
            }
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn parse_filter_rejects_excessive_nesting() {
        // Build a filter nested far deeper than MAX_FILTER_DEPTH. This must
        // return an Err rather than overflowing the native stack.
        let depth = MAX_FILTER_DEPTH + 1000;
        let mut s = String::with_capacity(depth * 2 + 8);
        for _ in 0..depth {
            s.push_str("(!");
        }
        s.push_str("(cn=a)");
        for _ in 0..depth {
            s.push(')');
        }
        let err = parse_filter(&s).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));

        // A filter nested just under the limit still parses fine.
        let ok_depth = MAX_FILTER_DEPTH - 1;
        let mut ok = String::new();
        for _ in 0..ok_depth {
            ok.push_str("(!");
        }
        ok.push_str("(cn=a)");
        for _ in 0..ok_depth {
            ok.push(')');
        }
        assert!(parse_filter(&ok).is_ok());

        // And an ordinary shallow filter is unaffected.
        assert!(parse_filter("(|(cn=a)(!(cn=b)))").is_ok());
    }

    #[test]
    fn parse_filter_substring_initial_only() {
        let f = parse_filter("(cn=foo*)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attr: "cn".into(),
                initial: Some("foo".into()),
                any: vec![],
                final_: None,
            }
        );
    }

    #[test]
    fn parse_filter_substring_final_only() {
        let f = parse_filter("(cn=*bar)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attr: "cn".into(),
                initial: None,
                any: vec![],
                final_: Some("bar".into()),
            }
        );
    }

    #[test]
    fn parse_filter_substring_initial_any_final() {
        let f = parse_filter("(cn=a*b*c)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attr: "cn".into(),
                initial: Some("a".into()),
                any: vec!["b".into()],
                final_: Some("c".into()),
            }
        );
    }

    #[test]
    fn parse_filter_substring_any_only() {
        let f = parse_filter("(cn=*x*)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attr: "cn".into(),
                initial: None,
                any: vec!["x".into()],
                final_: None,
            }
        );
    }

    #[test]
    fn parse_filter_substring_multiple_any() {
        // Consecutive `**` and leading/trailing `*` contribute no element.
        let f = parse_filter("(cn=**a**b**)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attr: "cn".into(),
                initial: None,
                any: vec!["a".into(), "b".into()],
                final_: None,
            }
        );
    }

    #[test]
    fn parse_filter_present_not_substring() {
        // A bare `*` is the presence filter, not a substring filter.
        let f = parse_filter("(cn=*)").unwrap();
        assert_eq!(f, Filter::Present("cn".into()));
    }

    #[test]
    fn parse_filter_no_star_stays_equality() {
        let f = parse_filter("(cn=foo)").unwrap();
        assert_eq!(
            f,
            Filter::EqualityMatch {
                attr: "cn".into(),
                value: "foo".into(),
            }
        );
    }

    #[test]
    fn parse_filter_substring_rejects_control_bytes() {
        // A control byte inside a substring segment is rejected by reject_ctl.
        assert!(parse_filter("(cn=foo\n*bar)").is_err());
        assert!(parse_filter("(cn=foo*ba\0r)").is_err());
    }

    /// Encode a standalone filter and return the BER bytes for tag inspection.
    fn encode_one(f: &Filter) -> Vec<u8> {
        let mut out = Vec::new();
        encode_filter(&mut out, f);
        out
    }

    #[test]
    fn encode_substring_initial_only_tags() {
        // (cn=foo*) -> [4] constructed (0xA4) { type, SEQUENCE { initial [0] } }
        let f = parse_filter("(cn=foo*)").unwrap();
        let buf = encode_one(&f);
        assert_eq!(buf[0], 0xA4, "substring filter tag must be [4] constructed");
        assert_eq!(buf[0], tag::ctx(4, true));
        let mut r = BerReader::new(&buf);
        let sub = r.read_expect(tag::ctx(4, true)).unwrap();
        let mut sr = BerReader::new(sub);
        assert_eq!(sr.read_octet_string().unwrap(), b"cn");
        let seq = sr.read_expect(tag::SEQUENCE).unwrap();
        let mut subs = BerReader::new(seq);
        let init = subs.read_tlv().unwrap();
        assert_eq!(init.tag, 0x80, "initial must be [0] primitive");
        assert_eq!(init.tag, tag::ctx(0, false));
        assert_eq!(init.value, b"foo");
        assert!(subs.is_empty());
    }

    #[test]
    fn encode_substring_final_only_tags() {
        // (cn=*bar) -> SEQUENCE { final [2] }
        let f = parse_filter("(cn=*bar)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let sub = r.read_expect(tag::ctx(4, true)).unwrap();
        let mut sr = BerReader::new(sub);
        assert_eq!(sr.read_octet_string().unwrap(), b"cn");
        let seq = sr.read_expect(tag::SEQUENCE).unwrap();
        let mut subs = BerReader::new(seq);
        let fin = subs.read_tlv().unwrap();
        assert_eq!(fin.tag, 0x82, "final must be [2] primitive");
        assert_eq!(fin.tag, tag::ctx(2, false));
        assert_eq!(fin.value, b"bar");
        assert!(subs.is_empty());
    }

    #[test]
    fn encode_substring_initial_any_final_tags() {
        // (cn=a*b*c) -> initial [0]=0x80, any [1]=0x81, final [2]=0x82 in order
        let f = parse_filter("(cn=a*b*c)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let sub = r.read_expect(tag::ctx(4, true)).unwrap();
        let mut sr = BerReader::new(sub);
        assert_eq!(sr.read_octet_string().unwrap(), b"cn");
        let seq = sr.read_expect(tag::SEQUENCE).unwrap();
        let mut subs = BerReader::new(seq);
        let init = subs.read_tlv().unwrap();
        assert_eq!(init.tag, 0x80);
        assert_eq!(init.value, b"a");
        let mid = subs.read_tlv().unwrap();
        assert_eq!(mid.tag, 0x81, "any must be [1] primitive");
        assert_eq!(mid.value, b"b");
        let fin = subs.read_tlv().unwrap();
        assert_eq!(fin.tag, 0x82);
        assert_eq!(fin.value, b"c");
        assert!(subs.is_empty());
    }

    #[test]
    fn encode_substring_any_only_tag() {
        // (cn=*x*) -> SEQUENCE { any [1] }
        let f = parse_filter("(cn=*x*)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let sub = r.read_expect(tag::ctx(4, true)).unwrap();
        let mut sr = BerReader::new(sub);
        assert_eq!(sr.read_octet_string().unwrap(), b"cn");
        let seq = sr.read_expect(tag::SEQUENCE).unwrap();
        let mut subs = BerReader::new(seq);
        let any = subs.read_tlv().unwrap();
        assert_eq!(any.tag, 0x81);
        assert_eq!(any.value, b"x");
        assert!(subs.is_empty());
    }

    #[test]
    fn encode_present_tag() {
        // (cn=*) -> present [7] primitive = 0x87
        let f = parse_filter("(cn=*)").unwrap();
        let buf = encode_one(&f);
        assert_eq!(buf[0], 0x87, "present filter tag must be [7] primitive");
        assert_eq!(buf[0], tag::ctx(7, false));
        let mut r = BerReader::new(&buf);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value, b"cn");
    }

    #[test]
    fn encode_equality_tag() {
        // (cn=foo) -> equalityMatch [3] constructed = 0xA3
        let f = parse_filter("(cn=foo)").unwrap();
        let buf = encode_one(&f);
        assert_eq!(buf[0], 0xA3);
        assert_eq!(buf[0], tag::ctx(3, true));
    }

    #[test]
    fn parse_filter_extensible_type_only() {
        let f = parse_filter("(cn:=foo)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: None,
                attr_type: Some("cn".into()),
                match_value: "foo".into(),
                dn_attributes: false,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_dn() {
        let f = parse_filter("(cn:dn:=foo)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: None,
                attr_type: Some("cn".into()),
                match_value: "foo".into(),
                dn_attributes: true,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_rule() {
        let f = parse_filter("(cn:1.2.3.4:=foo)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: Some("1.2.3.4".into()),
                attr_type: Some("cn".into()),
                match_value: "foo".into(),
                dn_attributes: false,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_dn_and_rule() {
        let f = parse_filter("(cn:dn:caseIgnoreMatch:=foo)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: Some("caseIgnoreMatch".into()),
                attr_type: Some("cn".into()),
                match_value: "foo".into(),
                dn_attributes: true,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_rule_no_type() {
        let f = parse_filter("(:caseExactMatch:=bar)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: Some("caseExactMatch".into()),
                attr_type: None,
                match_value: "bar".into(),
                dn_attributes: false,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_dn_rule_no_type() {
        let f = parse_filter("(:dn:caseExactMatch:=bar)").unwrap();
        assert_eq!(
            f,
            Filter::ExtensibleMatch {
                matching_rule: Some("caseExactMatch".into()),
                attr_type: None,
                match_value: "bar".into(),
                dn_attributes: true,
            }
        );
    }

    #[test]
    fn parse_filter_extensible_rejects_control_bytes() {
        // A control byte in the value is rejected by reject_ctl.
        assert!(parse_filter("(cn:=foo\nbar)").is_err());
        assert!(parse_filter("(cn:=foo\0bar)").is_err());
    }

    #[test]
    fn parse_filter_plain_equality_not_extensible() {
        // A `=` without a preceding `:` stays equality, never extensible.
        let f = parse_filter("(cn=foo)").unwrap();
        assert_eq!(
            f,
            Filter::EqualityMatch {
                attr: "cn".into(),
                value: "foo".into(),
            }
        );
    }

    #[test]
    fn encode_extensible_type_only_tags() {
        // (cn:=foo) -> [9] constructed (0xA9) { type [2], matchValue [3] }
        // No matchingRule [1], no dnAttributes [4].
        let f = parse_filter("(cn:=foo)").unwrap();
        let buf = encode_one(&f);
        assert_eq!(buf[0], 0xA9, "extensible match tag must be [9] constructed");
        assert_eq!(buf[0], tag::ctx(9, true));
        let mut r = BerReader::new(&buf);
        let body = r.read_expect(tag::ctx(9, true)).unwrap();
        let mut mr = BerReader::new(body);
        // First child is type [2] (no matchingRule [1]).
        let t = mr.read_tlv().unwrap();
        assert_eq!(t.tag, 0x82, "type must be [2] primitive");
        assert_eq!(t.tag, tag::ctx(2, false));
        assert_eq!(t.value, b"cn");
        let v = mr.read_tlv().unwrap();
        assert_eq!(v.tag, 0x83, "matchValue must be [3] primitive");
        assert_eq!(v.tag, tag::ctx(3, false));
        assert_eq!(v.value, b"foo");
        assert!(mr.is_empty(), "no matchingRule [1] and no dnAttributes [4]");
        // Belt-and-braces: the encoded bytes carry neither 0x81 nor 0x84.
        assert!(!body.contains(&0x84), "dnAttributes [4] must be absent");
    }

    #[test]
    fn encode_extensible_dn_attributes() {
        // (cn:dn:=foo) -> dnAttributes [4] BOOLEAN TRUE = 0x84 0x01 0xFF.
        let f = parse_filter("(cn:dn:=foo)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let body = r.read_expect(tag::ctx(9, true)).unwrap();
        let mut mr = BerReader::new(body);
        let t = mr.read_tlv().unwrap();
        assert_eq!(t.tag, tag::ctx(2, false));
        assert_eq!(t.value, b"cn");
        let v = mr.read_tlv().unwrap();
        assert_eq!(v.tag, tag::ctx(3, false));
        assert_eq!(v.value, b"foo");
        let dn = mr.read_tlv().unwrap();
        assert_eq!(dn.tag, 0x84, "dnAttributes must be [4] primitive");
        assert_eq!(dn.tag, tag::ctx(4, false));
        assert_eq!(dn.value, &[0xff], "dnAttributes TRUE is a single 0xFF byte");
        assert!(mr.is_empty());
        // The raw bytes 84 01 FF appear in order.
        assert!(
            body.windows(3).any(|w| w == [0x84, 0x01, 0xff]),
            "expected 0x84 0x01 0xFF"
        );
    }

    #[test]
    fn encode_extensible_matching_rule_ordering() {
        // (cn:1.2.3.4:=foo) -> matchingRule [1] before type [2] before value.
        let f = parse_filter("(cn:1.2.3.4:=foo)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let body = r.read_expect(tag::ctx(9, true)).unwrap();
        let mut mr = BerReader::new(body);
        let rule = mr.read_tlv().unwrap();
        assert_eq!(rule.tag, 0x81, "matchingRule must be [1] primitive");
        assert_eq!(rule.tag, tag::ctx(1, false));
        assert_eq!(rule.value, b"1.2.3.4");
        let t = mr.read_tlv().unwrap();
        assert_eq!(t.tag, tag::ctx(2, false));
        assert_eq!(t.value, b"cn");
        let v = mr.read_tlv().unwrap();
        assert_eq!(v.tag, tag::ctx(3, false));
        assert_eq!(v.value, b"foo");
        assert!(mr.is_empty());
    }

    #[test]
    fn encode_extensible_dn_and_rule() {
        // (cn:dn:caseIgnoreMatch:=foo) -> rule [1], type [2], value [3], dn [4].
        let f = parse_filter("(cn:dn:caseIgnoreMatch:=foo)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let body = r.read_expect(tag::ctx(9, true)).unwrap();
        let mut mr = BerReader::new(body);
        let rule = mr.read_tlv().unwrap();
        assert_eq!(rule.tag, tag::ctx(1, false));
        assert_eq!(rule.value, b"caseIgnoreMatch");
        let t = mr.read_tlv().unwrap();
        assert_eq!(t.tag, tag::ctx(2, false));
        assert_eq!(t.value, b"cn");
        let v = mr.read_tlv().unwrap();
        assert_eq!(v.tag, tag::ctx(3, false));
        assert_eq!(v.value, b"foo");
        let dn = mr.read_tlv().unwrap();
        assert_eq!(dn.tag, tag::ctx(4, false));
        assert_eq!(dn.value, &[0xff]);
        assert!(mr.is_empty());
    }

    #[test]
    fn encode_extensible_rule_no_type_tags() {
        // (:caseExactMatch:=bar) -> matchingRule [1] present, NO type [2].
        let f = parse_filter("(:caseExactMatch:=bar)").unwrap();
        let buf = encode_one(&f);
        let mut r = BerReader::new(&buf);
        let body = r.read_expect(tag::ctx(9, true)).unwrap();
        let mut mr = BerReader::new(body);
        let rule = mr.read_tlv().unwrap();
        assert_eq!(rule.tag, 0x81, "matchingRule [1] must be present");
        assert_eq!(rule.value, b"caseExactMatch");
        let v = mr.read_tlv().unwrap();
        assert_eq!(v.tag, 0x83, "next child is matchValue [3], not type [2]");
        assert_eq!(v.value, b"bar");
        assert!(mr.is_empty());
        // No type [2] tag anywhere in the assertion body.
        assert!(!body.contains(&0x82), "type [2] must be absent");
    }

    #[test]
    fn build_bind_request_shape() {
        // Anonymous bind v3 — name "" password "".
        let msg = build_bind_request(1, "", "");
        // Top-level SEQUENCE.
        assert_eq!(msg[0], tag::SEQUENCE);
        // Decode and check the inner structure.
        let mut r = BerReader::new(&msg);
        let body = r.read_expect(tag::SEQUENCE).unwrap();
        let (mid, op_tag, op_body) = split_message(body).unwrap();
        assert_eq!(mid, 1);
        assert_eq!(op_tag, tag::app(APP_BIND_REQUEST, true));
        let mut br = BerReader::new(op_body);
        assert_eq!(br.read_integer_i64().unwrap(), 3);
        assert_eq!(br.read_octet_string().unwrap(), b"");
        // Authentication choice tag = context [0] primitive
        let auth = br.read_tlv().unwrap();
        assert_eq!(auth.tag, tag::ctx(0, false));
        assert_eq!(auth.value, b"");
    }

    #[test]
    fn ldif_escaping() {
        // A safe string is rendered verbatim.
        let mut out = Vec::new();
        write_ldif_line(&mut out, "cn", b"Alice");
        assert_eq!(out, b"cn: Alice\n");
        // A leading space triggers base64.
        let mut out = Vec::new();
        write_ldif_line(&mut out, "cn", b" leading");
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("cn:: "), "got {s:?}");
        // High-bit triggers base64.
        let mut out = Vec::new();
        write_ldif_line(&mut out, "cn", &[0xc3, 0xa9]);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("cn:: "), "got {s:?}");
    }

    #[test]
    fn ldif_name_safety() {
        assert!(ldif_name_is_safe("cn"));
        assert!(ldif_name_is_safe("userPassword"));
        assert!(ldif_name_is_safe("attr-1.2;binary"));
        // Empty, or anything with framing-breaking bytes, is unsafe.
        assert!(!ldif_name_is_safe(""));
        assert!(!ldif_name_is_safe("cn\nuserPassword"));
        assert!(!ldif_name_is_safe("cn:evil"));
        assert!(!ldif_name_is_safe("cn evil"));
        assert!(!ldif_name_is_safe("cn\0"));
    }

    #[test]
    fn write_ldif_entry_drops_unsafe_attribute_names() {
        // A malicious server returns an attribute whose NAME embeds a newline
        // to forge an extra LDIF line. The forged name must be dropped, while
        // a sibling legitimate attribute is still emitted.
        let attrs = vec![
            ("cn\nuserPassword".to_string(), vec![b"secret".to_vec()]),
            ("mail".to_string(), vec![b"a@b".to_vec()]),
        ];
        let mut out = Vec::new();
        write_ldif_entry(&mut out, "cn=alice,dc=ex", &attrs);
        let s = String::from_utf8(out).unwrap();
        // The forged name never appears as a line.
        assert!(!s.contains("userPassword"));
        assert!(!s.contains("secret"));
        // The good attribute survives, and the DN line is present.
        assert!(s.contains("dn: cn=alice,dc=ex"));
        assert!(s.contains("mail: a@b"));
    }

    #[test]
    fn write_ldif_entry_base64s_dn_with_newline() {
        // A DN carrying a newline can't forge lines: its value is base64-encoded.
        let mut out = Vec::new();
        write_ldif_entry(&mut out, "cn=alice\ncn=evil", &[]);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("dn:: "), "got {s:?}");
        assert!(!s.contains("cn=evil\n"));
    }

    #[test]
    fn reject_ctl_flags_control_bytes() {
        assert!(reject_ctl("dc=example,dc=com", "search DN").is_ok());
        assert!(reject_ctl("(cn=Alice Smith)", "search filter").is_ok());
        assert!(reject_ctl("cn=a\nob", "search DN").is_err());
        assert!(reject_ctl("cn=a\rb", "bind DN").is_err());
        assert!(reject_ctl("cn=a\0b", "bind password").is_err());
        assert!(reject_ctl("cn=a\x7f", "search DN").is_err());
    }

    #[test]
    fn read_message_rejects_oversized_length() {
        // A SEQUENCE header declaring a body larger than MAX_MESSAGE_BYTES must
        // be rejected before we `vec![0u8; len]`. No body is supplied — the
        // error has to fire on the length check alone.
        let big = MAX_MESSAGE_BYTES + 1;
        let mut wire = vec![tag::SEQUENCE];
        encode_length(big, &mut wire);
        let mut io = std::io::Cursor::new(wire);
        let err = read_message_from(&mut io).expect_err("oversized length must error");
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn read_message_accepts_within_cap() {
        // A small, well-formed message reads back its body bytes intact.
        let mut wire = vec![tag::SEQUENCE];
        encode_length(3, &mut wire);
        wire.extend_from_slice(&[0x01, 0x02, 0x03]);
        let mut io = std::io::Cursor::new(wire);
        let body = read_message_from(&mut io).unwrap();
        assert_eq!(body, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn build_search_request_decodes() {
        let q = ParsedUrlQuery {
            dn: "dc=example,dc=com".into(),
            attrs: vec!["cn".into(), "mail".into()],
            scope: Scope::Subtree,
            filter: "(cn=Alice)".into(),
        };
        let msg = build_search_request(7, &q).unwrap();
        let mut r = BerReader::new(&msg);
        let body = r.read_expect(tag::SEQUENCE).unwrap();
        let (mid, op_tag, op_body) = split_message(body).unwrap();
        assert_eq!(mid, 7);
        assert_eq!(op_tag, tag::app(APP_SEARCH_REQUEST, true));
        let mut sr = BerReader::new(op_body);
        assert_eq!(sr.read_octet_string().unwrap(), b"dc=example,dc=com");
        assert_eq!(sr.read_enumerated_i64().unwrap(), 2); // sub
        assert_eq!(sr.read_enumerated_i64().unwrap(), 0); // never deref
        assert_eq!(sr.read_integer_i64().unwrap(), 100); // sizeLimit
        assert_eq!(sr.read_integer_i64().unwrap(), 30); // timeLimit
                                                        // typesOnly boolean
        let bool_tlv = sr.read_tlv().unwrap();
        assert_eq!(bool_tlv.tag, tag::BOOLEAN);
        assert_eq!(bool_tlv.value, &[0x00]);
        // Filter: equalityMatch is context [3] constructed.
        let filt = sr.read_tlv().unwrap();
        assert_eq!(filt.tag, tag::ctx(3, true));
        // Attributes SEQUENCE OF
        let attrs_seq = sr.read_expect(tag::SEQUENCE).unwrap();
        let mut ar = BerReader::new(attrs_seq);
        assert_eq!(ar.read_octet_string().unwrap(), b"cn");
        assert_eq!(ar.read_octet_string().unwrap(), b"mail");
        assert!(ar.is_empty());
    }

    #[test]
    fn parse_search_entry_roundtrip() {
        // Build a SearchResultEntry body by hand and parse it back.
        let mut body = Vec::new();
        write_octet_string(&mut body, b"cn=alice,dc=ex,dc=com");
        write_constructed(&mut body, tag::SEQUENCE, |attrs| {
            // cn: alice
            write_constructed(attrs, tag::SEQUENCE, |a| {
                write_octet_string(a, b"cn");
                write_constructed(a, tag::SET, |vals| {
                    write_octet_string(vals, b"alice");
                });
            });
            // mail: a@b, c@d
            write_constructed(attrs, tag::SEQUENCE, |a| {
                write_octet_string(a, b"mail");
                write_constructed(a, tag::SET, |vals| {
                    write_octet_string(vals, b"a@b");
                    write_octet_string(vals, b"c@d");
                });
            });
        });

        let (dn, attrs) = parse_search_entry(&body).unwrap();
        assert_eq!(dn, "cn=alice,dc=ex,dc=com");
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, "cn");
        assert_eq!(attrs[0].1, vec![b"alice".to_vec()]);
        assert_eq!(attrs[1].0, "mail");
        assert_eq!(attrs[1].1, vec![b"a@b".to_vec(), b"c@d".to_vec()]);
    }
}
