//! DICT protocol (RFC 2229).
//!
//! Dict URLs look like `dict://server/d:word[:database]` (define),
//! `dict://server/m:word[:database[:strategy]]` (match), or just
//! `dict://server/word` (define against any database).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::Url;

/// Default I/O timeout per RFC 2229; servers can be slow to respond on first
/// connect, so we err on the generous side.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Parsed form of the path component of a `dict://` URL.
///
/// The four tuple elements are, in order: the DICT verb to send (`DEFINE`,
/// `MATCH`, or `SHOW`), the word being looked up (empty for `SHOW`), the
/// database to query (`*` means "any"), and a strategy name (only used for
/// `MATCH`, defaults to `.`).
#[derive(Debug, PartialEq, Eq)]
struct DictRequest {
    verb: Verb,
    word: String,
    database: String,
    strategy: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Verb {
    Define,
    Match,
    ShowDatabases,
}

impl DictRequest {
    /// Encode the request as the on-the-wire command (without trailing CRLF).
    fn to_command(&self) -> String {
        match self.verb {
            Verb::Define => format!("DEFINE {} {}", self.database, self.word),
            Verb::Match => format!("MATCH {} {} {}", self.database, self.strategy, self.word),
            Verb::ShowDatabases => "SHOW DATABASES".to_string(),
        }
    }
}

/// Parse the path of a `dict://` URL into a structured request.
///
/// Accepts the forms documented in RFC 2229 §5:
///   * `/`           → `SHOW DATABASES`
///   * `/word`       → `DEFINE * word`
///   * `/d:word`     → `DEFINE * word`
///   * `/d:word:db`  → `DEFINE db word`
///   * `/m:word[:db[:strategy]]` → `MATCH db strategy word`
fn parse_path(path: &str) -> Result<DictRequest> {
    // Trim a single leading '/'; the rest is the dict-specific selector.
    let raw = path.strip_prefix('/').unwrap_or(path);

    if raw.is_empty() {
        return Ok(DictRequest {
            verb: Verb::ShowDatabases,
            word: String::new(),
            database: "*".into(),
            strategy: ".".into(),
        });
    }

    // RFC 2229 uses a leading `d:` or `m:` to mark the verb. Anything else is
    // treated as a bare word (DEFINE * word).
    let (verb, rest) = if let Some(r) = raw.strip_prefix("d:") {
        (Verb::Define, r)
    } else if let Some(r) = raw.strip_prefix("m:") {
        (Verb::Match, r)
    } else {
        (Verb::Define, raw)
    };

    let mut parts = rest.split(':');
    let word = parts
        .next()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidUrl(format!("dict: empty word in path '{path}'")))?;
    let database = parts
        .next()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "*".into());
    let strategy = parts
        .next()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ".".into());

    // The word/database/strategy are interpolated raw into CRLF-terminated
    // DICT command lines (see `DictRequest::to_command` / `fetch`). A bare
    // CR, LF, NUL, or other control byte in the URL would let an attacker
    // inject additional DICT commands onto the wire, so reject them here.
    reject_control_bytes(&word, "word", path)?;
    reject_control_bytes(&database, "database", path)?;
    reject_control_bytes(&strategy, "strategy", path)?;

    Ok(DictRequest {
        verb,
        word,
        database,
        strategy,
    })
}

/// Reject any ASCII control byte (including CR, LF, and NUL) in a
/// URL-derived DICT field, returning [`Error::InvalidUrl`]. This prevents
/// CRLF command injection on the DICT control connection.
fn reject_control_bytes(value: &str, field: &str, path: &str) -> Result<()> {
    if value.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::InvalidUrl(format!(
            "dict: control byte in {field} of path '{path}'"
        )));
    }
    Ok(())
}

/// Read the three-digit status code at the start of a DICT response line.
/// Returns the code as an integer and the trailing message text.
fn parse_status(line: &str) -> Result<(u16, &str)> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.len() < 3 {
        return Err(Error::BadResponse(format!(
            "dict: short status line '{trimmed}'"
        )));
    }
    let (code_str, rest) = trimmed.split_at(3);
    let code: u16 = code_str
        .parse()
        .map_err(|_| Error::BadResponse(format!("dict: non-numeric status '{trimmed}'")))?;
    // Skip a single space separator if present.
    let msg = rest.strip_prefix(' ').unwrap_or(rest);
    Ok((code, msg))
}

/// True for DICT response codes in the 4xx (transient) or 5xx (permanent)
/// failure ranges.
fn is_error_code(code: u16) -> bool {
    (400..600).contains(&code)
}

/// Read one CRLF-terminated line from `reader`. Translates an EOF before any
/// data is read into [`Error::UnexpectedEof`].
fn read_line<R: BufRead>(reader: &mut R) -> Result<String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    Ok(line)
}

/// Read a multi-line textual response body terminated by a line containing
/// only `.\r\n` (a single dot). Lines that begin with a dot are unescaped by
/// removing the leading dot, per RFC 2229 §2.2.
fn read_text_block<R: BufRead>(reader: &mut R, out: &mut Vec<u8>) -> Result<()> {
    loop {
        let line = read_line(reader)?;
        let body = line.trim_end_matches(['\r', '\n']);
        if body == "." {
            return Ok(());
        }
        // Dot-stuffing: a line beginning with ".." is really "."-prefixed text.
        let unescaped = body.strip_prefix('.').unwrap_or(body);
        // Skip the leading-dot only when it was followed by another character
        // (so that text lines starting with a literal dot survive); a bare "."
        // was handled above.
        let to_write = if body.starts_with('.') {
            unescaped
        } else {
            body
        };
        out.extend_from_slice(to_write.as_bytes());
        out.extend_from_slice(b"\n");
    }
}

/// Connect, issue the DICT request encoded in `url.path`, and return the
/// human-readable text response.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let request = parse_path(&url.path)?;

    let stream = TcpStream::connect((url.host.as_str(), url.port))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // 1. Banner: must start with 220 OK.
    let banner = read_line(&mut reader)?;
    let (code, msg) = parse_status(&banner)?;
    if code != 220 {
        return Err(Error::BadResponse(format!("dict: {code} {msg}")));
    }

    // 2. Polite hello. The server may reply with 250 OK; ignore failures
    // (some servers don't implement CLIENT but still let us proceed).
    let hello = format!("CLIENT rsurl/{}\r\n", env!("CARGO_PKG_VERSION"));
    writer.write_all(hello.as_bytes())?;
    let _ = read_line(&mut reader)?; // discard whatever CLIENT returns

    // 3. Send the actual command and parse its response.
    let command = request.to_command();
    writer.write_all(command.as_bytes())?;
    writer.write_all(b"\r\n")?;

    let mut output: Vec<u8> = Vec::new();
    let result = read_response(&mut reader, &request.verb, &mut output);

    // 4. Always try to QUIT cleanly even if the body errored, so the server
    // isn't left hanging. Ignore I/O errors during shutdown.
    let _ = writer.write_all(b"QUIT\r\n");
    let _ = read_line(&mut reader);
    let _ = writer.shutdown(std::net::Shutdown::Both);

    result?;
    Ok(output)
}

/// Read the response for a single command (the request `verb` determines how
/// many text blocks to expect).
fn read_response<R: BufRead>(reader: &mut R, verb: &Verb, out: &mut Vec<u8>) -> Result<()> {
    let mut status = read_line(reader)?;
    loop {
        let (code, msg) = parse_status(&status)?;
        if is_error_code(code) {
            return Err(Error::BadResponse(format!("dict: {code} {msg}")));
        }

        match (verb, code) {
            // SHOW DATABASES: 110 <n> databases present, then a text block,
            // then 250 ok.
            (Verb::ShowDatabases, 110) => {
                read_text_block(reader, out)?;
            }
            // MATCH: 152 <n> matches, then text block, then 250 ok. 552 is
            // "no matches" — surface that as an error.
            (Verb::Match, 152) => {
                read_text_block(reader, out)?;
            }
            // DEFINE: 150 <n> definitions retrieved, followed by one or more
            // 151 blocks (each its own text block) and a final 250.
            (Verb::Define, 150) => {
                // Nothing to do; the definitions follow as their own 151 frames.
            }
            (Verb::Define, 151) => {
                // The 151 line itself is metadata (word, db, db-description);
                // include it as a header for the human reader.
                out.extend_from_slice(msg.as_bytes());
                out.extend_from_slice(b"\n");
                read_text_block(reader, out)?;
            }
            // Final success status — we're done with this command.
            (_, 250) => return Ok(()),
            // 230 = ok (auth), 130 = informational — ignore and keep reading.
            (_, 130) | (_, 230) => {}
            // Anything else with a 2xx/1xx code we don't know about: stop if
            // it's terminal (2xx) or keep reading if informational (1xx).
            (_, c) if (200..300).contains(&c) => return Ok(()),
            _ => {
                // Unexpected but not an error code; treat the message as the
                // body and return so the caller still gets something.
                out.extend_from_slice(msg.as_bytes());
                out.extend_from_slice(b"\n");
                return Ok(());
            }
        }

        status = read_line(reader)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_empty_means_show_databases() {
        let r = parse_path("/").unwrap();
        assert_eq!(r.verb, Verb::ShowDatabases);
        assert_eq!(r.to_command(), "SHOW DATABASES");
    }

    #[test]
    fn path_bare_word_defines_against_any_db() {
        let r = parse_path("/rust").unwrap();
        assert_eq!(r.verb, Verb::Define);
        assert_eq!(r.word, "rust");
        assert_eq!(r.database, "*");
        assert_eq!(r.to_command(), "DEFINE * rust");
    }

    #[test]
    fn path_define_with_db() {
        let r = parse_path("/d:rust:foldoc").unwrap();
        assert_eq!(r.verb, Verb::Define);
        assert_eq!(r.word, "rust");
        assert_eq!(r.database, "foldoc");
        assert_eq!(r.to_command(), "DEFINE foldoc rust");
    }

    #[test]
    fn path_define_with_explicit_verb_no_db() {
        let r = parse_path("/d:rust").unwrap();
        assert_eq!(r.verb, Verb::Define);
        assert_eq!(r.word, "rust");
        assert_eq!(r.database, "*");
        assert_eq!(r.to_command(), "DEFINE * rust");
    }

    #[test]
    fn path_match_default_db_and_strategy() {
        let r = parse_path("/m:rust").unwrap();
        assert_eq!(r.verb, Verb::Match);
        assert_eq!(r.word, "rust");
        assert_eq!(r.database, "*");
        assert_eq!(r.strategy, ".");
        assert_eq!(r.to_command(), "MATCH * . rust");
    }

    #[test]
    fn path_match_with_db_and_strategy() {
        let r = parse_path("/m:rust:foldoc:prefix").unwrap();
        assert_eq!(r.verb, Verb::Match);
        assert_eq!(r.word, "rust");
        assert_eq!(r.database, "foldoc");
        assert_eq!(r.strategy, "prefix");
        assert_eq!(r.to_command(), "MATCH foldoc prefix rust");
    }

    #[test]
    fn path_match_with_only_strategy_uses_default_db() {
        // Empty middle slot keeps the default database.
        let r = parse_path("/m:rust::prefix").unwrap();
        assert_eq!(r.database, "*");
        assert_eq!(r.strategy, "prefix");
    }

    #[test]
    fn path_with_only_verb_prefix_is_rejected() {
        assert!(parse_path("/d:").is_err());
        assert!(parse_path("/m:").is_err());
    }

    #[test]
    fn path_rejects_crlf_injection_in_word() {
        // A raw CR/LF in the word would inject an extra DICT command.
        let err = parse_path("/d:rust\r\nQUIT").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
        assert!(parse_path("/rust\nDEFINE * evil").is_err());
        assert!(parse_path("/d:rust\rQUIT").is_err());
    }

    #[test]
    fn path_rejects_control_bytes_in_database_and_strategy() {
        assert!(parse_path("/d:rust:fol\r\ndoc").is_err());
        assert!(parse_path("/m:rust:foldoc:pre\nfix").is_err());
        // NUL byte is also a control byte.
        assert!(parse_path("/d:rust:fol\0doc").is_err());
    }

    #[test]
    fn path_accepts_clean_input() {
        // Sanity: ordinary words with no control bytes still parse.
        assert!(parse_path("/d:rust:foldoc").is_ok());
        assert!(parse_path("/m:rust:foldoc:prefix").is_ok());
    }

    #[test]
    fn parse_status_extracts_code_and_message() {
        let (code, msg) = parse_status("220 dict.org dictd 1.12.1\r\n").unwrap();
        assert_eq!(code, 220);
        assert!(msg.starts_with("dict.org"));
    }

    #[test]
    fn parse_status_handles_code_only() {
        let (code, msg) = parse_status("250\r\n").unwrap();
        assert_eq!(code, 250);
        assert_eq!(msg, "");
    }

    #[test]
    fn parse_status_rejects_garbage() {
        assert!(parse_status("OK\r\n").is_err());
        assert!(parse_status("ab").is_err());
    }

    #[test]
    fn is_error_code_classifies_correctly() {
        assert!(!is_error_code(220));
        assert!(!is_error_code(250));
        assert!(!is_error_code(150));
        assert!(is_error_code(420));
        assert!(is_error_code(500));
        assert!(is_error_code(550));
        assert!(!is_error_code(600));
    }

    #[test]
    fn read_text_block_stops_at_dot() {
        let input = b"line one\r\nline two\r\n.\r\n250 ok\r\n";
        let mut reader = std::io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        read_text_block(&mut reader, &mut out).unwrap();
        assert_eq!(out, b"line one\nline two\n");
        // The next read should give us the 250 line.
        let mut tail = String::new();
        reader.read_line(&mut tail).unwrap();
        assert_eq!(tail, "250 ok\r\n");
    }

    #[test]
    fn read_text_block_unescapes_dot_stuffing() {
        // A line starting with ".." represents a body line starting with ".".
        let input = b"normal\r\n..hidden\r\n.\r\n";
        let mut reader = std::io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        read_text_block(&mut reader, &mut out).unwrap();
        assert_eq!(out, b"normal\n.hidden\n");
    }

    #[test]
    fn read_text_block_errors_on_premature_eof() {
        let input = b"line one\r\n";
        let mut reader = std::io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        let err = read_text_block(&mut reader, &mut out).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }
}
