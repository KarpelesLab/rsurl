//! BitTorrent support: load metadata from a `.torrent` file or `magnet:` link,
//! discover peers (HTTP/UDP trackers, DHT), exchange pieces over the peer wire
//! protocol, verify and write data, and optionally seed.
//!
//! Built on the crate's existing primitives — `purecrypto` (SHA-1, RNG),
//! `crate::net` (UDP/TCP), `crate::http` (HTTP trackers) — and `std` threads +
//! channels; no async runtime and no new external dependency.
//!
//! This is delivered in phases. Phase 1 (here): bencode, `.torrent` metainfo +
//! infohash, and magnet parsing.

pub mod bencode;
pub mod magnet;
pub mod metainfo;

pub use bencode::Value;
pub use magnet::Magnet;
pub use metainfo::{FileEntry, Metainfo};

use purecrypto::rng::{OsRng, RngCore};

use crate::error::{Error, Result};

/// Generate a 20-byte BitTorrent peer id with the Azureus-style prefix
/// `-RS` + version, the rest random. Fails closed if no OS entropy is
/// available (a predictable id is worse than an error).
pub fn generate_peer_id() -> Result<[u8; 20]> {
    let mut id = [0u8; 20];
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OsRng.fill_bytes(&mut id);
    }))
    .map_err(|_| Error::BadResponse("bittorrent: no secure entropy source".into()))?;
    // Peer-id convention: "-<2-char client><4-digit version>-" then random.
    let prefix = b"-RS0001-";
    id[..prefix.len()].copy_from_slice(prefix);
    Ok(id)
}
