//! On-disk storage: maps the torrent's linear byte space onto one or many
//! files, writes SHA-1-verified pieces (which may straddle file boundaries),
//! tracks the completion bitfield, and reads blocks back (for seeding).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::error::{Error, Result};

use super::metainfo::sha1;
use super::picker::Bitfield;

fn serr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bt storage: {}", msg.into()))
}

struct FileSlot {
    path: PathBuf,
    length: u64,
    /// Global byte offset where this file begins in the torrent space.
    start: u64,
    handle: Option<File>,
}

pub struct Storage {
    piece_length: u64,
    total: u64,
    hashes: Vec<[u8; 20]>,
    files: Vec<FileSlot>,
    have: Bitfield,
}

impl Storage {
    /// `layout` is the resolved (absolute path, length) of each file in piece
    /// order; `hashes` is the per-piece SHA-1 table.
    pub fn create(
        layout: Vec<(PathBuf, u64)>,
        piece_length: u64,
        hashes: Vec<[u8; 20]>,
    ) -> Result<Storage> {
        if piece_length == 0 {
            return Err(serr("zero piece length"));
        }
        let mut files = Vec::with_capacity(layout.len());
        let mut start = 0u64;
        for (path, length) in layout {
            files.push(FileSlot {
                path,
                length,
                start,
                handle: None,
            });
            start = start
                .checked_add(length)
                .ok_or_else(|| serr("size overflow"))?;
        }
        let total = start;
        Ok(Storage {
            piece_length,
            total,
            have: Bitfield::new(hashes.len()),
            hashes,
            files,
        })
    }

    pub fn num_pieces(&self) -> usize {
        self.hashes.len()
    }

    pub fn total_length(&self) -> u64 {
        self.total
    }

    pub fn piece_size(&self, index: usize) -> u64 {
        let start = self.piece_length * index as u64;
        (self.total - start).min(self.piece_length)
    }

    pub fn has(&self, index: usize) -> bool {
        self.have.has(index)
    }

    pub fn is_complete(&self) -> bool {
        self.have.is_complete()
    }

    pub fn bitfield(&self) -> &Bitfield {
        &self.have
    }

    /// Bytes of verified, on-disk data.
    pub fn bytes_complete(&self) -> u64 {
        (0..self.num_pieces())
            .filter(|&i| self.have.has(i))
            .map(|i| self.piece_size(i))
            .sum()
    }

    /// Verify `data` against the piece hash and, if it matches, write it across
    /// the covering file(s) and mark the piece complete. Returns `Ok(true)` on
    /// a verified write, `Ok(false)` on a hash mismatch (nothing written).
    pub fn write_piece(&mut self, index: usize, data: &[u8]) -> Result<bool> {
        if index >= self.num_pieces() {
            return Err(serr("piece index out of range"));
        }
        if data.len() as u64 != self.piece_size(index) {
            return Err(serr("piece has wrong length"));
        }
        if sha1(data) != self.hashes[index] {
            return Ok(false);
        }
        let offset = self.piece_length * index as u64;
        self.rw(offset, data.len() as u64, |file, file_off, span| {
            file.seek(SeekFrom::Start(file_off)).map_err(Error::Io)?;
            file.write_all(&data[span.clone()]).map_err(Error::Io)?;
            Ok(())
        })?;
        self.have.set(index);
        Ok(true)
    }

    /// Read `length` bytes of (already-complete) piece `index` starting at
    /// `begin`. Used to serve `request`s when seeding.
    pub fn read_block(&mut self, index: usize, begin: u32, length: u32) -> Result<Vec<u8>> {
        if !self.has(index) {
            return Err(serr("read of incomplete piece"));
        }
        let psize = self.piece_size(index);
        if begin as u64 + length as u64 > psize {
            return Err(serr("read past end of piece"));
        }
        let mut out = vec![0u8; length as usize];
        let offset = self.piece_length * index as u64 + begin as u64;
        self.rw(offset, length as u64, |file, file_off, span| {
            file.seek(SeekFrom::Start(file_off)).map_err(Error::Io)?;
            file.read_exact(&mut out[span.clone()]).map_err(Error::Io)
        })?;
        Ok(out)
    }

    /// Walk the file(s) covering global range `[offset, offset+len)`, invoking
    /// `f(file, within_file_offset, range_in_buffer)` for each overlap.
    fn rw<F>(&mut self, offset: u64, len: u64, mut f: F) -> Result<()>
    where
        F: FnMut(&mut File, u64, std::ops::Range<usize>) -> Result<()>,
    {
        let end = offset + len;
        for slot in &mut self.files {
            let fstart = slot.start;
            let fend = slot.start + slot.length;
            let ov_start = offset.max(fstart);
            let ov_end = end.min(fend);
            if ov_start >= ov_end {
                continue;
            }
            // Lazily open (creating parent dirs + the file).
            if slot.handle.is_none() {
                if let Some(parent) = slot.path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(Error::Io)?;
                    }
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&slot.path)
                    .map_err(Error::Io)?;
                slot.handle = Some(file);
            }
            let file = slot.handle.as_mut().unwrap();
            let within = ov_start - fstart;
            let buf_span = (ov_start - offset) as usize..(ov_end - offset) as usize;
            f(file, within, buf_span)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rsurl_bt_store_{}_{}", std::process::id(), name))
    }

    #[test]
    fn writes_and_verifies_across_two_files() {
        // total 10 bytes, piece_length 4 → pieces of 4,4,2 that straddle the
        // two files (lengths 6 and 4).
        let data: Vec<u8> = (0..10u8).collect();
        let piece_len = 4u64;
        let pieces: Vec<[u8; 20]> = (0..3)
            .map(|i| {
                let s = (i * 4) as usize;
                let e = (s + 4).min(10);
                sha1(&data[s..e])
            })
            .collect();
        let f0 = tmp("a.bin");
        let f1 = tmp("b.bin");
        let _ = std::fs::remove_file(&f0);
        let _ = std::fs::remove_file(&f1);
        let mut st =
            Storage::create(vec![(f0.clone(), 6), (f1.clone(), 4)], piece_len, pieces).unwrap();

        assert_eq!(st.num_pieces(), 3);
        assert_eq!(st.piece_size(0), 4);
        assert_eq!(st.piece_size(2), 2);

        // A corrupt piece is rejected without writing.
        assert!(!st.write_piece(0, &[9, 9, 9, 9]).unwrap());
        assert!(!st.has(0));

        for i in 0..3 {
            let s = i * 4;
            let e = (s + 4).min(10);
            assert!(st.write_piece(i, &data[s..e]).unwrap());
        }
        assert!(st.is_complete());
        assert_eq!(st.bytes_complete(), 10);

        // Files on disk hold the right bytes (piece 1 spans the boundary at 6).
        assert_eq!(std::fs::read(&f0).unwrap(), &data[0..6]);
        assert_eq!(std::fs::read(&f1).unwrap(), &data[6..10]);

        // read_block round-trips (serve a request from the boundary piece).
        let blk = st.read_block(1, 0, 4).unwrap();
        assert_eq!(blk, &data[4..8]);

        let _ = std::fs::remove_file(&f0);
        let _ = std::fs::remove_file(&f1);
    }
}
