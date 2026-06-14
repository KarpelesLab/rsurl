//! Piece bookkeeping: a [`Bitfield`] and a rarest-first [`Picker`].

use std::collections::HashSet;

/// A BitTorrent bitfield (BEP 3): bit 0 is the most-significant bit of byte 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    bits: Vec<u8>,
    len: usize,
}

impl Bitfield {
    pub fn new(len: usize) -> Self {
        Bitfield {
            bits: vec![0u8; len.div_ceil(8)],
            len,
        }
    }

    /// Build from wire bytes; extra bytes/bits beyond `len` are ignored.
    pub fn from_bytes(bytes: &[u8], len: usize) -> Self {
        let mut bf = Bitfield::new(len);
        let n = bytes.len().min(bf.bits.len());
        bf.bits[..n].copy_from_slice(&bytes[..n]);
        bf
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn has(&self, i: usize) -> bool {
        if i >= self.len {
            return false;
        }
        self.bits[i / 8] & (0x80 >> (i % 8)) != 0
    }

    pub fn set(&mut self, i: usize) {
        if i < self.len {
            self.bits[i / 8] |= 0x80 >> (i % 8);
        }
    }

    pub fn count(&self) -> usize {
        (0..self.len).filter(|&i| self.has(i)).count()
    }

    pub fn is_complete(&self) -> bool {
        (0..self.len).all(|i| self.has(i))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

/// Rarest-first piece picker. The engine feeds it each peer's advertised pieces
/// (so it knows availability), and asks it which piece to fetch next.
pub struct Picker {
    availability: Vec<u32>,
}

impl Picker {
    pub fn new(num_pieces: usize) -> Self {
        Picker {
            availability: vec![0; num_pieces],
        }
    }

    pub fn add_have(&mut self, index: usize) {
        if let Some(c) = self.availability.get_mut(index) {
            *c += 1;
        }
    }

    pub fn add_bitfield(&mut self, bf: &Bitfield) {
        for i in 0..bf.len() {
            if bf.has(i) {
                self.add_have(i);
            }
        }
    }

    /// A peer left; decrement availability for the pieces it had.
    pub fn remove_bitfield(&mut self, bf: &Bitfield) {
        for i in 0..bf.len() {
            if bf.has(i) {
                if let Some(c) = self.availability.get_mut(i) {
                    *c = c.saturating_sub(1);
                }
            }
        }
    }

    /// Pick the rarest piece we lack (`!ours`) that `peer_has`, excluding pieces
    /// already being fetched (`exclude`). Ties break toward the lowest index.
    pub fn pick(
        &self,
        ours: &Bitfield,
        peer_has: &Bitfield,
        exclude: &HashSet<usize>,
    ) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for i in 0..self.availability.len() {
            if ours.has(i) || !peer_has.has(i) || exclude.contains(&i) {
                continue;
            }
            let avail = self.availability[i];
            match best {
                Some((b, _)) if b <= avail => {}
                _ => best = Some((avail, i)),
            }
        }
        best.map(|(_, i)| i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitfield_msb_first() {
        let mut bf = Bitfield::new(10);
        assert!(!bf.has(0));
        bf.set(0);
        bf.set(9);
        assert!(bf.has(0));
        assert!(bf.has(9));
        assert!(!bf.has(5));
        assert_eq!(bf.count(), 2);
        // piece 0 => high bit of byte 0; piece 9 => bit 1 of byte 1.
        assert_eq!(bf.as_bytes(), &[0x80, 0x40]);
        assert!(!bf.is_complete());
    }

    #[test]
    fn from_bytes_round_trips() {
        let bf = Bitfield::from_bytes(&[0b1010_0000], 3);
        assert!(bf.has(0));
        assert!(!bf.has(1));
        assert!(bf.has(2));
    }

    #[test]
    fn picker_prefers_rarest() {
        let mut p = Picker::new(4);
        let ours = Bitfield::new(4);
        // availability: piece0=3, piece1=1, piece2=2, piece3=0(peer lacks)
        let mut a = Bitfield::new(4);
        a.set(0);
        a.set(1);
        a.set(2);
        p.add_bitfield(&a); // all three +1
        p.add_have(0);
        p.add_have(0);
        p.add_have(2);
        let mut peer = Bitfield::new(4);
        peer.set(0);
        peer.set(1);
        peer.set(2);
        let exclude = HashSet::new();
        // rarest among {0:3,1:1,2:2} is piece 1
        assert_eq!(p.pick(&ours, &peer, &exclude), Some(1));
        // exclude piece 1 → next rarest is piece 2
        let exclude: HashSet<usize> = [1].into_iter().collect();
        assert_eq!(p.pick(&ours, &peer, &exclude), Some(2));
    }

    #[test]
    fn picker_skips_owned_and_unavailable() {
        let p = Picker::new(3);
        let mut ours = Bitfield::new(3);
        ours.set(0);
        let mut peer = Bitfield::new(3);
        peer.set(0); // we already have it
        peer.set(1); // peer has it, we lack it
                     // piece 2 nobody has
        assert_eq!(p.pick(&ours, &peer, &HashSet::new()), Some(1));
    }
}
