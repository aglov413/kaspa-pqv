//! Compile-time stack bookkeeping.
//!
//! An unrolled SLH-DSA verifier is tens of thousands of opcodes deep and every
//! `OpPick` needs a depth counted from the top of a stack that eight different
//! phases are pushing to. Hand-counting those depths is where this kind of
//! generator goes wrong, and the failure mode is a script that runs, hashes the
//! wrong bytes, and returns false — indistinguishable from a bad signature.
//!
//! So the emitter never writes a literal depth. It names its stack slots and
//! asks for them, and [`Frame`] resolves the name to a depth or fails at
//! *generation* time. Anything unnamed is a transient and must be balanced
//! before the frame is queried again.

use anyhow::{bail, Result};

/// The main data stack, bottom first, as the emitter believes it to be.
#[derive(Clone, Debug, Default)]
pub struct Frame {
    slots: Vec<String>,
}

/// The name given to values that exist only within one emitted expression.
pub const TRANSIENT: &str = "_";

impl Frame {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Depth of a named slot, counted from the top of the stack (top is 0),
    /// which is what `OpPick` and `OpRoll` expect.
    pub fn depth(&self, name: &str) -> Result<usize> {
        match self.slots.iter().rposition(|s| s == name) {
            Some(pos) => Ok(self.slots.len() - 1 - pos),
            None => bail!("no stack slot named `{name}`; frame is {:?}", self.slots),
        }
    }

    pub fn push(&mut self, name: &str) {
        self.slots.push(name.to_string());
    }

    pub fn push_transient(&mut self) {
        self.push(TRANSIENT);
    }

    pub fn pop(&mut self) -> Result<String> {
        self.slots.pop().ok_or_else(|| anyhow::anyhow!("stack underflow in the emitter"))
    }

    /// Pop `n` values and push one named result — the shape of most opcodes.
    pub fn replace(&mut self, n: usize, name: &str) -> Result<()> {
        for _ in 0..n {
            self.pop()?;
        }
        self.push(name);
        Ok(())
    }

    pub fn rename_top(&mut self, name: &str) -> Result<()> {
        self.pop()?;
        self.push(name);
        Ok(())
    }

    pub fn swap(&mut self) -> Result<()> {
        let n = self.slots.len();
        if n < 2 {
            bail!("swap needs two stack items, frame is {:?}", self.slots);
        }
        self.slots.swap(n - 1, n - 2);
        Ok(())
    }

    /// `OpRoll`: move the item at `depth` to the top.
    pub fn roll(&mut self, depth: usize) -> Result<()> {
        let n = self.slots.len();
        if depth >= n {
            bail!("roll depth {depth} exceeds frame {:?}", self.slots);
        }
        let item = self.slots.remove(n - 1 - depth);
        self.slots.push(item);
        Ok(())
    }

    /// `OpNip`: discard the second item.
    pub fn nip(&mut self) -> Result<()> {
        let n = self.slots.len();
        if n < 2 {
            bail!("nip needs two stack items, frame is {:?}", self.slots);
        }
        self.slots.remove(n - 2);
        Ok(())
    }

    /// Assert the exact contents of the top of the frame, top-most last.
    ///
    /// Used at phase boundaries: a phase that leaves one stray transient
    /// behind shifts every depth in the next phase by one, and this is what
    /// turns that into a generator error rather than a wrong hash.
    pub fn expect_top(&self, expected: &[&str]) -> Result<()> {
        let n = self.slots.len();
        if n < expected.len() {
            bail!("frame {:?} is shorter than expected {:?}", self.slots, expected);
        }
        let actual: Vec<&str> = self.slots[n - expected.len()..].iter().map(String::as_str).collect();
        if actual != expected {
            bail!("frame top is {actual:?}, expected {expected:?} (full frame {:?})", self.slots);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_is_counted_from_the_top() {
        let mut f = Frame::new();
        f.push("a");
        f.push("b");
        f.push("c");
        assert_eq!(f.depth("c").unwrap(), 0);
        assert_eq!(f.depth("b").unwrap(), 1);
        assert_eq!(f.depth("a").unwrap(), 2);
    }

    #[test]
    fn roll_moves_a_buried_slot_to_the_top() {
        let mut f = Frame::new();
        for n in ["a", "b", "c"] {
            f.push(n);
        }
        f.roll(2).unwrap();
        f.expect_top(&["b", "c", "a"]).unwrap();
    }

    #[test]
    fn missing_slots_and_bad_shapes_are_generation_errors() {
        let f = Frame::new();
        assert!(f.depth("nope").is_err());
        let mut f = Frame::new();
        f.push("a");
        assert!(f.swap().is_err());
        assert!(f.expect_top(&["a", "b"]).is_err());
        assert!(f.expect_top(&["b"]).is_err());
    }
}
