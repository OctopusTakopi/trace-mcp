//! Zero-allocation scanner for `perf script` sample lines.
//!
//! A calls pass of a modest Intel PT capture is ~10 million lines of ~180
//! bytes each; the tolerant token parser (allocating per token) was the
//! decode bottleneck. This scanner walks the line with raw pointers and
//! decodes numbers from 16-byte windows using lookup tables and masked
//! arithmetic instead of per-byte branches.
//!
//! Layout handled (see `docs/perf-compatibility.md`):
//!
//! ```text
//! PID/TID [CPU] SEC.NS:  branches:u:   FLAGS  IP => ADDR
//! PID/TID [CPU] SEC.NS:  instructions:u:  FLAGS  ADDR IP ilen: N insn: xx xx
//! PID/TID [CPU] SEC.NS:  branches:u:  IP ADDR FLAGS          (synthetic fixtures)
//! ```
//!
//! Anything else returns `None` and the caller falls back to the tolerant
//! parser, so the fast path never has to be lenient.
//!
//! # Safety contract
//!
//! [`parse_sample_guarded`] reads up to [`GUARD`] bytes past the end of the
//! slice it is given. It never *consumes* past the end; the over-read only
//! feeds classification and is masked off by the remaining length. Callers
//! must guarantee those bytes are readable. [`parse_sample`] is the safe
//! wrapper that copies into a guarded buffer.

use super::{Flags, InsnBytes, Sample, SampleEvent};

/// Readable bytes required after the end of a line.
pub const GUARD: usize = 32;

const INVALID: u8 = 0xff;

const HEX_LUT: [u8; 256] = {
    let mut t = [INVALID; 256];
    let mut i = 0u8;
    while i < 10 {
        t[(b'0' + i) as usize] = i;
        i += 1;
    }
    let mut i = 0u8;
    while i < 6 {
        t[(b'a' + i) as usize] = 10 + i;
        t[(b'A' + i) as usize] = 10 + i;
        i += 1;
    }
    t
};

const POW10: [u64; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

struct Cur {
    p: *const u8,
    end: *const u8,
}

impl Cur {
    #[inline(always)]
    fn rem(&self) -> usize {
        // SAFETY: p and end come from the same allocation and p <= end.
        unsafe { self.end.offset_from(self.p) as usize }
    }

    #[inline(always)]
    unsafe fn load16(&self) -> [u8; 16] {
        // SAFETY: p <= end and GUARD >= 16 readable bytes follow `end`.
        unsafe { (self.p as *const [u8; 16]).read_unaligned() }
    }

    #[inline(always)]
    unsafe fn load8(&self) -> u64 {
        // SAFETY: as above, GUARD >= 8.
        unsafe { (self.p as *const u64).read_unaligned() }
    }

    #[inline(always)]
    unsafe fn adv(&mut self, n: usize) {
        // SAFETY: callers clamp n to rem().
        self.p = unsafe { self.p.add(n) };
    }

    #[inline(always)]
    fn peek(&self) -> u8 {
        // Guard bytes are readable, so peeking at end is fine; the value is
        // only compared against structural characters.
        // SAFETY: see module docs.
        unsafe { *self.p }
    }

    /// Decimal run, branchless over a 16-byte window. Returns (value, digits).
    #[inline(always)]
    unsafe fn dec(&mut self) -> (u64, usize) {
        let w = unsafe { self.load16() };
        let mut invalid: u32 = 0;
        let mut d = [0u64; 16];
        for (i, (&b, slot)) in w.iter().zip(d.iter_mut()).enumerate() {
            let x = b.wrapping_sub(b'0');
            invalid |= u32::from(x > 9) << i;
            *slot = u64::from(x);
        }
        invalid |= 1u32 << self.rem().min(16);
        let n = invalid.trailing_zeros() as usize;
        let mut v = 0u64;
        for (i, &digit) in d.iter().enumerate() {
            let take = u64::from(i < n);
            v = v * (1 + 9 * take) + digit * take;
        }
        unsafe { self.adv(n) };
        (v, n)
    }

    /// Hex run, branchless over a 16-byte window. Returns (value, digits).
    #[inline(always)]
    unsafe fn hex(&mut self) -> (u64, usize) {
        let w = unsafe { self.load16() };
        let mut invalid: u32 = 0;
        let mut nib = [0u64; 16];
        for (i, (&b, slot)) in w.iter().zip(nib.iter_mut()).enumerate() {
            let x = HEX_LUT[b as usize];
            invalid |= u32::from(x == INVALID) << i;
            *slot = u64::from(x & 0x0f);
        }
        invalid |= 1u32 << self.rem().min(16);
        let n = invalid.trailing_zeros() as usize;
        let mut v = 0u64;
        for (i, &x) in nib.iter().enumerate() {
            let take = u64::from(i < n);
            v = (v << (4 * take as u32)) | (x * take);
        }
        unsafe { self.adv(n) };
        (v, n)
    }

    /// Skip spaces and tabs, 8 bytes at a time.
    #[inline(always)]
    unsafe fn skip_ws(&mut self) {
        loop {
            let rem = self.rem();
            if rem == 0 {
                return;
            }
            let w = unsafe { self.load8() };
            // Bytes equal to ' ' become 0; then find the first nonzero byte.
            let x = w ^ 0x2020_2020_2020_2020;
            // Tabs are rare in perf output; treat them as non-space stops.
            if x == 0 && rem >= 8 {
                unsafe { self.adv(8) };
                continue;
            }
            let first = if x == 0 {
                8
            } else {
                (x.trailing_zeros() / 8) as usize
            };
            unsafe { self.adv(first.min(rem)) };
            return;
        }
    }

    /// Length of the token starting at `p` (bytes until space/tab/end).
    #[inline(always)]
    unsafe fn token_len(&self) -> usize {
        let rem = self.rem();
        let mut n = 0usize;
        while n < rem {
            let w = unsafe { (self.p.add(n) as *const [u8; 16]).read_unaligned() };
            let mut stop: u32 = 0;
            for (i, &b) in w.iter().enumerate() {
                stop |= u32::from(b == b' ' || b == b'\t' || b == b'\n') << i;
            }
            let k = stop.trailing_zeros() as usize;
            if k < 16 {
                return (n + k).min(rem);
            }
            n += 16;
        }
        rem
    }

    #[inline(always)]
    unsafe fn token(&self) -> &[u8] {
        let n = unsafe { self.token_len() };
        // SAFETY: n <= rem.
        unsafe { std::slice::from_raw_parts(self.p, n) }
    }

    #[inline(always)]
    fn starts_with(&self, lit: &[u8]) -> bool {
        if self.rem() < lit.len() {
            return false;
        }
        // SAFETY: rem >= lit.len().
        unsafe { std::slice::from_raw_parts(self.p, lit.len()) == lit }
    }
}

#[inline(always)]
fn is_hex_token(tok: &[u8]) -> bool {
    !tok.is_empty() && tok.len() <= 16 && tok.iter().all(|&b| HEX_LUT[b as usize] != INVALID)
}

/// Safe wrapper: copies the line into a guarded buffer.
pub fn parse_sample(line: &[u8]) -> Option<Sample> {
    let mut buf = Vec::with_capacity(line.len() + GUARD);
    buf.extend_from_slice(line);
    buf.resize(line.len() + GUARD, 0);
    // SAFETY: GUARD zero bytes follow the line.
    unsafe { parse_sample_guarded(&buf[..line.len()]) }
}

/// Parse a sample line.
///
/// # Safety
/// At least [`GUARD`] bytes past `line.as_ptr() + line.len()` must be readable.
pub unsafe fn parse_sample_guarded(line: &[u8]) -> Option<Sample> {
    // SAFETY: every pointer read below stays within line + GUARD and every
    // advance is clamped to the remaining length.
    unsafe {
        let mut c = Cur {
            p: line.as_ptr(),
            end: line.as_ptr().add(line.len()),
        };
        c.skip_ws();
        let (pid, n) = c.dec();
        if n == 0 || c.peek() != b'/' {
            return None;
        }
        c.adv(1);
        let (tid, n) = c.dec();
        if n == 0 {
            return None;
        }
        c.skip_ws();

        let mut cpu = None;
        if c.peek() == b'[' {
            c.adv(1);
            let (v, n) = c.dec();
            if n == 0 || c.peek() != b']' {
                return None;
            }
            c.adv(1);
            cpu = Some(v as u32);
            c.skip_ws();
        }

        let (sec, n) = c.dec();
        if n == 0 || c.peek() != b'.' {
            return None;
        }
        c.adv(1);
        let (frac, fd) = c.dec();
        if fd == 0 || fd > 9 || c.peek() != b':' {
            return None;
        }
        c.adv(1);
        let time_ns = sec
            .checked_mul(1_000_000_000)?
            .checked_add(frac * POW10[9 - fd])?;
        c.skip_ws();

        let ev = c.token();
        let event = if ev.starts_with(b"branches") {
            SampleEvent::Branches
        } else if ev.starts_with(b"instructions") {
            SampleEvent::Instructions
        } else {
            return None;
        };
        if ev.last() != Some(&b':') {
            return None;
        }
        c.adv(ev.len());
        c.skip_ws();

        let mut flags = Flags::EMPTY;
        let mut prev_hw = false;
        loop {
            let tok = c.token();
            if tok.is_empty() {
                break;
            }
            match Flags::from_token(tok) {
                Some(Flags::INT) if prev_hw => flags = flags.union(Flags::HW_INT),
                Some(f) => flags = flags.union(f),
                None => break,
            }
            prev_hw = tok == b"hw";
            c.adv(tok.len());
            c.skip_ws();
        }

        let mut ip = None;
        let mut addr = None;
        let first = c.token();
        if is_hex_token(first) {
            let (a, _) = c.hex();
            c.skip_ws();
            if c.starts_with(b"=>") {
                c.adv(2);
                c.skip_ws();
                let t = c.token();
                if !is_hex_token(t) {
                    return None;
                }
                let (b, _) = c.hex();
                ip = Some(a);
                addr = Some(b);
            } else {
                let t = c.token();
                if is_hex_token(t) {
                    let (b, _) = c.hex();
                    if event.is_instruction() {
                        addr = Some(a);
                        ip = Some(b);
                    } else {
                        ip = Some(a);
                        addr = Some(b);
                    }
                } else {
                    ip = Some(a);
                }
            }
            c.skip_ws();
        }

        let mut insn_len = None;
        let mut insn = InsnBytes::default();
        loop {
            let tok = c.token();
            if tok.is_empty() {
                break;
            }
            if tok == b"ilen:" || tok == b"insnlen:" {
                c.adv(tok.len());
                c.skip_ws();
                let (v, n) = c.dec();
                if n == 0 || v > 255 {
                    return None;
                }
                insn_len = Some(v as u8);
                c.skip_ws();
                continue;
            }
            if tok == b"insn:" {
                c.adv(tok.len());
                c.skip_ws();
                loop {
                    let t = c.token();
                    if t.len() != 2 || !is_hex_token(t) {
                        break;
                    }
                    let (v, _) = c.hex();
                    if usize::from(insn.len) < 15 {
                        insn.bytes[usize::from(insn.len)] = v as u8;
                        insn.len += 1;
                    }
                    c.skip_ws();
                }
                continue;
            }
            match Flags::from_token(tok) {
                Some(Flags::INT) if prev_hw => flags = flags.union(Flags::HW_INT),
                Some(f) => flags = flags.union(f),
                None => return None,
            }
            prev_hw = tok == b"hw";
            c.adv(tok.len());
            c.skip_ws();
        }

        Some(Sample {
            pid: pid as u32,
            tid: tid as u32,
            cpu,
            time_ns: (time_ns != 0).then_some(time_ns),
            event,
            ip,
            addr,
            flags,
            insn_len,
            insn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_matches_hardware_calls_line() {
        let s = parse_sample(b"1620630/1620630 [019] 519333.481030700:                                                                  branches:u:   jcc                        55d0d6d2de38 =>     55d0d6d2de30").unwrap();
        assert_eq!(s.pid, 1620630);
        assert_eq!(s.cpu, Some(19));
        assert_eq!(s.time_ns, Some(519333_481030700));
        assert_eq!(s.flags, Flags::JCC);
        assert_eq!(s.ip, Some(0x55d0d6d2de38));
        assert_eq!(s.addr, Some(0x55d0d6d2de30));
        assert_eq!(s.event, SampleEvent::Branches);
    }

    #[test]
    fn fast_handles_two_word_flags_and_zero_addr() {
        let s = parse_sample(b"1620630/1620631 [054] 519322.048887130:   branches:u:   tr end  syscall            7f8222e7e234 =>                0").unwrap();
        assert!(s.flags.has(Flags::TR_END) && s.flags.has(Flags::SYSCALL));
        assert_eq!(s.addr, Some(0));
        let s = parse_sample(b"1/1 [000] 1.0:  branches:u:   hw int   10 => 20").unwrap();
        assert!(s.flags.has(Flags::HW_INT));
        assert!(!s.flags.has(Flags::INT));
    }

    #[test]
    fn fast_instruction_line() {
        let s = parse_sample(b"1518114/1518114 [062] 513961.572230317:  instructions:u:   call                      7f5459d6d140     7f5459d6c443 ilen: 5 insn: e8 f8 0c 00 00").unwrap();
        assert_eq!(s.ip, Some(0x7f5459d6c443));
        assert_eq!(s.addr, Some(0x7f5459d6d140));
        assert_eq!(s.insn_len, Some(5));
        assert_eq!(s.insn.as_slice(), &[0xe8, 0xf8, 0x0c, 0x00, 0x00]);
    }

    #[test]
    fn fast_rejects_sideband_and_junk() {
        assert!(parse_sample(b"1620630/1620630 [019] 519321.847655482: PERF_RECORD_MMAP2 1620630/1620630: [0x55d0d6d0c000(0x237000) @ 0xc5000]: r-xp /x").is_none());
        assert!(
            parse_sample(
                b" instruction trace error type 1 time 1.0 cpu 1 pid 1 tid 1 ip 0x0 code 5: x"
            )
            .is_none()
        );
        assert!(parse_sample(b"").is_none());
        assert!(parse_sample(b"12/").is_none());
        assert!(parse_sample(b"1/1 [000] 1.0:  branches:u:  10 => zz").is_none());
    }

    #[test]
    fn fast_fixture_flags_last_dialect() {
        let s = parse_sample(b"1/1 [000] 10.000000010:  branches:u:  200 300  call").unwrap();
        assert_eq!(s.ip, Some(0x200));
        assert_eq!(s.addr, Some(0x300));
        assert_eq!(s.flags, Flags::CALL);
        assert_eq!(s.time_ns, Some(10_000_000_010));
    }

    #[test]
    fn dec_and_hex_windows_clamp_to_line() {
        // 16+ digit runs and runs that end exactly at the slice end.
        let s = parse_sample(b"1/1 [000] 1.5:  branches:u:  ffffffffffffffff").unwrap();
        assert_eq!(s.ip, Some(u64::MAX));
        assert_eq!(s.time_ns, Some(1_500_000_000));
        let s = parse_sample(b"4294967295/1 1.000000001:  branches:u:  1").unwrap();
        assert_eq!(s.pid, u32::MAX);
        assert_eq!(s.cpu, None);
        assert_eq!(s.time_ns, Some(1_000_000_001));
    }
}
