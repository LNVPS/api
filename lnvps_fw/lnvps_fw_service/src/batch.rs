//! Batched BPF map reads via the raw `BPF_MAP_LOOKUP_BATCH` syscall.
//!
//! aya 0.14 only exposes per-entry iteration: every entry costs a
//! `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_LOOKUP_ELEM` syscall pair. The control
//! loop reads the source/dest counter maps every sample tick, so on a large
//! map (the source counters hold up to 256k entries during a flood) that is
//! ~1M syscalls/second — a pinned core. `BPF_MAP_LOOKUP_BATCH` (kernel 5.6+)
//! returns thousands of entries per syscall instead.
//!
//! Callers must fall back to per-entry iteration when [`supported`] turns
//! false: the first syscall failure with `EINVAL`/`ENOTSUPP` (old kernel, or
//! a map type without batch support) latches the flag off process-wide.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use aya::Pod;

/// `enum bpf_cmd` value for `BPF_MAP_LOOKUP_BATCH`.
const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;

/// Entries requested per syscall. Large enough that syscall overhead is noise
/// (a full 256k-entry map is ~64 calls), small enough that the key/value
/// buffers stay modest (16-byte keys × 4096 = 64 KiB).
const CHUNK: usize = 4096;

/// Kernel-visible tail of `union bpf_attr` used by the `BPF_MAP_*_BATCH`
/// commands (uapi `linux/bpf.h`). Field order and alignment must match.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

/// Latched process-wide support flag (assume supported until proven wrong).
static SUPPORTED: AtomicBool = AtomicBool::new(true);

/// Whether batch lookups are (still believed to be) supported. Callers should
/// take their per-entry fallback path when this is false.
pub fn supported() -> bool {
    SUPPORTED.load(Ordering::Relaxed)
}

/// Does this error mean "the kernel or map type cannot do batch lookups"
/// (permanent — latch off and fall back) rather than a transient failure?
fn is_unsupported(e: &io::Error) -> bool {
    // ENOTSUPP (524) has no libc constant; EINVAL = kernel predates the
    // command or rejects it for this map type; EPERM under a locked-down bpf().
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::EPERM) | Some(524)
    )
}

/// One raw `BPF_MAP_LOOKUP_BATCH` call. Returns `Ok(done)` where `done` means
/// the map is exhausted (`ENOENT` — the final partial chunk, if any, is still
/// delivered). `attr.count` is updated by the kernel to the entries returned.
///
/// # Safety
/// `attr` must point key/value buffers with room for `attr.count` entries of
/// the map's key size / value stride respectively, and `in_batch`/`out_batch`
/// at valid token storage.
unsafe fn lookup_batch_once(attr: &mut BatchAttr) -> io::Result<bool> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_BATCH,
            attr as *mut BatchAttr,
            size_of::<BatchAttr>(),
        )
    };
    if ret == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        return Ok(true); // exhausted; attr.count holds the final chunk size
    }
    Err(err)
}

/// Scan an entire hash-family map with batched lookups into raw byte buffers.
/// `stride` is the byte size of one entry's value block (`value_size` for
/// plain maps, `round8(value_size) × possible_cpus` for per-CPU maps).
/// Returns `(keys, values, n)` holding `n` densely-packed entries.
fn scan_raw(
    fd: BorrowedFd<'_>,
    key_size: usize,
    stride: usize,
) -> io::Result<(Vec<u8>, Vec<u8>, usize)> {
    let mut keys: Vec<u8> = Vec::new();
    let mut vals: Vec<u8> = Vec::new();
    let mut total = 0usize;
    // Opaque per-map resume token (a bucket index for hash maps; u64 storage
    // is large enough for every map family).
    let mut token_in = 0u64;
    let mut token_out = 0u64;
    let mut first = true;
    let mut chunk = CHUNK;
    loop {
        keys.resize((total + chunk) * key_size, 0);
        vals.resize((total + chunk) * stride, 0);
        let mut attr = BatchAttr {
            in_batch: if first { 0 } else { &raw mut token_in as u64 },
            out_batch: &raw mut token_out as u64,
            keys: keys[total * key_size..].as_mut_ptr() as u64,
            values: vals[total * stride..].as_mut_ptr() as u64,
            count: chunk as u32,
            map_fd: fd.as_raw_fd() as u32,
            elem_flags: 0,
            flags: 0,
        };
        // SAFETY: buffers sized for `chunk` entries above; tokens are valid.
        let done = match unsafe { lookup_batch_once(&mut attr) } {
            Ok(done) => done,
            // A bucket larger than the whole chunk (pathological collisions):
            // grow and retry the same position.
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                chunk *= 2;
                continue;
            }
            Err(e) => return Err(e),
        };
        total += attr.count as usize;
        if done {
            break;
        }
        token_in = token_out;
        first = false;
    }
    keys.truncate(total * key_size);
    vals.truncate(total * stride);
    Ok((keys, vals, total))
}

/// Round a per-CPU value size up to the kernel's 8-byte per-CPU slot stride.
fn round8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Batched read of a **per-CPU** map, folding each entry's per-CPU values into
/// one `T` with `fold` (e.g. summing counters across CPUs).
pub fn read_percpu_folded<K, V, T>(
    fd: BorrowedFd<'_>,
    ncpus: usize,
    fold: impl Fn(&mut T, &V),
) -> io::Result<Vec<(K, T)>>
where
    K: Pod,
    V: Pod,
    T: Default,
{
    let key_size = size_of::<K>();
    let slot = round8(size_of::<V>());
    let stride = slot * ncpus;
    let (keys, vals, n) = scan_raw(fd, key_size, stride)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: buffers hold `n` densely-packed entries; K/V are Pod, and
        // every per-CPU slot lies within the entry's stride block.
        let k = unsafe { *(keys[i * key_size..].as_ptr() as *const K) };
        let mut acc = T::default();
        for cpu in 0..ncpus {
            let v = unsafe { *(vals[i * stride + cpu * slot..].as_ptr() as *const V) };
            fold(&mut acc, &v);
        }
        out.push((k, acc));
    }
    Ok(out)
}

/// Batched read of a **plain** (non-per-CPU) map into `(key, value)` pairs.
pub fn read_plain<K, V>(fd: BorrowedFd<'_>) -> io::Result<Vec<(K, V)>>
where
    K: Pod,
    V: Pod,
{
    let key_size = size_of::<K>();
    let stride = size_of::<V>();
    let (keys, vals, n) = scan_raw(fd, key_size, stride)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: buffers hold `n` densely-packed entries and K/V are Pod.
        let k = unsafe { *(keys[i * key_size..].as_ptr() as *const K) };
        let v = unsafe { *(vals[i * stride..].as_ptr() as *const V) };
        out.push((k, v));
    }
    Ok(out)
}

/// Record a batch failure: permanent unsupport latches the flag off (callers
/// fall back to per-entry iteration for the rest of the process lifetime).
/// Returns true if the error was the permanent kind.
pub fn note_failure(e: &io::Error) -> bool {
    if is_unsupported(e) {
        SUPPORTED.store(false, Ordering::Relaxed);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round8_covers_slot_alignment() {
        assert_eq!(round8(1), 8);
        assert_eq!(round8(8), 8);
        assert_eq!(round8(9), 16);
        assert_eq!(round8(56), 56); // DestCounters: 7 × u64
    }

    #[test]
    fn unsupported_errors_latch_off() {
        assert!(is_unsupported(&io::Error::from_raw_os_error(libc::EINVAL)));
        assert!(is_unsupported(&io::Error::from_raw_os_error(524))); // ENOTSUPP
        assert!(!is_unsupported(&io::Error::from_raw_os_error(libc::ENOENT)));
        assert!(!is_unsupported(&io::Error::from_raw_os_error(libc::EFAULT)));
    }

    #[test]
    fn batch_attr_layout_matches_uapi() {
        // Offsets from uapi linux/bpf.h `struct bpf_attr { ... } batch;`
        assert_eq!(std::mem::offset_of!(BatchAttr, in_batch), 0);
        assert_eq!(std::mem::offset_of!(BatchAttr, out_batch), 8);
        assert_eq!(std::mem::offset_of!(BatchAttr, keys), 16);
        assert_eq!(std::mem::offset_of!(BatchAttr, values), 24);
        assert_eq!(std::mem::offset_of!(BatchAttr, count), 32);
        assert_eq!(std::mem::offset_of!(BatchAttr, map_fd), 36);
        assert_eq!(std::mem::offset_of!(BatchAttr, elem_flags), 40);
        assert_eq!(std::mem::offset_of!(BatchAttr, flags), 48);
        assert_eq!(size_of::<BatchAttr>(), 56);
    }

    /// End-to-end against a real kernel map (needs CAP_BPF/root): create an
    /// LRU per-CPU hash, fill it via aya, batch-read it back and compare with
    /// aya's per-entry iteration.
    #[test]
    #[ignore = "requires root/CAP_BPF"]
    fn batch_read_matches_iteration_on_real_map() {
        use std::os::fd::FromRawFd;
        // Create a BPF_MAP_TYPE_LRU_PERCPU_HASH (9) directly via bpf(2).
        #[repr(C)]
        #[derive(Default)]
        struct CreateAttr {
            map_type: u32,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            map_flags: u32,
        }
        let attr = CreateAttr {
            map_type: 10, // BPF_MAP_TYPE_LRU_PERCPU_HASH
            key_size: 4,
            value_size: 8,
            max_entries: 1024,
            ..Default::default()
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                0i64, // BPF_MAP_CREATE
                &attr as *const CreateAttr,
                size_of::<CreateAttr>(),
            )
        };
        assert!(fd >= 0, "map create failed: {}", io::Error::last_os_error());
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
        let ncpus = aya::util::nr_cpus().expect("nr_cpus");

        // Insert 100 keys, value = key on every CPU slot.
        #[repr(C)]
        struct UpdateAttr {
            map_fd: u32,
            _pad: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        let slot = round8(8);
        for i in 0u32..100 {
            let vals: Vec<u8> = (0..ncpus)
                .flat_map(|_| u64::from(i).to_ne_bytes())
                .collect();
            assert_eq!(vals.len(), slot * ncpus);
            let ua = UpdateAttr {
                map_fd: fd as u32,
                _pad: 0,
                key: &raw const i as u64,
                value: vals.as_ptr() as u64,
                flags: 0,
            };
            let r = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    1i64, // BPF_MAP_UPDATE_ELEM
                    &ua as *const UpdateAttr,
                    size_of::<UpdateAttr>(),
                )
            };
            assert_eq!(r, 0, "update failed: {}", io::Error::last_os_error());
        }

        use std::os::fd::AsFd;
        let got: Vec<([u8; 4], u64)> =
            read_percpu_folded(owned.as_fd(), ncpus, |acc: &mut u64, v: &u64| *acc += *v)
                .expect("batch read");
        assert_eq!(got.len(), 100);
        for (k, sum) in got {
            let key = u32::from_ne_bytes(k);
            assert_eq!(sum, u64::from(key) * ncpus as u64);
        }
    }
}
