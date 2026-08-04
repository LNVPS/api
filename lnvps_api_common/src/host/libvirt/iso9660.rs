//! Minimal ISO9660 writer for cloud-init NoCloud seed images.
//!
//! cloud-init's NoCloud datasource looks for a filesystem labelled `cidata`
//! containing `user-data` / `meta-data` (and optionally `network-config`). This
//! builds exactly that and nothing more: a single-level directory, no Joliet,
//! no Rock Ridge, no boot record.
//!
//! Output is **deterministic** (fixed timestamps), so an unchanged VM config
//! produces a byte-identical image and the seed only has to be re-uploaded when
//! something actually changed.

use anyhow::{Result, bail};

/// ISO9660 logical block size.
const SECTOR: usize = 2048;
/// Sectors reserved before the volume descriptors (the "system area").
const SYSTEM_AREA_SECTORS: usize = 16;

/// A file to place in the image root.
pub struct IsoFile {
    /// Name as the guest should see it, e.g. `user-data`.
    pub name: String,
    pub content: Vec<u8>,
}

impl IsoFile {
    pub fn new(name: &str, content: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.to_string(),
            content: content.into(),
        }
    }

    /// On-disc identifier.
    ///
    /// ISO9660 stores names upper-cased with a `;1` version suffix; Linux's
    /// iso9660 driver maps them back to lower case and strips the version, so
    /// the guest sees `user-data` again.
    fn identifier(&self) -> String {
        format!("{};1", self.name.to_uppercase())
    }
}

/// Build an ISO9660 image containing `files` in the root directory.
///
/// `label` becomes the volume identifier, which is what `blkid` reports as the
/// filesystem label and how cloud-init finds the seed.
pub fn build(label: &str, files: &[IsoFile]) -> Result<Vec<u8>> {
    if files.is_empty() {
        bail!("refusing to build an empty ISO image");
    }
    // The root directory is given a single sector, which is ample for a seed
    // but must not be exceeded silently.
    let mut dir_len = dir_record_len(1) * 2; // "." and ".."
    for f in files {
        dir_len += dir_record_len(f.identifier().len());
    }
    if dir_len > SECTOR {
        bail!("too many files for a single-sector root directory");
    }

    let pvd_lba = SYSTEM_AREA_SECTORS;
    let terminator_lba = pvd_lba + 1;
    let l_path_lba = terminator_lba + 1;
    let m_path_lba = l_path_lba + 1;
    let root_lba = m_path_lba + 1;
    let first_file_lba = root_lba + 1;

    // Lay files out at sector boundaries so each extent is addressable.
    let mut file_lbas = Vec::with_capacity(files.len());
    let mut lba = first_file_lba;
    for f in files {
        file_lbas.push(lba);
        lba += sectors_for(f.content.len());
    }
    let total_sectors = lba;

    let mut image = vec![0u8; total_sectors * SECTOR];

    // --- Primary Volume Descriptor -------------------------------------
    {
        let pvd = &mut image[pvd_lba * SECTOR..(pvd_lba + 1) * SECTOR];
        pvd[0] = 1; // primary volume descriptor
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 1; // version
        write_str(&mut pvd[8..40], ""); // system identifier
        write_str(&mut pvd[40..72], &label.to_uppercase()); // volume identifier
        write_both_u32(&mut pvd[80..88], total_sectors as u32);
        write_both_u16(&mut pvd[120..124], 1); // volume set size
        write_both_u16(&mut pvd[124..128], 1); // volume sequence number
        write_both_u16(&mut pvd[128..132], SECTOR as u16);
        write_both_u32(&mut pvd[132..140], PATH_TABLE_LEN as u32);
        pvd[140..144].copy_from_slice(&(l_path_lba as u32).to_le_bytes());
        pvd[148..152].copy_from_slice(&(m_path_lba as u32).to_be_bytes());
        // Root directory record, inline in the PVD.
        let root = dir_record(&[0x00], root_lba as u32, dir_len as u32, true);
        pvd[156..156 + root.len()].copy_from_slice(&root);
        for range in [
            190..318, // volume set id
            318..446, // publisher
            446..574, // data preparer
            574..702, // application id
        ] {
            write_str(&mut pvd[range], "");
        }
        write_str(&mut pvd[702..739], ""); // copyright file
        write_str(&mut pvd[739..776], ""); // abstract file
        write_str(&mut pvd[776..813], ""); // bibliographic file
        for range in [813..830, 830..847, 847..864, 864..881] {
            write_datetime(&mut pvd[range]);
        }
        pvd[881] = 1; // file structure version
    }

    // --- Volume Descriptor Set Terminator ------------------------------
    {
        let t = &mut image[terminator_lba * SECTOR..(terminator_lba + 1) * SECTOR];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 1;
    }

    // --- Path tables (root only) ---------------------------------------
    {
        let l = &mut image[l_path_lba * SECTOR..l_path_lba * SECTOR + PATH_TABLE_LEN];
        l[0] = 1; // directory identifier length
        l[1] = 0; // extended attribute length
        l[2..6].copy_from_slice(&(root_lba as u32).to_le_bytes());
        l[6..8].copy_from_slice(&1u16.to_le_bytes()); // parent = itself
        l[8] = 0; // identifier for the root is a single null byte
        l[9] = 0; // padding to an even length

        let m = &mut image[m_path_lba * SECTOR..m_path_lba * SECTOR + PATH_TABLE_LEN];
        m[0] = 1;
        m[1] = 0;
        m[2..6].copy_from_slice(&(root_lba as u32).to_be_bytes());
        m[6..8].copy_from_slice(&1u16.to_be_bytes());
        m[8] = 0;
        m[9] = 0;
    }

    // --- Root directory extent -----------------------------------------
    {
        let dir = &mut image[root_lba * SECTOR..(root_lba + 1) * SECTOR];
        let mut off = 0;

        let dot = dir_record(&[0x00], root_lba as u32, dir_len as u32, true);
        dir[off..off + dot.len()].copy_from_slice(&dot);
        off += dot.len();

        let dotdot = dir_record(&[0x01], root_lba as u32, dir_len as u32, true);
        dir[off..off + dotdot.len()].copy_from_slice(&dotdot);
        off += dotdot.len();

        // Records must be sorted by identifier for a compliant image.
        let mut entries: Vec<(String, usize)> = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.identifier(), i))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (identifier, i) in entries {
            let rec = dir_record(
                identifier.as_bytes(),
                file_lbas[i] as u32,
                files[i].content.len() as u32,
                false,
            );
            dir[off..off + rec.len()].copy_from_slice(&rec);
            off += rec.len();
        }
    }

    // --- File contents ---------------------------------------------------
    for (i, f) in files.iter().enumerate() {
        let start = file_lbas[i] * SECTOR;
        image[start..start + f.content.len()].copy_from_slice(&f.content);
    }

    Ok(image)
}

/// Length of the single-entry path table (root only), padded to even.
const PATH_TABLE_LEN: usize = 10;

fn sectors_for(len: usize) -> usize {
    len.div_ceil(SECTOR).max(1)
}

fn dir_record_len(identifier_len: usize) -> usize {
    // 33 bytes of fixed fields plus the identifier, padded to an even length.
    let len = 33 + identifier_len;
    len + (len % 2)
}

fn dir_record(identifier: &[u8], lba: u32, size: u32, is_dir: bool) -> Vec<u8> {
    let len = dir_record_len(identifier.len());
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[1] = 0; // extended attribute record length
    r[2..6].copy_from_slice(&lba.to_le_bytes());
    r[6..10].copy_from_slice(&lba.to_be_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[14..18].copy_from_slice(&size.to_be_bytes());
    write_dir_datetime(&mut r[18..25]);
    r[25] = if is_dir { 0x02 } else { 0x00 };
    r[26] = 0; // file unit size
    r[27] = 0; // interleave gap
    r[28..30].copy_from_slice(&1u16.to_le_bytes()); // volume sequence number
    r[30..32].copy_from_slice(&1u16.to_be_bytes());
    r[32] = identifier.len() as u8;
    r[33..33 + identifier.len()].copy_from_slice(identifier);
    r
}

/// Write a space-padded strA/strD field.
fn write_str(field: &mut [u8], value: &str) {
    for b in field.iter_mut() {
        *b = b' ';
    }
    let bytes = value.as_bytes();
    let n = bytes.len().min(field.len());
    field[..n].copy_from_slice(&bytes[..n]);
}

/// 17-byte decimal date/time. Fixed so images are byte-reproducible.
fn write_datetime(field: &mut [u8]) {
    field[..16].copy_from_slice(b"2020010100000000");
    field[16] = 0; // GMT offset
}

/// 7-byte binary date/time used in directory records.
fn write_dir_datetime(field: &mut [u8]) {
    field[0] = 120; // years since 1900 => 2020
    field[1] = 1; // month
    field[2] = 1; // day
    field[3] = 0; // hour
    field[4] = 0; // minute
    field[5] = 0; // second
    field[6] = 0; // GMT offset in 15-minute intervals
}

fn write_both_u32(field: &mut [u8], value: u32) {
    field[..4].copy_from_slice(&value.to_le_bytes());
    field[4..8].copy_from_slice(&value.to_be_bytes());
}

fn write_both_u16(field: &mut [u8], value: u16) {
    field[..2].copy_from_slice(&value.to_le_bytes());
    field[2..4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Vec<IsoFile> {
        vec![
            IsoFile::new("user-data", "#cloud-config\nhostname: VM1\n"),
            IsoFile::new("meta-data", "instance-id: lnvps-vm-1\n"),
            IsoFile::new("network-config", "version: 2\n"),
        ]
    }

    #[test]
    fn image_has_iso9660_structure() -> Result<()> {
        let iso = build("cidata", &seed())?;

        assert_eq!(iso.len() % SECTOR, 0, "image must be sector aligned");
        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        assert_eq!(pvd[0], 1, "primary volume descriptor type");
        assert_eq!(&pvd[1..6], b"CD001", "ISO9660 magic");
        assert_eq!(pvd[6], 1, "descriptor version");
        assert_eq!(pvd[881], 1, "file structure version");

        // The terminator must follow the PVD.
        let term = &iso[(SYSTEM_AREA_SECTORS + 1) * SECTOR..];
        assert_eq!(term[0], 0xFF);
        assert_eq!(&term[1..6], b"CD001");
        Ok(())
    }

    #[test]
    fn volume_label_is_how_cloud_init_finds_the_seed() -> Result<()> {
        let iso = build("cidata", &seed())?;
        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        let label = std::str::from_utf8(&pvd[40..72])?.trim_end();
        // blkid reports this as LABEL; NoCloud looks for exactly "cidata".
        assert_eq!(label, "CIDATA");
        Ok(())
    }

    #[test]
    fn declared_size_matches_the_image() -> Result<()> {
        let iso = build("cidata", &seed())?;
        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        let sectors = u32::from_le_bytes(pvd[80..84].try_into()?) as usize;
        assert_eq!(
            sectors * SECTOR,
            iso.len(),
            "volume space size must cover the whole image"
        );
        // Both-endian fields must agree or a strict reader rejects the image.
        assert_eq!(sectors as u32, u32::from_be_bytes(pvd[84..88].try_into()?));
        Ok(())
    }

    #[test]
    fn file_contents_are_readable_at_their_extents() -> Result<()> {
        let files = seed();
        let iso = build("cidata", &files)?;

        // Walk the root directory the way a reader would.
        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        let root_lba = u32::from_le_bytes(pvd[158..162].try_into()?) as usize;
        let root_len = u32::from_le_bytes(pvd[166..170].try_into()?) as usize;

        let dir = &iso[root_lba * SECTOR..root_lba * SECTOR + root_len];
        let mut off = 0;
        let mut found = 0;
        while off < dir.len() && dir[off] != 0 {
            let rec_len = dir[off] as usize;
            let name_len = dir[off + 32] as usize;
            let name = String::from_utf8_lossy(&dir[off + 33..off + 33 + name_len]).to_string();
            let lba = u32::from_le_bytes(dir[off + 2..off + 6].try_into()?) as usize;
            let size = u32::from_le_bytes(dir[off + 10..off + 14].try_into()?) as usize;

            if let Some(expected) = files.iter().find(|f| f.identifier() == name) {
                let data = &iso[lba * SECTOR..lba * SECTOR + size];
                assert_eq!(data, expected.content.as_slice(), "content of {name}");
                found += 1;
            }
            off += rec_len;
        }
        assert_eq!(found, files.len(), "every file must be in the directory");
        Ok(())
    }

    #[test]
    fn identifiers_use_the_iso9660_form() {
        // Linux maps these back to lower case and strips the version, so the
        // guest sees the names cloud-init expects.
        assert_eq!(IsoFile::new("user-data", "").identifier(), "USER-DATA;1");
        assert_eq!(
            IsoFile::new("network-config", "").identifier(),
            "NETWORK-CONFIG;1"
        );
    }

    #[test]
    fn directory_records_are_sorted() -> Result<()> {
        let iso = build("cidata", &seed())?;
        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        let root_lba = u32::from_le_bytes(pvd[158..162].try_into()?) as usize;
        let dir = &iso[root_lba * SECTOR..(root_lba + 1) * SECTOR];

        let mut names = Vec::new();
        let mut off = 0;
        while off < SECTOR && dir[off] != 0 {
            let rec_len = dir[off] as usize;
            let name_len = dir[off + 32] as usize;
            let name = dir[off + 33..off + 33 + name_len].to_vec();
            // Skip the "." and ".." records.
            if name_len > 1 {
                names.push(name);
            }
            off += rec_len;
        }
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        Ok(())
    }

    #[test]
    fn output_is_deterministic() -> Result<()> {
        // Lets the caller skip re-uploading an unchanged seed.
        assert_eq!(build("cidata", &seed())?, build("cidata", &seed())?);
        Ok(())
    }

    #[test]
    fn large_files_span_multiple_sectors() -> Result<()> {
        let big = vec![b'x'; SECTOR * 3 + 17];
        let files = vec![IsoFile::new("user-data", big.clone())];
        let iso = build("cidata", &files)?;

        let pvd = &iso[SYSTEM_AREA_SECTORS * SECTOR..];
        let root_lba = u32::from_le_bytes(pvd[158..162].try_into()?) as usize;
        let dir = &iso[root_lba * SECTOR..(root_lba + 1) * SECTOR];
        let mut off = dir[0] as usize;
        off += dir[off] as usize; // skip "." and ".."
        let lba = u32::from_le_bytes(dir[off + 2..off + 6].try_into()?) as usize;
        let size = u32::from_le_bytes(dir[off + 10..off + 14].try_into()?) as usize;
        assert_eq!(size, big.len());
        assert_eq!(&iso[lba * SECTOR..lba * SECTOR + size], big.as_slice());
        Ok(())
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(build("cidata", &[]).is_err());
    }
}
