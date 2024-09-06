use anyhow::{anyhow, ensure, Result};

use std::io::{Cursor, Read};
use std::ops::Range;

use crate::{IDBHeader, IDBSectionCompression, VaVersion};

#[derive(Clone, Debug)]
pub struct ID1Section {
    pub seglist: Vec<SegInfo>,
}

#[derive(Clone, Debug)]
pub struct SegInfo {
    pub offset: u64,
    pub data: Vec<u8>,
    // TODO find a way to decode this data
    _flags: Vec<u32>,
}

impl ID1Section {
    pub(crate) fn read<I: Read>(
        input: &mut I,
        header: &IDBHeader,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input, header),
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::read_inner(&mut input, header)
            }
        }
    }

    fn read_inner<I: Read>(input: &mut I, header: &IDBHeader) -> Result<Self> {
        // TODO pages are always 0x2000?
        const PAGE_SIZE: usize = 0x2000;
        let mut buf = vec![0; PAGE_SIZE];
        input.read_exact(&mut buf[..])?;
        let mut header_page = Cursor::new(&buf);
        let version = VaVersion::read(&mut header_page)?;
        let (npages, seglist_raw) = match version {
            VaVersion::Va0 | VaVersion::Va1 | VaVersion::Va2 | VaVersion::Va3 | VaVersion::Va4 => {
                let nsegments: u16 = bincode::deserialize_from(&mut header_page)?;
                let npages: u16 = bincode::deserialize_from(&mut header_page)?;
                ensure!(
                    npages > 0,
                    "Invalid number of pages, net at least one for the header"
                );
                // TODO section_size / npages == 0x2000

                // TODO the reference code uses the magic version, should it use
                // the version itself instead?
                let seglist: Vec<SegInfoVaNRaw> = if header.magic_version.is_64() {
                    (0..nsegments)
                        .map(|_| {
                            let start: u64 = bincode::deserialize_from(&mut header_page)?;
                            let end: u64 = bincode::deserialize_from(&mut header_page)?;
                            ensure!(start <= end);
                            let offset: u64 = bincode::deserialize_from(&mut header_page)?;
                            Ok(SegInfoVaNRaw {
                                address: start..end,
                                offset,
                            })
                        })
                        .collect::<Result<_>>()?
                } else {
                    (0..nsegments)
                        .map(|_| {
                            let start: u32 = bincode::deserialize_from(&mut header_page)?;
                            let end: u32 = bincode::deserialize_from(&mut header_page)?;
                            ensure!(start <= end);
                            let offset: u32 = bincode::deserialize_from(&mut header_page)?;
                            Ok(SegInfoVaNRaw {
                                address: start.into()..end.into(),
                                offset: offset.into(),
                            })
                        })
                        .collect::<Result<_>>()?
                };
                (u32::from(npages), SegInfoRaw::VaN(seglist))
            }
            VaVersion::VaX => {
                let unknown_always3: u32 = bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always3 == 3);
                let nsegments: u32 = bincode::deserialize_from(&mut header_page)?;
                let unknown_always2048: u32 = bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always2048 == 2048);
                let npages: u32 = bincode::deserialize_from(&mut header_page)?;

                let seglist: Vec<Range<u64>> = (0..nsegments)
                    // TODO the reference code uses the magic version, should it use
                    // the version itself instead?
                    .map(|_| {
                        let (start, end) = match header.magic_version {
                            crate::IDBMagic::IDA0 | crate::IDBMagic::IDA1 => {
                                let startea: u32 = bincode::deserialize_from(&mut header_page)?;
                                let endea: u32 = bincode::deserialize_from(&mut header_page)?;
                                (startea.into(), endea.into())
                            }
                            crate::IDBMagic::IDA2 => (
                                bincode::deserialize_from(&mut header_page)?,
                                bincode::deserialize_from(&mut header_page)?,
                            ),
                        };
                        ensure!(start <= end);
                        Ok(start..end)
                    })
                    .collect::<Result<_>>()?;
                (npages, SegInfoRaw::VaX(seglist))
            }
        };
        // make sure the unused values a all zero
        ensure!(buf[header_page.position().try_into().unwrap()..]
            .iter()
            .all(|b| *b == 0));
        drop(header_page);

        // sort segments by address
        let mut overlay_check = match &seglist_raw {
            SegInfoRaw::VaN(segs) => segs.iter().map(|s| s.address.clone()).collect(),
            SegInfoRaw::VaX(segs) => segs.clone(),
        };
        overlay_check.sort_unstable_by_key(|s| s.start);

        // make sure segments don't overlap
        let overlap = overlay_check.windows(2).any(|segs| {
            let [seg1, seg2] = segs else { unreachable!() };
            seg1.end >= seg2.start
        });
        ensure!(!overlap);

        // make sure the data fits the available pages
        let required_size: u64 = overlay_check.iter().map(|s| (s.end - s.start) * 4).sum();
        let required_pages = required_size.div_ceil(u64::try_from(PAGE_SIZE).unwrap());
        // TODO if the extra data at the end of the section is identified, review replacing <= with ==
        // -1 because the first page is always the header
        ensure!(required_pages <= u64::from(npages - 1));

        // populated the seglist data using the pages
        let seglist = match seglist_raw {
            SegInfoRaw::VaN(mut segs) => {
                // sort it by disk offset, so we can read one after the other
                segs.sort_unstable_by_key(|s| s.offset);
                let mut current_offset = u64::try_from(PAGE_SIZE).unwrap();
                segs.into_iter()
                    .map(|seg| {
                        // skip any gaps
                        match seg.offset.cmp(&current_offset) {
                            std::cmp::Ordering::Less => return Err(anyhow!("invalid offset")),
                            std::cmp::Ordering::Greater => {
                                // TODO can be any deleted sector contains randon data?
                                // skip intermidiate bytes, also ensuring they are all zeros
                                ensure_all_bytes_are_zero(
                                    input.take(seg.offset - current_offset),
                                    &mut buf,
                                )?;
                                current_offset = seg.offset;
                            }
                            std::cmp::Ordering::Equal => {}
                        }
                        let len = seg.address.end - seg.address.start;
                        let (data, _flags) = split_flags_data(&mut *input, len)?;
                        current_offset += len * 4;
                        Ok(SegInfo {
                            offset: seg.address.start,
                            data,
                            _flags,
                        })
                    })
                    .collect::<Result<_>>()?
            }
            SegInfoRaw::VaX(segs) => {
                // the data for the segments are stored sequentialy in disk
                segs.into_iter()
                    .map(|address| {
                        let (data, _flags) =
                            split_flags_data(&mut *input, address.end - address.start)?;
                        Ok(SegInfo {
                            offset: address.start,
                            data,
                            _flags,
                        })
                    })
                    .collect::<Result<_>>()?
            }
        };

        //// ensure the rest of the data (page alignment) is just zeros
        //ensure_all_bytes_are_zero(input, &mut buf)?;
        // TODO sometimes there some extra data with unknown meaning, maybe it's just a
        // delete segment
        ignore_bytes(input, &mut buf)?;

        Ok(Self { seglist })
    }
}

#[derive(Clone, Debug)]
pub enum SegInfoRaw {
    VaN(Vec<SegInfoVaNRaw>),
    VaX(Vec<Range<u64>>),
}

#[derive(Clone, Debug)]
pub struct SegInfoVaNRaw {
    address: Range<u64>,
    offset: u64,
}

fn ensure_all_bytes_are_zero<I: Read>(mut input: I, buf: &mut [u8]) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(n) => ensure!(&buf[..n].iter().all(|b| *b == 0)),
            // ignore interrupts
            Err(ref e) if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn ignore_bytes<I: Read>(mut input: I, buf: &mut [u8]) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(_n) => {}
            // ignore interrupts
            Err(ref e) if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn split_flags_data<I: Read>(mut input: I, len: u64) -> Result<(Vec<u8>, Vec<u32>)> {
    let len = usize::try_from(len).unwrap();
    let mut flags = vec![0u32; len];
    // SAFETY: don't worry &mut[u32] is compatible with &mut[u8] with len * 4
    input.read_exact(unsafe {
        &mut *core::slice::from_raw_parts_mut(flags.as_mut_ptr() as *mut u8, len * 4)
    })?;
    // extract the bytes into other vector and leave the flags there
    let data = flags
        .iter_mut()
        .map(|b| {
            let value = (*b & 0xFF) as u8;
            *b = *b >> 8;
            value
        })
        .collect();
    Ok((data, flags))
}
