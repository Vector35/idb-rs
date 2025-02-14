use anyhow::{anyhow, ensure, Result};

use std::ops::Range;

use crate::ida_reader::IdaGenericUnpack;
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
    pub _flags: Vec<u32>,
}

impl ID1Section {
    pub(crate) fn read(
        input: &mut impl IdaGenericUnpack,
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

    fn read_inner(
        input: &mut impl IdaGenericUnpack,
        header: &IDBHeader,
    ) -> Result<Self> {
        // TODO pages are always 0x2000?
        const PAGE_SIZE: usize = 0x2000;
        let mut buf = vec![0; PAGE_SIZE];
        input.read_exact(&mut buf[..])?;
        let mut header_page = &buf[..];
        let version = VaVersion::read(&mut header_page)?;
        let (npages, seglist_raw) = match version {
            VaVersion::Va0
            | VaVersion::Va1
            | VaVersion::Va2
            | VaVersion::Va3
            | VaVersion::Va4 => {
                let nsegments: u16 =
                    bincode::deserialize_from(&mut header_page)?;
                let npages: u16 = bincode::deserialize_from(&mut header_page)?;
                ensure!(
                    npages > 0,
                    "Invalid number of pages, net at least one for the header"
                );
                // TODO section_size / npages == 0x2000

                // TODO the reference code uses the magic version, should it use
                // the version itself instead?
                let seglist: Vec<SegInfoVaNRaw> = if header
                    .magic_version
                    .is_64()
                {
                    (0..nsegments)
                        .map(|_| {
                            let start: u64 =
                                bincode::deserialize_from(&mut header_page)?;
                            let end: u64 =
                                bincode::deserialize_from(&mut header_page)?;
                            ensure!(start <= end);
                            let offset: u64 =
                                bincode::deserialize_from(&mut header_page)?;
                            Ok(SegInfoVaNRaw {
                                address: start..end,
                                offset,
                            })
                        })
                        .collect::<Result<_>>()?
                } else {
                    (0..nsegments)
                        .map(|_| {
                            let start: u32 =
                                bincode::deserialize_from(&mut header_page)?;
                            let end: u32 =
                                bincode::deserialize_from(&mut header_page)?;
                            ensure!(start <= end);
                            let offset: u32 =
                                bincode::deserialize_from(&mut header_page)?;
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
                let unknown_always3: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always3 == 3);
                let nsegments: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                let unknown_always2048: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always2048 == 2048);
                let npages: u32 = bincode::deserialize_from(&mut header_page)?;

                let seglist: Vec<Range<u64>> = (0..nsegments)
                    // TODO the reference code uses the magic version, should it use
                    // the version itself instead?
                    .map(|_| {
                        let (start, end) = match header.magic_version {
                            crate::IDBMagic::IDA0 | crate::IDBMagic::IDA1 => {
                                let startea: u32 = bincode::deserialize_from(
                                    &mut header_page,
                                )?;
                                let endea: u32 = bincode::deserialize_from(
                                    &mut header_page,
                                )?;
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
        ensure!(header_page.iter().all(|b| *b == 0));

        // sort segments by address
        let mut overlay_check = match &seglist_raw {
            SegInfoRaw::VaN(segs) => {
                segs.iter().map(|s| s.address.clone()).collect()
            }
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
        let required_size: u64 =
            overlay_check.iter().map(|s| (s.end - s.start) * 4).sum();
        let required_pages =
            required_size.div_ceil(u64::try_from(PAGE_SIZE).unwrap());
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
                            std::cmp::Ordering::Less => {
                                return Err(anyhow!("invalid offset"))
                            }
                            std::cmp::Ordering::Greater => {
                                // TODO can be any deleted sector contains randon data?
                                // skip intermidiate bytes, also ensuring they are all zeros
                                ensure_all_bytes_are_zero(
                                    std::io::Read::take(
                                        &mut *input,
                                        seg.offset - current_offset,
                                    ),
                                    &mut buf,
                                )?;
                                current_offset = seg.offset;
                            }
                            std::cmp::Ordering::Equal => {}
                        }
                        let len = seg.address.end - seg.address.start;
                        let (data, _flags) =
                            split_flags_data(&mut *input, len)?;
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
                        let (data, _flags) = split_flags_data(
                            &mut *input,
                            address.end - address.start,
                        )?;
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
        // deleted segment
        ignore_bytes(input, &mut buf)?;

        Ok(Self { seglist })
    }

    pub fn value_by_address(&self, address: u64) -> Option<u8> {
        for seg in &self.seglist {
            let addr_range =
                seg.offset..seg.offset + u64::try_from(seg.data.len()).unwrap();
            if addr_range.contains(&address) {
                return Some(
                    seg.data[usize::try_from(address - seg.offset).unwrap()],
                );
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
enum SegInfoRaw {
    VaN(Vec<SegInfoVaNRaw>),
    VaX(Vec<Range<u64>>),
}

#[derive(Clone, Debug)]
struct SegInfoVaNRaw {
    address: Range<u64>,
    offset: u64,
}

fn ensure_all_bytes_are_zero(
    mut input: impl IdaGenericUnpack,
    buf: &mut [u8],
) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(n) => ensure!(&buf[..n].iter().all(|b| *b == 0)),
            // ignore interrupts
            Err(ref e)
                if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn ignore_bytes(
    mut input: impl IdaGenericUnpack,
    buf: &mut [u8],
) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(_n) => {}
            // ignore interrupts
            Err(ref e)
                if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn split_flags_data(
    mut input: impl IdaGenericUnpack,
    len: u64,
) -> Result<(Vec<u8>, Vec<u32>)> {
    let len = usize::try_from(len).unwrap();
    let mut flags = Vec::with_capacity(len);
    let mut data = Vec::with_capacity(len);
    for _i in 0..len {
        let bytes = input.read_u32()?;
        data.push((bytes & 0xFF) as u8);
        flags.push(bytes >> 8);
    }
    Ok((data, flags))
}
