use anyhow::{ensure, Result};

use crate::ida_reader::IdaGenericUnpack;
use crate::{IDBHeader, IDBSectionCompression, VaVersion};

#[derive(Debug, Clone)]
pub struct NamSection {
    pub names: Vec<u64>,
}

impl NamSection {
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
    pub(crate) fn read_inner(
        input: &mut impl IdaGenericUnpack,
        header: &IDBHeader,
    ) -> Result<Self> {
        // NOTE 64 should be enougth for all version, if a new version is implemented
        // review this value
        const MAX_HEADER_LEN: usize = 64;
        const DEFAULT_PAGE_SIZE: usize = 0x2000;
        //assert!(MAX_HEADER_LEN < DEFAULT_PAGE_SIZE);

        let mut buf = vec![0; MAX_HEADER_LEN];
        input.read_exact(&mut buf[..])?;
        let mut header_page = &buf[..];
        let version = VaVersion::read(&mut header_page)?;

        let (npages, nnames, pagesize) = match version {
            VaVersion::Va0
            | VaVersion::Va1
            | VaVersion::Va2
            | VaVersion::Va3
            | VaVersion::Va4 => {
                let always1: u16 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always1 == 1);
                let npages: u64 = if header.magic_version.is_64() {
                    bincode::deserialize_from(&mut header_page)?
                } else {
                    bincode::deserialize_from::<_, u32>(&mut header_page)?
                        .into()
                };
                let always0: u16 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always0 == 0);
                let nnames: u64 = if header.magic_version.is_64() {
                    // TODO nnames / 2? Why?
                    bincode::deserialize_from::<_, u64>(&mut header_page)? / 2
                } else {
                    bincode::deserialize_from::<_, u32>(&mut header_page)?
                        .into()
                };
                let pagesize: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(pagesize >= 64);
                (npages, nnames, pagesize)
            }
            VaVersion::VaX => {
                let always3: u32 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always3 == 3);
                let one_or_zero: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!([0, 1].contains(&one_or_zero));
                // TODO always2048 have some relation to pagesize?
                let always2048: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(always2048 == 2048);
                let npages: u64 = if header.magic_version.is_64() {
                    bincode::deserialize_from(&mut header_page)?
                } else {
                    bincode::deserialize_from::<_, u32>(&mut header_page)?
                        .into()
                };
                let always0: u32 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always0 == 0);
                let nnames: u64 = if header.magic_version.is_64() {
                    // TODO nnames / 2? Why?
                    bincode::deserialize_from::<_, u64>(&mut header_page)? / 2
                } else {
                    bincode::deserialize_from::<_, u32>(&mut header_page)?
                        .into()
                };
                (npages, nnames, DEFAULT_PAGE_SIZE.try_into().unwrap())
            }
        };
        ensure!(
            npages >= 1,
            "Invalid number of pages, need at least one page for the header"
        );

        // read the rest of the header page and ensure it's all zeros
        buf.resize(pagesize.try_into().unwrap(), 0);
        input.read_exact(&mut buf[64..])?;
        ensure!(buf[64..].iter().all(|b| *b == 0));

        let name_len = if header.magic_version.is_64() { 8 } else { 4 };
        // ensure pages dont break a name
        ensure!(pagesize % name_len == 0);
        // names fit inside the pages
        let size_required = nnames * u64::from(name_len);
        let available_data = (npages - 1) * u64::from(pagesize);
        ensure!(
            size_required <= available_data,
            "there is no enough size required {size_required} <= {available_data}"
        );

        let mut names = Vec::with_capacity(nnames.try_into().unwrap());
        let mut current_nnames = nnames;
        for _page in 1..npages {
            input.read_exact(&mut buf)?;
            let mut input = &buf[..];
            loop {
                if current_nnames == 0 {
                    break;
                };
                let name = if header.magic_version.is_64() {
                    bincode::deserialize_from::<_, u64>(&mut input)
                } else {
                    bincode::deserialize_from::<_, u32>(&mut input)
                        .map(u64::from)
                };
                let Ok(name) = name else {
                    break;
                };
                names.push(name);
                current_nnames -= 1;
            }
            // if anything is left, make sure it's all zeros
            ensure!(input.iter().all(|b| *b == 0));
        }

        assert!(current_nnames == 0);
        Ok(Self { names })
    }
}
