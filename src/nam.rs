use anyhow::{ensure, Result};
use byteorder::LE;

use crate::ida_reader::IdbRead;
use crate::{IDBSectionCompression, IdbInt, IdbKind, VaVersion};

#[derive(Debug, Clone)]
pub struct NamSection {
    pub names: Vec<u64>,
}

impl NamSection {
    pub(crate) fn read<K: IdbKind>(
        input: &mut impl IdbRead,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner::<K>(input),
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::read_inner::<K>(&mut input)
            }
        }
    }

    pub(crate) fn read_inner<K: IdbKind>(
        input: &mut impl IdbRead,
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
                let npages = K::Int::from_bytes_reader::<LE>(&mut header_page)?;
                let always0: u16 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always0 == 0);
                let mut nnames =
                    K::Int::from_bytes_reader::<LE>(&mut header_page)?;
                if K::Int::BYTES == 8 {
                    // TODO nnames / 2? Why?
                    nnames /= K::Int::from(2u8);
                }
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
                let npages = K::Int::from_bytes_reader::<LE>(&mut header_page)?;
                let always0: u32 = bincode::deserialize_from(&mut header_page)?;
                ensure!(always0 == 0);
                let mut nnames =
                    K::Int::from_bytes_reader::<LE>(&mut header_page)?;
                // TODO remove this HACK to find if the Type is u64
                if K::Int::BYTES == 8 {
                    // TODO nnames / 2? Why?
                    nnames /= K::Int::from(2u8);
                }
                (npages, nnames, DEFAULT_PAGE_SIZE.try_into().unwrap())
            }
        };
        ensure!(
            npages >= K::Int::from(1u8),
            "Invalid number of pages, need at least one page for the header"
        );

        // read the rest of the header page and ensure it's all zeros
        buf.resize(pagesize.try_into().unwrap(), 0);
        input.read_exact(&mut buf[64..])?;
        ensure!(buf[64..].iter().all(|b| *b == 0));

        let name_len: u32 = K::Int::BYTES.into();
        // ensure pages dont break a name
        ensure!(pagesize % name_len == 0);
        // names fit inside the pages
        let size_required = nnames * K::Int::from(name_len);
        let available_data =
            (npages - K::Int::from(1u8)) * K::Int::from(pagesize);
        ensure!(
            size_required <= available_data,
            "there is no enough size required {size_required} <= {available_data}"
        );

        let mut names = Vec::with_capacity(nnames.try_into().unwrap());
        let mut current_nnames = nnames;
        for _page in 1u64..npages.into() {
            input.read_exact(&mut buf)?;
            let mut input = &buf[..];
            loop {
                if current_nnames == K::Int::from(0u8) {
                    break;
                };
                let name = K::Int::from_bytes_reader::<LE>(&mut input);
                let Ok(name) = name else {
                    break;
                };
                names.push(name.into());
                current_nnames -= K::Int::from(1u8);
            }
            // if anything is left, make sure it's all zeros
            ensure!(input.iter().all(|b| *b == 0));
        }

        assert!(current_nnames == K::Int::from(0u8));
        Ok(Self { names })
    }
}
