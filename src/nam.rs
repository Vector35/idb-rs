use anyhow::{ensure, Result};
use serde::Serialize;

use crate::ida_reader::{IdbBufRead, IdbReadKind};
use crate::{Address, IDAKind, IDAUsize, SectionReader, VaVersion};

#[derive(Debug, Clone, Serialize)]
pub struct NamSection<K: IDAKind> {
    pub names: Vec<Address<K>>,
}

impl<K: IDAKind> SectionReader<K> for NamSection<K> {
    type Result = Self;

    fn read_section<I: IdbReadKind<K> + IdbBufRead>(
        input: &mut I,
        _magic: crate::IDBMagic,
    ) -> Result<Self> {
        Self::read(input)
    }
}

impl<K: IDAKind> NamSection<K> {
    pub fn read<I: IdbReadKind<K> + IdbBufRead>(input: &mut I) -> Result<Self> {
        // NOTE 64 should be enougth for all version, if a new version is implemented
        // review this value
        const MAX_HEADER_LEN: usize = 64;

        let mut buf = vec![0; MAX_HEADER_LEN];
        input.read_exact(&mut buf[..])?;
        let mut header_cursor = &buf[..];
        let (npages, nnames, pagesize) = Self::read_header(&mut header_cursor)?;
        let header_read_len = buf.len() - header_cursor.len();
        ensure!(
            npages >= K::Usize::from(1u8),
            "Invalid number of pages, need at least one page for the header"
        );

        // read the rest of the header page and ensure it's all zeros
        buf.resize(pagesize.try_into().unwrap(), 0);
        input.read_exact(&mut buf[MAX_HEADER_LEN..])?;
        ensure!(buf[header_read_len..].iter().all(|b| *b == 0));

        // ensure pages dont break a name
        ensure!(pagesize % u32::from(K::BYTES) == 0);
        let name_len: K::Usize = K::BYTES.into();
        // names fit inside the pages
        let size_required = nnames * name_len;
        let available_data =
            (npages - K::Usize::from(1u8)) * K::Usize::from(pagesize);
        ensure!(
            size_required <= available_data,
            "there is no enough size required {size_required} <= {available_data}"
        );

        let names = (0..nnames.into_u64())
            .map(|_i| input.read_usize().map(Address::from_raw))
            .collect::<Result<_, _>>()?;
        // if anything is left after the page, make sure it's all zeros
        #[cfg(feature = "restrictive")]
        if available_data > size_required {
            ensure!((available_data - size_required) % name_len == 0u8.into());
            let len_unused = (available_data - size_required) / name_len;
            for _i in 0..len_unused.into_u64() {
                // TODO we can allow those values to contain garbage, allow it?
                let unused_value = input.read_usize()?;
                ensure!(unused_value == 0u8.into(), "Unparsed value in Nam");
            }
        }

        Ok(Self { names })
    }

    pub fn read_header<I: IdbReadKind<K> + IdbBufRead>(
        input: &mut I,
    ) -> Result<(K::Usize, K::Usize, u32)> {
        const DEFAULT_PAGE_SIZE: usize = 0x2000;
        //assert!(MAX_HEADER_LEN < DEFAULT_PAGE_SIZE);
        match VaVersion::read(&mut *input)? {
            VaVersion::Va0
            | VaVersion::Va1
            | VaVersion::Va2
            | VaVersion::Va3
            | VaVersion::Va4 => {
                let always1 = input.read_u16()?;
                ensure!(always1 == 1);
                let npages = input.read_usize()?;
                let always0 = input.read_u16()?;
                ensure!(always0 == 0);
                let mut nnames = input.read_usize()?;
                if K::BYTES == 8 {
                    // TODO nnames / 2? Why?
                    nnames /= K::Usize::from(2u8);
                }
                let pagesize = input.read_u32()?;
                ensure!(pagesize >= 64);
                Ok((npages, nnames, pagesize))
            }
            VaVersion::VaX => {
                let always3 = input.read_u32()?;
                ensure!(always3 == 3);
                let one_or_zero = input.read_u32()?;
                ensure!([0, 1].contains(&one_or_zero));
                // TODO always2048 have some relation to pagesize?
                let always2048 = input.read_u32()?;
                ensure!(always2048 == 2048);
                let npages = input.read_usize()?;
                let always0 = input.read_u32()?;
                ensure!(always0 == 0);
                let mut nnames = input.read_usize()?;
                // TODO remove this HACK to find if the Type is u64
                if K::BYTES == 8 {
                    // TODO nnames / 2? Why?
                    nnames /= K::Usize::from(2u8);
                }
                Ok((npages, nnames, DEFAULT_PAGE_SIZE.try_into().unwrap()))
            }
        }
    }
}
