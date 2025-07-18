use anyhow::{ensure, Result};

use crate::ida_reader::{IdbRead, IdbReadKind};
use crate::{IDAKind, SectionReader, VaVersion};

#[derive(Debug, Clone)]
pub struct NamSection {
    pub names: Vec<u64>,
}

impl<K: IDAKind> SectionReader<K> for NamSection {
    type Result = Self;

    fn read_section<I: IdbReadKind<K>>(input: &mut I) -> Result<Self> {
        Self::read::<K>(input)
    }
}

impl NamSection {
    pub fn read<K: IDAKind>(input: &mut impl IdbRead) -> Result<Self> {
        // NOTE 64 should be enougth for all version, if a new version is implemented
        // review this value
        const MAX_HEADER_LEN: usize = 64;

        let mut buf = vec![0; MAX_HEADER_LEN];
        input.read_exact(&mut buf[..])?;
        let (npages, nnames, pagesize) = Self::read_header::<K>(&mut &buf[..])?;
        ensure!(
            npages >= K::Usize::from(1u8),
            "Invalid number of pages, need at least one page for the header"
        );

        // read the rest of the header page and ensure it's all zeros
        buf.resize(pagesize.try_into().unwrap(), 0);
        input.read_exact(&mut buf[MAX_HEADER_LEN..])?;
        ensure!(buf[MAX_HEADER_LEN..].iter().all(|b| *b == 0));

        let name_len: u32 = K::BYTES.into();
        // ensure pages dont break a name
        ensure!(pagesize % name_len == 0);
        // names fit inside the pages
        let size_required = nnames * K::Usize::from(name_len);
        let available_data =
            (npages - K::Usize::from(1u8)) * K::Usize::from(pagesize);
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
                if current_nnames == K::Usize::from(0u8) {
                    break;
                };
                let name_bytes =
                    <K::AddrBytes as crate::IDAUsizeBytes>::from_reader(
                        &mut input,
                    )
                    .map(|x| {
                        <K::Usize as num_traits::FromBytes>::from_le_bytes(&x)
                    });
                let Ok(name) = name_bytes else {
                    break;
                };
                names.push(name.into());
                current_nnames -= K::Usize::from(1u8);
            }
            // if anything is left, make sure it's all zeros
            ensure!(input.iter().all(|b| *b == 0));
        }

        assert!(current_nnames == K::Usize::from(0u8));
        Ok(Self { names })
    }

    fn read_header<K: IDAKind>(
        input: &mut impl IdbReadKind<K>,
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
