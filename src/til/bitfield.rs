use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::TAH;

#[derive(Debug, Clone)]
pub struct Bitfield {
    pub unsigned: bool,
    pub width: u16,
    pub nbytes: i32,
}

impl Bitfield {
    pub(crate) fn read(input: &mut impl IdaGenericBufUnpack, metadata: u8) -> anyhow::Result<Self> {
        let nbytes = 1 << (metadata >> 4);
        let dt = input.read_dt()?;
        let width = dt >> 1;
        let unsigned = (dt & 1) > 0;
        let _tag = TAH::read(&mut *input)?;
        Ok(Self {
            unsigned,
            width,
            nbytes,
        })
    }
}
