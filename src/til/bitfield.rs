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
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x472f3c print_til_type
        let nbytes = match metadata {
            super::flag::tf_complex::BTMT_BFLDI8 => 1,
            super::flag::tf_complex::BTMT_BFLDI16 => 2,
            super::flag::tf_complex::BTMT_BFLDI32 => 4,
            super::flag::tf_complex::BTMT_BFLDI64 => 8,
            _ => unreachable!(),
        };
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
