use crate::til::{read_dt, TAH};
use std::io::BufRead;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Bitfield {
    pub unsigned: bool,
    pub width: u16,
    pub nbytes: i32,
}

impl Bitfield {
    pub(crate) fn read<I: BufRead>(input: &mut I, metadata: u8) -> anyhow::Result<Self> {
        let nbytes = 1 << (metadata >> 4);
        let dt = read_dt(&mut *input)?;
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
