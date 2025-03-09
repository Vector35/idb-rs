use std::num::NonZeroU8;

use anyhow::Result;

use crate::ida_reader::IdbBufRead;

use super::TypeAttribute;

#[derive(Debug, Clone, Copy)]
pub struct Bitfield {
    pub unsigned: bool,
    // TODO what a 0 width bitfield means? The start of a new byte-field?
    // ntddk_win10.til
    // struct _D3DKMDT_DISPLAYMODE_FLAGS {
    //   unsigned __int32 ValidatedAgainstMonitorCaps : 1;
    //   unsigned __int32 RoundedFakeMode : 1;
    //   unsigned __int32 : 0;
    //   __int32 ModePruningReason : 4;
    //   unsigned __int32 Stereo : 1;
    //   unsigned __int32 AdvancedScanCapable : 1;
    //   unsigned __int32 PreferredTiming : 1;
    //   unsigned __int32 PhysicalModeSupported : 1;
    //   unsigned __int32 Reserved : 24;
    // };
    pub width: u16,
    pub nbytes: NonZeroU8,
}

impl Bitfield {
    pub(crate) fn read(
        input: &mut impl IdbBufRead,
        metadata: u8,
    ) -> Result<Self> {
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
        match input.read_tah()? {
            None => {}
            Some(TypeAttribute {
                tattr: _tattr,
                extended: _extended,
            }) => {
                #[cfg(feature = "restrictive")]
                anyhow::ensure!(
                    _tattr == 0,
                    "Unknown TypeAttribute {_tattr:x}"
                );
                #[cfg(feature = "restrictive")]
                anyhow::ensure!(
                    _extended.is_none(),
                    "Unknown TypeAttribute ext {_extended:x?}"
                );
            }
        }
        Ok(Self {
            unsigned,
            width,
            nbytes: nbytes.try_into().unwrap(),
        })
    }
}
