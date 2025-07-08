use anyhow::{ensure, Context, Result};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::id0::{ID0Section, Netdelta, NetnodeIdx};
use crate::{Address, IDAKind};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive,
)]
#[repr(u8)]
pub enum ReferenceType {
    /// reserved
    V695Off8 = 0,
    /// 16bit full offset
    Off16 = 1,
    /// 32bit full offset
    Off32 = 2,
    /// low 8bits of 16bit offset
    Low8 = 3,
    /// low 16bits of 32bit offset
    Low16 = 4,
    /// high 8bits of 16bit offset
    High8 = 5,
    /// high 16bits of 32bit offset
    High16 = 6,
    /// obsolete
    V695Vhigh = 7,
    /// obsolete
    V695Vlow = 8,
    /// 64bit full offset
    Off64 = 9,
    /// 8bit full offset
    Off8 = 10,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceFlags(u32);
impl ReferenceFlags {
    fn from_raw(flags: u32) -> Result<ReferenceFlags> {
        #[cfg(feature = "restrictive")]
        ensure!(
            flags
                & !(REFINFO_TYPE
                    | REFINFO_RVAOFF
                    | REFINFO_PASTEND
                    | REFINFO_CUSTOM
                    | REFINFO_NOBASE
                    | REFINFO_SUBTRACT
                    | REFINFO_SIGNEDOP
                    | REFINFO_NO_ZEROS
                    | REFINFO_NO_ONES
                    | REFINFO_SELFREF)
                == 0,
            "Unknown flags use used by ReferenceInfo: {flags:X}",
        );
        ensure!(
            ReferenceType::try_from_primitive((flags & REFINFO_TYPE) as u8)
                .is_ok(),
            "Invalid flags ReferenceType: {flags:X}"
        );
        Ok(Self(flags))
    }

    pub fn into_primitive(self) -> u32 {
        self.0
    }

    pub fn ref_type(&self) -> ReferenceType {
        ReferenceType::try_from_primitive((self.0 & REFINFO_TYPE) as u8)
            .unwrap()
    }

    pub fn is_based_reference(&self) -> bool {
        self.0 & REFINFO_RVAOFF != 0
    }

    /// reference past an item
    pub fn is_past_an_item(&self) -> bool {
        self.0 & REFINFO_PASTEND != 0
    }

    /// custom reference
    pub fn is_custom(&self) -> bool {
        self.0 & REFINFO_CUSTOM != 0
    }

    pub fn is_nobase(&self) -> bool {
        self.0 & REFINFO_NOBASE != 0
    }

    pub fn is_base_subtraction(&self) -> bool {
        self.0 & REFINFO_SUBTRACT != 0
    }

    pub fn is_sign_extended(&self) -> bool {
        self.0 & REFINFO_SIGNEDOP != 0
    }

    pub fn is_zero_invalid(&self) -> bool {
        self.0 & REFINFO_NO_ZEROS != 0
    }

    pub fn is_max_invalid(&self) -> bool {
        self.0 & REFINFO_NO_ONES != 0
    }

    pub fn is_self_ref(&self) -> bool {
        self.0 & REFINFO_SELFREF != 0
    }
}

const REFINFO_TYPE: u32 = 0x000F;
const REFINFO_RVAOFF: u32 = 0x0010;
/// reference past an item
const REFINFO_PASTEND: u32 = 0x0020;
const REFINFO_CUSTOM: u32 = 0x0040;
const REFINFO_NOBASE: u32 = 0x0080;
/// the reference value is subtracted from the base value instead of (as usual) being added to it
const REFINFO_SUBTRACT: u32 = 0x0100;
/// the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
const REFINFO_SIGNEDOP: u32 = 0x0200;
/// an opval of 0 will be considered invalid
const REFINFO_NO_ZEROS: u32 = 0x0400;
/// an opval of ~0 will be considered invalid
const REFINFO_NO_ONES: u32 = 0x0800;
const REFINFO_SELFREF: u32 = 0x1000;

pub fn reference_info<K: IDAKind>(
    id0: &ID0Section<K>,
    netdelta: Netdelta<K>,
    address: Address<K>,
    operand: u8,
) -> Result<Option<ReferenceInfo<K>>> {
    // InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5bef30
    // TODO get_udm_by_tid and get_idainfo_by_udm
    let netnode = netdelta.ea2node(address);
    let alt = operand_to_alt(operand);
    let Some(value_raw) = id0.sup_value(
        netnode,
        alt.into(),
        super::flag::netnode::nn_res::ARRAY_SUP_TAG,
    ) else {
        return Ok(None);
    };
    let mut cursor = value_raw;
    let result = ReferenceInfo::from_raw(&mut cursor).with_context(|| {
        format!("Unable to deserialize Reference info for operand {operand} at {address:#X?}")
    })?;
    ensure!(
        cursor.is_empty(),
        "Extra data found after the ReferenceInfo at {address:X}"
    );
    Ok(Some(result))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceInfo<K: IDAKind> {
    pub target: Option<NetnodeIdx<K>>,
    pub base: Option<NetnodeIdx<K>>,
    pub tdelta: Option<K::Usize>,
    pub flags: ReferenceFlags,
}

impl<K: IDAKind> ReferenceInfo<K> {
    fn from_raw(
        data: &mut impl crate::ida_reader::IdbReadKind<K>,
    ) -> Result<Self> {
        let Some(mut flags) = data.read_u8_or_nothing()?.map(u32::from) else {
            #[cfg(feature = "restrictive")]
            return Err(anyhow::anyhow!("Empty Reference Info"));
            #[cfg(not(feature = "restrictive"))]
            return Ok(Self::default());
        };
        // NOTE don't confuse it with REFINFO_RVAOFF, REFINFO_PASTEND or
        // REFINFO_CUSTOM, those only come from flags_ext
        let target = (flags & 0x10 != 0)
            .then(|| data.unpack_usize().map(NetnodeIdx))
            .transpose()?;
        let base = (flags & 0x20 != 0)
            .then(|| data.unpack_usize().map(NetnodeIdx))
            .transpose()?;
        let tdelta = (flags & 0x40 != 0)
            .then(|| data.unpack_usize())
            .transpose()?;
        // NOTE first byte of flag is fully covered, not need to check rouge bits
        flags &= REFINFO_NOBASE | REFINFO_TYPE;

        if let Some(flags_ext_0) = data.read_u8_or_nothing()?.map(u32::from) {
            let flags_ext_1 =
                data.read_u8_or_nothing()?.map(u32::from).unwrap_or(0);
            let flags_ext = (flags_ext_1 << 8) | flags_ext_0;
            #[cfg(feature = "restrictive")]
            ensure!(
                (flags_ext << 4) & !0x1f70 == 0,
                "Invalid extended flags {flags_ext:X}"
            );
            flags |= (flags_ext << 4) & 0x1f70
        }
        let flags = ReferenceFlags::from_raw(flags)?;

        #[cfg(feature = "restrictive")]
        match (flags.is_based_reference(), flags.is_self_ref(), base) {
            (true, true, _) => {
                return Err(anyhow::anyhow!(
                "Reference Info flags set based and self ref at the same time"
            ))
            }
            (true, _, Some(_)) | (_, true, Some(_)) => {
                return Err(anyhow::anyhow!(
                "Reference Info flags set based/self-ref at the same time that it contains a base"
            ))
            }
            _ => {},
        }

        Ok(Self {
            target,
            base,
            tdelta,
            flags,
        })
    }
}

const fn operand_to_alt(operand: u8) -> u8 {
    // I could not find a cituation that `param_1 & 0x80 != 0`, use sub = 3
    // always instead
    //let value = operand & 0xf;
    //let flag = operand & 0x80 != 0;
    //let sub = if !flag { 3 } else { 0 };
    let sub = 3;
    match operand {
        0..3 => (operand + 0xc) - sub,
        3..8 => (operand + 0x1d) - (sub - 1),
        8..16 => (operand + 0x15) - sub,
        16.. => unreachable!(),
    }
}
