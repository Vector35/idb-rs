use anyhow::Result;

use std::collections::HashMap;
use std::num::{NonZeroU32, NonZeroU8};
use std::ops::Range;

use super::*;

#[derive(Clone, Debug)]
pub struct Segment {
    pub address: Range<u64>,
    pub name: Option<Vec<u8>>,
    // TODO class String
    _class_id: u64,
    /// This field is IDP dependent.
    /// You may keep your information about the segment here
    pub orgbase: u64,
    /// See more at [flags](https://hex-rays.com//products/ida/support/sdkdoc/group___s_f_l__.html)
    pub flags: SegmentFlag,
    /// [Segment alignment codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sa__.html)
    pub align: SegmentAlignment,
    /// [Segment combination codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sc__.html)
    pub comb: SegmentCombination,
    /// [Segment permissions](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g_p_e_r_m__.html) (0 means no information)
    pub perm: Option<SegmentPermission>,
    /// Number of bits in the segment addressing.
    pub bitness: SegmentBitness,
    /// Segment type (see [Segment types](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g__.html)).
    /// The kernel treats different segment types differently. Segments marked with '*' contain no instructions or data and are not declared as 'segments' in the disassembly.
    pub seg_type: SegmentType,
    /// Segment selector - should be unique.
    /// You can't change this field after creating the segment.
    /// Exception: 16bit OMF files may have several segments with the same selector,
    /// but this is not good (no way to denote a segment exactly) so it should be fixed in
    /// the future.
    pub selector: u64,
    /// Default segment register values.
    /// First element of this array keeps information about value of [processor_t::reg_first_sreg](https://hex-rays.com//products/ida/support/sdkdoc/structprocessor__t.html#a4206e35bf99d211c18d53bd1035eb2e3)
    pub defsr: [u64; 16],
    /// the segment color
    pub color: u32,
}

impl Segment {
    pub(crate) fn read(
        value: &[u8],
        is_64: bool,
        names: Option<&HashMap<NonZeroU32, Vec<u8>>>,
        id0: &ID0Section,
    ) -> Result<Self> {
        let mut cursor = IdaUnpacker::new(value, is_64);
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x330684
        let startea = cursor.unpack_usize()?;
        let size = cursor.unpack_usize()?;
        let name_id = cursor.unpack_usize()?;
        let name_id = NonZeroU32::new(u32::try_from(name_id).unwrap());
        // TODO: I'm assuming name_id == 0 means no name, but maybe I'm wrong
        let name = name_id
            .map(|name_id| {
                // TODO I think this is dependent on the version, and not on availability
                if let Some(names) = names {
                    names.get(&name_id).map(Vec::to_owned).ok_or_else(|| {
                        anyhow!("Not found name for segment {name_id}")
                    })
                } else {
                    // if there is no names, AKA `$ segstrings`, search for the key directly
                    id0.name_by_index(name_id.get().into()).map(<[u8]>::to_vec)
                }
            })
            .transpose();
        let name = name?;
        // TODO AKA [sclass](https://hex-rays.com//products/ida/support/sdkdoc/classsegment__t.html)
        // I don't know what is this value or what it represents
        let _class_id = cursor.unpack_usize()?;
        let orgbase = cursor.unpack_usize()?;
        let flags = SegmentFlag::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Flag value"))?;
        let align = SegmentAlignment::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Alignment value"))?;
        let comb = SegmentCombination::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Combination value"))?;
        let perm = SegmentPermission::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Permission value"))?;
        let bitness = SegmentBitness::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Bitness value"))?;
        let seg_type = SegmentType::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Type value"))?;
        let selector = cursor.unpack_usize()?;
        let defsr: [_; 16] = (0..16)
            .map(|_| cursor.unpack_usize())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let color = cursor.unpack_dd()?;

        // TODO maybe new versions include extra information and thid check fails
        ensure!(cursor.inner().is_empty());
        Ok(Segment {
            address: startea..startea + size,
            name,
            _class_id,
            orgbase,
            flags,
            align,
            comb,
            perm,
            bitness,
            seg_type,
            selector,
            defsr,
            color,
        })
    }
}

#[derive(Clone, Copy)]
pub struct SegmentFlag(u8);
impl SegmentFlag {
    fn from_raw(value: u32) -> Option<Self> {
        if value > 0x80 - 1 {
            return None;
        }
        Some(Self(value as u8))
    }

    /// IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    pub fn is_comorg(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// Orgbase is present? (IDP dependent field)
    pub fn is_orgbase_present(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// Is the segment hidden?
    pub fn is_hidden(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// Is the segment created for the debugger?.
    ///
    /// Such segments are temporary and do not have permanent flags.
    pub fn is_debug(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// Is the segment created by the loader?
    pub fn is_created_by_loader(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// Hide segment type (do not print it in the listing)
    pub fn is_hide_type(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// Header segment (do not create offsets to it in the disassembly)
    pub fn is_header(&self) -> bool {
        self.0 & 0x40 != 0
    }
}

impl core::fmt::Debug for SegmentFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SegmentFlag(")?;
        let flags: Vec<&str> = self
            .is_comorg()
            .then_some("Comorg")
            .into_iter()
            .chain(self.is_orgbase_present().then_some("Orgbase"))
            .chain(self.is_hidden().then_some("Hidden"))
            .chain(self.is_debug().then_some("Debug"))
            .chain(self.is_created_by_loader().then_some("LoaderCreated"))
            .chain(self.is_hide_type().then_some("HideType"))
            .chain(self.is_header().then_some("Header"))
            .collect();
        write!(f, "{}", flags.join(","))?;
        write!(f, ")")
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentAlignment {
    /// Absolute segment.
    Abs,
    /// Relocatable, byte aligned.
    RelByte,
    /// Relocatable, word (2-byte) aligned.
    RelWord,
    /// Relocatable, paragraph (16-byte) aligned.
    RelPara,
    /// Relocatable, aligned on 256-byte boundary.
    RelPage,
    /// Relocatable, aligned on a double word (4-byte) boundary.
    RelDble,
    /// This value is used by the PharLap OMF for page (4K) alignment.
    ///
    /// It is not supported by LINK.
    Rel4K,
    /// Segment group.
    Group,
    /// 32 bytes
    Rel32Bytes,
    /// 64 bytes
    Rel64Bytes,
    /// 8 bytes
    RelQword,
    /// 128 bytes
    Rel128Bytes,
    /// 512 bytes
    Rel512Bytes,
    /// 1024 bytes
    Rel1024Bytes,
    /// 2048 bytes
    Rel2048Bytes,
}

impl SegmentAlignment {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Abs),
            1 => Some(Self::RelByte),
            2 => Some(Self::RelWord),
            3 => Some(Self::RelPara),
            4 => Some(Self::RelPage),
            5 => Some(Self::RelDble),
            6 => Some(Self::Rel4K),
            7 => Some(Self::Group),
            8 => Some(Self::Rel32Bytes),
            9 => Some(Self::Rel64Bytes),
            10 => Some(Self::RelQword),
            11 => Some(Self::Rel128Bytes),
            12 => Some(Self::Rel512Bytes),
            13 => Some(Self::Rel1024Bytes),
            14 => Some(Self::Rel2048Bytes),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentCombination {
    /// Private.
    ///
    /// Do not combine with any other program segment.
    Priv,
    /// Segment group.
    Group,
    /// Public.
    ///
    /// Combine by appending at an offset that meets the alignment requirement.
    Pub,
    /// As defined by Microsoft, same as C=2 (public).
    Pub2,
    /// Stack.
    Stack,
    /// Common. Combine by overlay using maximum size.
    ///
    /// Combine as for C=2. This combine type forces byte alignment.
    Common,
    /// As defined by Microsoft, same as C=2 (public).
    Pub3,
}

impl SegmentCombination {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Priv),
            1 => Some(Self::Group),
            2 => Some(Self::Pub),
            4 => Some(Self::Pub2),
            5 => Some(Self::Stack),
            6 => Some(Self::Common),
            7 => Some(Self::Pub3),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SegmentPermission(NonZeroU8);

impl SegmentPermission {
    fn from_raw(value: u32) -> Option<Option<Self>> {
        if value > 7 {
            return None;
        }
        Some(NonZeroU8::new(value as u8).map(Self))
    }

    pub fn can_execute(&self) -> bool {
        self.0.get() & 1 != 0
    }

    pub fn can_write(&self) -> bool {
        self.0.get() & 2 != 0
    }

    pub fn can_read(&self) -> bool {
        self.0.get() & 4 != 0
    }
}

impl core::fmt::Debug for SegmentPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SegmentPermission(")?;
        if self.can_read() {
            write!(f, "R")?;
        }
        if self.can_write() {
            write!(f, "W")?;
        }
        if self.can_execute() {
            write!(f, "X")?;
        }
        write!(f, ")")
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentBitness {
    S16Bits,
    S32Bits,
    S64Bits,
}

impl SegmentBitness {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::S16Bits),
            1 => Some(Self::S32Bits),
            2 => Some(Self::S64Bits),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentType {
    /// unknown type, no assumptions
    Norm,
    /// segment with 'extern' definitions.
    ///
    /// no instructions are allowed
    Xtrn,
    /// code segment
    Code,
    /// data segment
    Data,
    /// java: implementation segment
    Imp,
    /// group of segments
    Grp,
    /// zero-length segment
    Null,
    /// undefined segment type (not used)
    Undf,
    /// uninitialized segment
    Bss,
    /// segment with definitions of absolute symbols
    Abssym,
    /// segment with communal definitions
    Comm,
    /// internal processor memory & sfr (8051)
    Imem,
}

impl SegmentType {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Norm),
            1 => Some(Self::Xtrn),
            2 => Some(Self::Code),
            3 => Some(Self::Data),
            4 => Some(Self::Imp),
            6 => Some(Self::Grp),
            7 => Some(Self::Null),
            8 => Some(Self::Undf),
            9 => Some(Self::Bss),
            10 => Some(Self::Abssym),
            11 => Some(Self::Comm),
            12 => Some(Self::Imem),
            _ => None,
        }
    }
}
