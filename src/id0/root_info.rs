mod migration;

use std::ops::Range;

use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::{WrappingAdd, WrappingSub};

use crate::{ida_reader::IdbReadKind, Address, IDAKind, IDAUsize};

use super::*;

#[derive(Copy, Clone, Debug)]
pub struct RootNodeIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<RootNodeIdx<K>> for NetnodeIdx<K> {
    fn from(value: RootNodeIdx<K>) -> Self {
        Self(value.0)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Netdelta<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> Netdelta<K> {
    // TODO create a nodeidx_t type
    pub fn ea2node(&self, ea: Address<K>) -> NetnodeIdx<K> {
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1db9c0
        // TODO this don't work with old versions????
        if ea.as_raw().is_max() {
            NetnodeIdx(ea.as_raw())
        } else {
            NetnodeIdx(ea.as_raw().wrapping_add(&self.0))
        }
    }
    pub fn node2ea(&self, node: NetnodeIdx<K>) -> Address<K> {
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1dba10
        Address::from_raw(node.0.wrapping_sub(&self.0))
    }
}

#[derive(Clone, Debug)]
pub struct RootInfo<K: IDAKind> {
    // offset = 4, tag = 0x0
    pub version: u16,
    pub target: RootInfoTarget,
    // offset = 16, tag = 0x0
    pub genflags: Inffl,
    // offset = 18, tag = 0x0
    pub lflags: Lflg,
    // offset = 1c, tag = 0x0
    pub database_change_count: u32,
    pub input: RootInfoInput,
    // offset = 27, tag = 0x0, name = "special_segment_entry_size"
    pub special_segment_entry_size: u8,
    // offset = 28, tag = 0x0 and offset = 2c, tag = 0x0
    pub af: Af,
    pub addresses: RootInfoAddressed<K>,
    pub suspiciousness_limits: RootInfoSuspiciousnessLimits<K>,
    pub xrefs: RootInfoXrefs<K>,

    pub names: RootInfoNames,
    pub demangler: RootInfoDemangler<K>,
    // offset = c9, tag = 0x0
    pub listname: ListName,
    // offset = ca, tag = 0x0
    pub indent: u8,
    // offset = cb, tag = 0x0
    pub cmt_ident: u8,
    // offset = cc, tag = 0x0
    pub margin: u16,
    pub listing: RootInfoListing,
    // offset = d0, tag = 0x0
    pub outflag: OutputFlags,
    // offset = d4, tag = 0x0
    pub cmtflg: CommentOptions,
    // offset = d5, tag = 0x0
    pub limiter: DelimiterOptions,
    // offset = d6, tag = 0x0
    pub bin_prefix_size: u16,
    // offset = d8, tag = 0x0
    pub prefflag: LinePrefixOptions,
    pub strlits: RootInfoStrlits<K>,
    // offset = dc, tag = 0x0
    pub strtype: K::Usize,
    // offset = f8, tag = 0x0, name = "data_carousel"
    pub data_carousel: K::Usize,
    pub compiler: RootInfoCompiler,
    // offset = 10c, tag = 0x0
    pub abibits: AbiOptions,
    // offset = 110, tag = 0x0
    pub appcall_options: u32,
}

#[derive(Clone, Debug)]
pub struct RootInfoTarget {
    // offset = 6, tag = 0x0, name = "target.processor"
    pub processor: Vec<u8>,
    // offset = 26, tag = 0x0, name = "target.assembler"
    pub assembler: u8,
}

#[derive(Clone, Debug)]
pub struct RootInfoInput {
    // offset = 20, tag = 0x0, name = "input.file_format"
    pub file_format: FileType,
    // offset = 22, tag = 0x0, name = "input.operating_system"
    pub operating_system: u16,
    // offset = 24, tag = 0x0, name = "input.application_type"
    pub application_type: u16,
}

#[derive(Clone, Debug)]
pub struct RootInfoAddressed<K: IDAKind> {
    // offset = 30, tag = 0x0, name = "addresses.loading_base"
    pub loading_base: K::Usize,
    // offset = 38, tag = 0x0, name = "addresses.initial_ss"
    pub initial_ss: K::Usize,
    // offset = 40, tag = 0x0, name = "addresses.initial_cs"
    pub initial_cs: K::Usize,
    // offset = 48, tag = 0x0, name = "addresses.initial_ip"
    pub initial_ip: K::Usize,
    // offset = 50, tag = 0x0, name = "addresses.initial_ea"
    pub initial_ea: Address<K>,
    // offset = 58, tag = 0x0, name = "addresses.initial_sp"
    pub initial_sp: K::Usize,
    // offset = 60, tag = 0x0, name = "addresses.main_ea"
    pub main_ea: Address<K>,
    // offset = 68, tag = 0x0, name = "addresses.min_ea"
    pub min_ea: Address<K>,
    // offset = 70, tag = 0x0, name = "addresses.max_ea"
    pub max_ea: Address<K>,
    // offset = 78, tag = 0x0, name = "addresses.original_min_ea"
    pub original_min_ea: Address<K>,
    // offset = 80, tag = 0x0, name = "addresses.original_max_ea"
    pub original_max_ea: Address<K>,
    // offset = a0, tag = 0x0, name = "addresses.privrange"
    pub privrange: Range<Address<K>>,
    // offset = b0, tag = 0x0, name = "addresses.netdelta"
    pub netdelta: K::Usize,
}

#[derive(Clone, Debug)]
pub struct RootInfoSuspiciousnessLimits<K: IDAKind> {
    // offset = 88, tag = 0x0, name = "suspiciousness_limits.low"
    pub low: Option<Address<K>>,
    // offset = 90, tag = 0x0, name = "suspiciousness_limits.high"
    pub high: Option<Address<K>>,
}

#[derive(Clone, Debug)]
pub struct RootInfoXrefs<K: IDAKind> {
    // offset = 98, tag = 0x0, name = "xrefs.max_depth"
    pub max_depth: K::Usize,
    // offset = b8, tag = 0x0
    pub max_displayed_xrefs: u8,
    // offset = b9, tag = 0x0, name = "xrefs.max_displayed_type_xrefs"
    pub max_displayed_type_xrefs: u8,
    // offset = ba, tag = 0x0, name = "xrefs.max_displayed_strlit_xrefs"
    pub max_displayed_strlit_xrefs: u8,
    // offset = bb, tag = 0x0
    pub xrefflag: XRef,
}

#[derive(Clone, Debug)]
pub struct RootInfoNames {
    // offset = bc, tag = 0x0, name = "names.max_autogenerated_name_length"
    pub max_autogenerated_name_length: u16,
    // offset = be, tag = 0x0, name = "names.dummy_names"
    pub dummy_names: NameType,
}

#[derive(Clone, Debug)]
pub struct RootInfoDemangler<K: IDAKind> {
    // offset = c0, tag = 0x0, name = "demangler.short_form"
    pub short_form: K::Usize,
    // offset = c4, tag = 0x0, name = "demangler.long_form"
    pub long_form: K::Usize,
    // offset = c8, tag = 0x0
    pub name: DemName,
}

#[derive(Clone, Debug)]
pub struct RootInfoListing {
    // offset = ce, tag = 0x0, name = "listing.xref_margin"
    pub xref_margin: u16,
}

#[derive(Clone, Debug)]
pub struct RootInfoStrlits<K: IDAKind> {
    // offset = d9, tag = 0x0
    pub flags: StrLiteralFlags,
    // offset = da, tag = 0x0, name = "strlits.break"
    pub break_: u8,
    // offset = db, tag = 0x0, name = "strlits.leading_zeroes"
    pub leading_zeroes: u8,
    // offset = e0, tag = 0x0, name = "strlits.name_prefix"
    pub name_prefix: Vec<u8>,
    // offset = f0, tag = 0x0, name = "strlits.serial_number"
    pub serial_number: K::Usize,
}

#[derive(Clone, Debug)]
pub struct RootInfoCompiler {
    // offset = 100, tag = 0x0
    pub is_guessed: bool,
    pub compiler: Compiler,
    pub sizeof: RootInfoCompilerSizeof,
    // offset = 105, tag = 0x0, name = "compiler.alignment"
    pub alignment: u8,
}

#[derive(Clone, Debug)]
pub struct RootInfoCompilerSizeof {
    // offset = 101, tag = 0x0
    pub cm: u8,
    // offset = 102, tag = 0x0, name = "compiler.sizeof.int"
    pub int: u8,
    // offset = 103, tag = 0x0, name = "compiler.sizeof.bool"
    pub bool: u8,
    // offset = 104, tag = 0x0, name = "compiler.sizeof.enum"
    pub enum_: u8,
    // offset = 106, tag = 0x0, name = "compiler.sizeof.short"
    pub short: u8,
    // offset = 107, tag = 0x0, name = "compiler.sizeof.long"
    pub long: u8,
    // offset = 108, tag = 0x0, name = "compiler.sizeof.longlong"
    pub longlong: u8,
    // offset = 109, tag = 0x0, name = "compiler.sizeof.long_double"
    pub long_double: u8,
}

impl<K: IDAKind> RootInfo<K> {
    pub(crate) fn read(id0: &ID0Section<K>, data: &[u8]) -> Result<Self> {
        let mut input = data;
        let magic: [u8; 3] = bincode::deserialize_from(&mut input)?;
        let magic_old = match &magic[..] {
            b"ida" => {
                // ida have the \x00, IDA does not
                let zero: u8 = input.read_u8()?;
                ensure!(zero == 0);
                true
            }
            b"IDA" => false,
            _ => return Err(anyhow!("Invalid IDBParam Magic")),
        };
        let version = input.read_u16()?;

        // TODO tight those ranges up
        let param = match (magic_old, version) {
            (true, ..699) => Self::read_v1(&mut input, version)?,
            (false, ..699) => {
                Self::read_v2(&mut input, data.len(), 0, version)?
            }
            (false, 699..) => {
                let upgrade_700 = id0
                    .upgrade_700_idx()?
                    .map(|netnode| id0.upgrade_700(netnode))
                    .transpose()?
                    .map(|x| x.into_u64())
                    .unwrap_or(0);
                if upgrade_700 & 0x40 == 0 {
                    Self::read_v2(&mut input, data.len(), upgrade_700, version)?
                } else {
                    Self::read_v3(&mut input, upgrade_700, version)?
                }
            }
            (true, 699..) => panic!("old magic and new version {version}?"),
        };
        match version {
            // TODO old version may contain extra data at the end with unknown purpose
            ..=699 => {}
            700.. => ensure!(input.is_empty(), "Data left after the IDBParam",),
        }
        Ok(param)
    }

    pub fn read_v1(
        input: &mut impl IdbReadKind<K>,
        version: u16,
    ) -> Result<Self> {
        let mut processor = [0; 8];
        input.read_exact(&mut processor)?;
        // remove any \x00 that marks the end of the str
        let cpu_str_part = parse_maybe_cstr(&processor[..])
            .ok_or_else(|| anyhow!("Invalid RootInfo CStr cpu name"))?;
        let processor = processor[0..cpu_str_part.len()].to_vec();

        let genflags = Inffl::new(input.read_u16()?)?;
        let lflags = Lflg::new(input.read_u32()?)?;
        let database_change_count = input.read_u32()?;
        let file_format = FileType::from_value(input.read_u16()?)?;
        let operating_system = input.read_u16()?;
        let application_type = input.read_u16()?;
        let assembler = input.read_u8()?;
        let special_segment_entry_size = input.read_u8()?;
        let af1 = input.read_u32()?;
        let af2 = input.read_u32()?;
        let af = Af::new(af1, af2)?;
        let loading_base = input.read_usize()?;
        let initial_ss = input.read_usize()?;
        let initial_cs = input.read_usize()?;
        let initial_ip = input.read_usize()?;
        let initial_ea = input.read_usize()?;
        let initial_sp = input.read_usize()?;
        let main_ea = input.read_usize()?;
        let min_ea = input.read_usize()?;
        let max_ea = input.read_usize()?;
        let original_min_ea = input.read_usize()?;
        let original_max_ea = input.read_usize()?;
        let lowoff = input.read_usize()?;
        let highoff = input.read_usize()?;
        let max_depth = input.read_usize()?;
        let privrange_start = input.read_usize()?;
        let privrange_end = input.read_usize()?;
        let netdelta = input.read_usize()?;
        let max_displayed_xrefs = input.read_u8()?;
        let max_displayed_type_xrefs = input.read_u8()?;
        let max_displayed_strlit_xrefs = input.read_u8()?;
        let xrefflag = XRef::new(input.read_u8()?)?;
        let max_autogenerated_name_length = input.read_u16()?;
        let dummy_names = NameType::new(input.read_u8()?)
            .ok_or_else(|| anyhow!("Invalid RootInfo NameType"))?;
        let demangler_short_form = input.read_u32()?;
        let demangler_long_form = input.read_u32()?;
        let demangler_name = DemName::new(input.read_u8()?)?;
        let listname = ListName::new(input.read_u8()?)?;
        let indent = input.read_u8()?;
        let cmt_ident = input.read_u8()?;
        let margin = input.read_u16()?;
        let listing_xref_margin = input.read_u16()?;
        let outflag = OutputFlags::new(input.read_u32()?)?;
        let cmtflg = CommentOptions::new(input.read_u8()?);
        let limiter = DelimiterOptions::new(input.read_u8()?)?;
        let bin_prefix_size = input.read_u16()?;
        let prefflag = LinePrefixOptions::new(input.read_u8()?)?;
        let strlit_flags = StrLiteralFlags::new(input.read_u8()?)?;
        let strlit_break = input.read_u8()?;
        let strlit_leading_zeroes = input.read_u8()?;
        let strtype = input.read_u32()?;

        let mut strlit_name_prefix = [0; 16];
        input.read_exact(&mut strlit_name_prefix)?;
        let strlit_name_prefix = strlit_name_prefix.to_vec();

        let strlit_serial_number = input.read_usize()?;
        let data_carousel = input.read_usize()?;

        let cc_id_raw = input.read_u8()?;
        let cc_guessed = cc_id_raw & 0x80 != 0;
        #[cfg(feature = "restrictive")]
        let cc_id = Compiler::try_from(cc_id_raw & 0x7F)
            .map_err(|_| anyhow!("Invalid compiler id: {cc_id_raw}"))?;
        #[cfg(not(feature = "restrictive"))]
        let cc_id =
            Compiler::try_from(cc_id_raw & 0x7F).unwrap_or(Compiler::Unknown);

        let cc_cm = input.read_u8()?;
        let cc_size_i = input.read_u8()?;
        let cc_size_b = input.read_u8()?;
        let cc_size_e = input.read_u8()?;
        let cc_defalign = input.read_u8()?;
        let cc_size_s = input.read_u8()?;
        let cc_size_l = input.read_u8()?;
        let cc_size_ll = input.read_u8()?;
        let cc_size_ldbl = input.read_u8()?;
        let abibits = AbiOptions::new(input.read_u32()?)?;
        let appcall_options = input.read_u32()?;

        Ok(Self {
            version,
            target: RootInfoTarget {
                processor,
                assembler,
            },
            genflags,
            lflags,
            database_change_count,
            input: RootInfoInput {
                file_format,
                operating_system,
                application_type,
            },
            special_segment_entry_size,
            af,
            addresses: RootInfoAddressed {
                loading_base,
                initial_ss,
                initial_cs,
                initial_ip,
                initial_ea: Address::from_raw(initial_ea),
                initial_sp,
                main_ea: Address::from_raw(main_ea),
                min_ea: Address::from_raw(min_ea),
                max_ea: Address::from_raw(max_ea),
                original_min_ea: Address::from_raw(original_min_ea),
                original_max_ea: Address::from_raw(original_max_ea),
                privrange: Address::from_raw(privrange_start)
                    ..Address::from_raw(privrange_end),
                netdelta,
            },
            suspiciousness_limits: RootInfoSuspiciousnessLimits {
                low: (!lowoff.is_max()).then_some(Address::from_raw(lowoff)),
                high: (!highoff.is_max()).then_some(Address::from_raw(highoff)),
            },
            xrefs: RootInfoXrefs {
                max_depth,
                max_displayed_xrefs,
                max_displayed_type_xrefs,
                max_displayed_strlit_xrefs,
                xrefflag,
            },
            names: RootInfoNames {
                max_autogenerated_name_length,
                dummy_names,
            },
            demangler: RootInfoDemangler {
                short_form: demangler_short_form.into(),
                long_form: demangler_long_form.into(),
                name: demangler_name,
            },
            listname,
            indent,
            cmt_ident,
            margin,
            listing: RootInfoListing {
                xref_margin: listing_xref_margin,
            },
            outflag,
            cmtflg,
            limiter,
            bin_prefix_size,
            prefflag,
            strlits: RootInfoStrlits {
                flags: strlit_flags,
                break_: strlit_break,
                leading_zeroes: strlit_leading_zeroes,
                name_prefix: strlit_name_prefix,
                serial_number: strlit_serial_number,
            },
            strtype: strtype.into(),
            data_carousel,
            compiler: RootInfoCompiler {
                is_guessed: cc_guessed,
                compiler: cc_id,
                sizeof: RootInfoCompilerSizeof {
                    cm: cc_cm,
                    int: cc_size_i,
                    bool: cc_size_b,
                    enum_: cc_size_e,
                    short: cc_size_s,
                    long: cc_size_l,
                    longlong: cc_size_ll,
                    long_double: cc_size_ldbl,
                },
                alignment: cc_defalign,
            },
            abibits,
            appcall_options,
        })
    }

    pub fn read_v3(
        input: &mut impl IdbReadKind<K>,
        upgrade700: u64,
        version: u16,
    ) -> Result<Self> {
        let cpu_len = input.unpack_dd()?;
        let cpu_len = if cpu_len <= 16 {
            usize::try_from(cpu_len).unwrap()
        } else {
            #[cfg(feature = "restrictive")]
            return Err(anyhow!("Invalid CPU len value"));
            #[cfg(not(feature = "restrictive"))]
            16
        };
        let mut processor = vec![0; cpu_len];
        input.read_exact(&mut processor)?;
        // remove any \x00 that marks the end of the str
        let cpu_str_part = parse_maybe_cstr(&processor[..])
            .ok_or_else(|| anyhow!("Invalid RootInfo CStr cpu name"))?;
        processor.truncate(cpu_str_part.len());

        // NOTE in this version parse_* functions are used
        let genflags = Inffl::new(input.unpack_dw()?)?;
        let lflags = Lflg::new(input.unpack_dd()?)?;
        let database_change_count = input.unpack_dd()?;
        let file_format = FileType::from_value(input.unpack_dw()?)?;
        let operating_system = input.unpack_dw()?;
        let application_type = input.unpack_dw()?;
        let assembler = input.unpack_dw()?;
        ensure!(assembler <= u8::MAX.into());
        let assembler = (assembler & 0xFF) as u8;
        let special_segment_entry_size = input.read_u8()?;
        let af1 = input.unpack_dd()?;
        let af2 = input.unpack_dd()?;
        let af = Af::new(af1, af2)?;
        let loading_base = input.unpack_usize()?;
        let initial_ss = input.unpack_usize()?;
        let initial_cs = input.unpack_usize()?;
        let initial_ip = input.unpack_usize()?;
        let initial_ea = input.unpack_usize()?;
        let initial_sp = input.unpack_usize()?;
        let main_ea = input.unpack_usize()?;
        let min_ea = input.unpack_usize()?;
        let max_ea = input.unpack_usize()?;
        let original_min_ea = input.unpack_usize()?;
        let original_max_ea = input.unpack_usize()?;
        let lowoff = input.unpack_usize()?;
        let highoff = input.unpack_usize()?;
        let max_depth = input.unpack_usize()?;
        let privrange = input.unpack_address_range()?;
        let netdelta = input.unpack_usize()?;
        let max_displayed_xrefs = input.read_u8()?;
        let max_displayed_type_xrefs = input.read_u8()?;
        let max_displayed_strlit_xrefs = input.read_u8()?;
        let xrefflag = XRef::new(input.read_u8()?)?;
        let max_autogenerated_name_length = input.unpack_dw()?;

        if upgrade700 & 0x10000 == 0 {
            let _len = input.unpack_dd()?;
            let mut _unknown1 = vec![0u8; _len.try_into().unwrap()];
            input.read_exact(&mut _unknown1)?;
            let _unknown2 = input.read_u8()?;
        }

        let dummy_names = NameType::new(input.read_u8()?).ok_or_else(|| {
            anyhow!("Invalid RootInfo names.dummy_names value")
        })?;
        let demangler_short_form = input.unpack_dd()?;
        let demangler_long_form = input.unpack_dd()?;
        let demname = DemName::new(input.read_u8()?)?;
        let listname = ListName::new(input.read_u8()?)?;
        let indent = input.read_u8()?;
        let cmt_ident = input.read_u8()?;
        let margin = input.unpack_dw()?;
        let listing_xref_margin = input.unpack_dw()?;
        let outflag = OutputFlags::new(input.unpack_dd()?)?;
        let cmtflg = CommentOptions::new(input.read_u8()?);
        let limiter = DelimiterOptions::new(input.read_u8()?)?;
        let bin_prefix_size = input.unpack_dw()?;
        let prefflag = LinePrefixOptions::new(input.read_u8()?)?;
        let strlit_flags = StrLiteralFlags::new(input.read_u8()?)?;
        let strlit_break = input.read_u8()?;
        let strlit_leading_zeroes = input.read_u8()?;
        let strtype = input.unpack_dd()?;

        let strlit_name_prefix_len = input.unpack_dd()?;
        let strlit_name_prefix_len = if strlit_name_prefix_len <= 16 {
            strlit_name_prefix_len
        } else {
            #[cfg(feature = "restrictive")]
            return Err(anyhow!("Invalid CPU len value"));
            #[cfg(not(feature = "restrictive"))]
            16
        };
        let mut strlit_name_prefix =
            vec![0; strlit_name_prefix_len.try_into().unwrap()];
        input.read_exact(&mut strlit_name_prefix)?;
        let strlit_name_prefix = strlit_name_prefix.to_vec();

        let strlit_serial_number = input.unpack_usize()?;
        let data_carousel = input.unpack_usize()?;
        let cc_id_raw = input.read_u8()?;
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1a15e8
        let cc_guessed = cc_id_raw & 0x80 != 0;
        #[cfg(feature = "restrictive")]
        let cc_id = Compiler::try_from(cc_id_raw & 0x7F)
            .map_err(|_| anyhow!("Invalid compiler id: {cc_id_raw}"))?;
        #[cfg(not(feature = "restrictive"))]
        let cc_id =
            Compiler::try_from(cc_id_raw & 0x7F).unwrap_or(Compiler::Unknown);
        let cc_cm = input.read_u8()?;
        let cc_size_i = input.read_u8()?;
        let cc_size_b = input.read_u8()?;
        let cc_size_e = input.read_u8()?;
        let cc_defalign = input.read_u8()?;
        let cc_size_s = input.read_u8()?;
        let cc_size_l = input.read_u8()?;
        let cc_size_ll = input.read_u8()?;
        let cc_size_ldbl = input.read_u8()?;
        let abibits = AbiOptions::new(input.unpack_dd()?)?;
        let appcall_options = input.unpack_dd()?;

        Ok(Self {
            version,
            target: RootInfoTarget {
                processor,
                assembler,
            },
            genflags,
            lflags,
            database_change_count,
            input: RootInfoInput {
                file_format,
                operating_system,
                application_type,
            },
            special_segment_entry_size,
            af,
            addresses: RootInfoAddressed {
                loading_base,
                initial_ss,
                initial_cs,
                initial_ip,
                initial_ea: Address::from_raw(initial_ea),
                initial_sp,
                main_ea: Address::from_raw(main_ea),
                min_ea: Address::from_raw(min_ea),
                max_ea: Address::from_raw(max_ea),
                original_min_ea: Address::from_raw(original_min_ea),
                original_max_ea: Address::from_raw(original_max_ea),
                privrange: Address::from_raw(privrange.start)
                    ..Address::from_raw(privrange.end),
                netdelta,
            },
            suspiciousness_limits: RootInfoSuspiciousnessLimits {
                low: (!lowoff.is_max()).then_some(Address::from_raw(lowoff)),
                high: (!highoff.is_max()).then_some(Address::from_raw(highoff)),
            },
            xrefs: RootInfoXrefs {
                max_depth,
                max_displayed_xrefs,
                max_displayed_type_xrefs,
                max_displayed_strlit_xrefs,
                xrefflag,
            },
            names: RootInfoNames {
                max_autogenerated_name_length,
                dummy_names,
            },
            demangler: RootInfoDemangler {
                short_form: demangler_short_form.into(),
                long_form: demangler_long_form.into(),
                name: demname,
            },
            listname,
            indent,
            cmt_ident,
            margin,
            listing: RootInfoListing {
                xref_margin: listing_xref_margin,
            },
            outflag,
            cmtflg,
            limiter,
            bin_prefix_size,
            prefflag,
            strlits: RootInfoStrlits {
                flags: strlit_flags,
                break_: strlit_break,
                leading_zeroes: strlit_leading_zeroes,
                name_prefix: strlit_name_prefix,
                serial_number: strlit_serial_number,
            },
            strtype: strtype.into(),
            data_carousel,
            compiler: RootInfoCompiler {
                is_guessed: cc_guessed,
                compiler: cc_id,
                sizeof: RootInfoCompilerSizeof {
                    cm: cc_cm,
                    int: cc_size_i,
                    bool: cc_size_b,
                    enum_: cc_size_e,
                    short: cc_size_s,
                    long: cc_size_l,
                    longlong: cc_size_ll,
                    long_double: cc_size_ldbl,
                },
                alignment: cc_defalign,
            },
            abibits,
            appcall_options,
        })
    }

    pub fn netdelta(&self) -> Netdelta<K> {
        Netdelta(self.addresses.netdelta)
    }
}

/// General idainfo flags
#[derive(Debug, Clone, Copy)]
pub struct Inffl(u8);
impl Inffl {
    fn new(value: u16) -> Result<Self> {
        ensure!(value < 0x3000, "Invalid INFFL flag: 0x{:x}", value);
        // TODO check for unused flags?
        Ok(Self(value as u8))
    }

    /// Autoanalysis is enabled?
    pub fn is_auto_analysis_enabled(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// May use constructs not supported by the target assembler
    pub fn maybe_not_supported(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// loading an idc file that contains database info
    pub fn is_database_info_in_idc(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// do not store user info in the database
    pub fn is_user_info_not_in_database(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// (internal) temporary interdiction to modify the database
    pub fn is_read_only(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// check manual operands? (unused)
    pub fn is_manual_operands(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// allow non-matched operands? (unused)
    pub fn is_non_matched_operands(&self) -> bool {
        self.0 & 0x40 != 0
    }
    /// currently using graph options
    pub fn is_using_graph(&self) -> bool {
        self.0 & 0x80 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Lflg(u16);
impl Lflg {
    fn new(value: u32) -> Result<Self> {
        ensure!(
            value < u16::MAX as u32,
            "Invalid LFLG flag value: {value:#b}"
        );
        Ok(Self(value as u16))
    }

    /// decode floating point processor instructions?
    pub fn is_decode_float(&self) -> bool {
        self.0 & 0x0001 != 0
    }
    /// 32-bit program (or higher)?
    pub fn is_program_32b_or_bigger(&self) -> bool {
        self.0 & 0x0002 != 0
    }
    /// 64-bit program?
    pub fn is_program_64b(&self) -> bool {
        self.0 & 0x0004 != 0
    }
    /// Is dynamic library?
    pub fn is_dyn_lib(&self) -> bool {
        self.0 & 0x0008 != 0
    }
    /// treat ::REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
    pub fn is_flat_off32(&self) -> bool {
        self.0 & 0x0010 != 0
    }
    /// Byte order: is MSB first?
    pub fn is_big_endian(&self) -> bool {
        self.0 & 0x0020 != 0
    }
    /// Bit order of wide bytes: high byte first?
    pub fn is_wide_byte_first(&self) -> bool {
        self.0 & 0x0040 != 0
    }
    /// do not store input full path in debugger process options
    pub fn is_dbg_non_fullpath(&self) -> bool {
        self.0 & 0x0080 != 0
    }
    /// memory snapshot was taken?
    pub fn is_snapshot_taken(&self) -> bool {
        self.0 & 0x0100 != 0
    }
    /// pack the database?
    pub fn is_database_pack(&self) -> bool {
        self.0 & 0x0200 != 0
    }
    /// compress the database?
    pub fn is_database_compress(&self) -> bool {
        self.0 & 0x0400 != 0
    }
    /// is kernel mode binary?
    pub fn is_kernel_mode(&self) -> bool {
        self.0 & 0x0800 != 0
    }
    // TODO: Figure out what this flag is.
    /// Unknown flag found in `resources/idbs/v7.0b/kernel32.i64`.
    pub fn _unk_flag_0x2000(&self) -> bool {
        self.0 & 0x2000 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Af(u32, u8);
impl Af {
    fn new(value1: u32, value2: u32) -> Result<Self> {
        ensure!(value2 < 0x10, "Invalid AF2 value {value2:#x}");
        Ok(Self(value1, value2 as u8))
    }

    /// Trace execution flow
    pub fn is_code(&self) -> bool {
        self.0 & 0x00000001 != 0
    }
    /// Mark typical code sequences as code
    pub fn is_markcode(&self) -> bool {
        self.0 & 0x00000002 != 0
    }
    /// Locate and create jump tables
    pub fn is_jumptbl(&self) -> bool {
        self.0 & 0x00000004 != 0
    }
    /// Control flow to data segment is ignored
    pub fn is_purdat(&self) -> bool {
        self.0 & 0x00000008 != 0
    }
    /// Analyze and create all xrefs
    pub fn is_used(&self) -> bool {
        self.0 & 0x00000010 != 0
    }
    /// Delete instructions with no xrefs
    pub fn is_unk(&self) -> bool {
        self.0 & 0x00000020 != 0
    }

    /// Create function if data xref data->code32 exists
    pub fn is_procptr(&self) -> bool {
        self.0 & 0x00000040 != 0
    }
    /// Create functions if call is present
    pub fn is_proc(&self) -> bool {
        self.0 & 0x00000080 != 0
    }
    /// Create function tails
    pub fn is_ftail(&self) -> bool {
        self.0 & 0x00000100 != 0
    }
    /// Create stack variables
    pub fn is_lvar(&self) -> bool {
        self.0 & 0x00000200 != 0
    }
    /// Propagate stack argument information
    pub fn is_stkarg(&self) -> bool {
        self.0 & 0x00000400 != 0
    }
    /// Propagate register argument information
    pub fn is_regarg(&self) -> bool {
        self.0 & 0x00000800 != 0
    }
    /// Trace stack pointer
    pub fn is_trace(&self) -> bool {
        self.0 & 0x00001000 != 0
    }
    /// Perform full SP-analysis.
    pub fn is_versp(&self) -> bool {
        self.0 & 0x00002000 != 0
    }
    /// Perform 'no-return' analysis
    pub fn is_anoret(&self) -> bool {
        self.0 & 0x00004000 != 0
    }
    /// Try to guess member function types
    pub fn is_memfunc(&self) -> bool {
        self.0 & 0x00008000 != 0
    }
    /// Truncate functions upon code deletion
    pub fn is_trfunc(&self) -> bool {
        self.0 & 0x00010000 != 0
    }

    /// Create string literal if data xref exists
    pub fn is_strlit(&self) -> bool {
        self.0 & 0x00020000 != 0
    }
    /// Check for unicode strings
    pub fn is_chkuni(&self) -> bool {
        self.0 & 0x00040000 != 0
    }
    /// Create offsets and segments using fixup info
    pub fn is_fixup(&self) -> bool {
        self.0 & 0x00080000 != 0
    }
    /// Create offset if data xref to seg32 exists
    pub fn is_drefoff(&self) -> bool {
        self.0 & 0x00100000 != 0
    }
    /// Convert 32bit instruction operand to offset
    pub fn is_immoff(&self) -> bool {
        self.0 & 0x00200000 != 0
    }
    /// Automatically convert data to offsets
    pub fn is_datoff(&self) -> bool {
        self.0 & 0x00400000 != 0
    }

    /// Use flirt signatures
    pub fn is_flirt(&self) -> bool {
        self.0 & 0x00800000 != 0
    }
    /// Append a signature name comment for recognized anonymous library functions
    pub fn is_sigcmt(&self) -> bool {
        self.0 & 0x01000000 != 0
    }
    /// Allow recognition of several copies of the same function
    pub fn is_sigmlt(&self) -> bool {
        self.0 & 0x02000000 != 0
    }
    /// Automatically hide library functions
    pub fn is_hflirt(&self) -> bool {
        self.0 & 0x04000000 != 0
    }

    /// Rename jump functions as j_...
    pub fn is_jfunc(&self) -> bool {
        self.0 & 0x08000000 != 0
    }
    /// Rename empty functions as nullsub_...
    pub fn is_nullsub(&self) -> bool {
        self.0 & 0x10000000 != 0
    }

    /// Coagulate data segs at the final pass
    pub fn is_dodata(&self) -> bool {
        self.0 & 0x20000000 != 0
    }
    /// Coagulate code segs at the final pass
    pub fn is_docode(&self) -> bool {
        self.0 & 0x40000000 != 0
    }
    /// Final pass of analysis
    pub fn is_final(&self) -> bool {
        self.0 & 0x80000000 != 0
    }

    /// Handle EH information
    pub fn is_doeh(&self) -> bool {
        self.1 & 0x1 != 0
    }
    /// Handle RTTI information
    pub fn is_dortti(&self) -> bool {
        self.1 & 0x2 != 0
    }
    /// Try to combine several instructions
    pub fn is_macro(&self) -> bool {
        self.1 & 0x4 != 0
    }
    // TODO find the meaning of this flag
    //pub fn is_XXX(&self) -> bool {
    //    self.1 & 0x8 != 0
    //}
}

#[derive(Debug, Clone, Copy)]
pub struct XRef(u8);
impl XRef {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid XRef flag");
        Ok(Self(value))
    }
    /// show segments in xrefs?
    pub fn is_segxrf(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// show xref type marks?
    pub fn is_xrfmrk(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// show function offsets?
    pub fn is_xrffnc(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// show xref values? (otherwise-"...")
    pub fn is_xrfval(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NameType {
    RelOff,
    PtrOff,
    NamOff,
    RelEa,
    PtrEa,
    NamEa,
    Ea,
    Ea4,
    Ea8,
    Short,
    Serial,
}

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x7e6e20
impl NameType {
    fn new(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::RelOff,
            1 => Self::PtrOff,
            2 => Self::NamOff,
            3 => Self::RelEa,
            4 => Self::PtrEa,
            5 => Self::NamEa,
            6 => Self::Ea,
            7 => Self::Ea4,
            8 => Self::Ea8,
            9 => Self::Short,
            10 => Self::Serial,
            _ => return None,
        })
    }
}

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x7e6de0
#[derive(Debug, Clone, Copy)]
pub enum DemNamesForm {
    /// display demangled names as comments
    Cmnt,
    /// display demangled names as regular names
    Name,
    /// don't display demangled names
    None,
}

#[derive(Clone, Copy, Debug)]
pub struct DemName(u8);
impl DemName {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid DemName flag");
        ensure!(value != 0x3);
        Ok(Self(value))
    }
    pub fn name_form(&self) -> DemNamesForm {
        match self.0 & 0x3 {
            0 => DemNamesForm::Cmnt,
            1 => DemNamesForm::Name,
            2 => DemNamesForm::None,
            _ => unreachable!(),
        }
    }

    /// assume gcc3 names (valid for gnu compiler)
    pub fn is_gcc3(&self) -> bool {
        self.0 & 0x4 != 0
    }

    /// override type info
    pub fn override_type_info(&self) -> bool {
        self.0 & 0x8 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ListName(u8);
impl ListName {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid ListName flag");
        Ok(Self(value))
    }
    /// include normal names
    pub fn is_normal(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// include public names
    pub fn is_public(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// include autogenerated names
    pub fn is_auto(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// include weak names
    pub fn is_weak(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OutputFlags(u16);
impl OutputFlags {
    fn new(value: u32) -> Result<Self> {
        ensure!(value < 0x800);
        Ok(Self(value as u16))
    }
    /// Display void marks?
    pub fn show_void(&self) -> bool {
        self.0 & 0x002 != 0
    }
    /// Display autoanalysis indicator?
    pub fn show_auto(&self) -> bool {
        self.0 & 0x004 != 0
    }
    /// Generate empty lines?
    pub fn gen_null(&self) -> bool {
        self.0 & 0x010 != 0
    }
    /// Show line prefixes?
    pub fn show_pref(&self) -> bool {
        self.0 & 0x020 != 0
    }
    /// line prefixes with segment name?
    pub fn is_pref_seg(&self) -> bool {
        self.0 & 0x040 != 0
    }
    /// generate leading zeroes in numbers
    pub fn gen_lzero(&self) -> bool {
        self.0 & 0x080 != 0
    }
    /// Generate 'org' directives?
    pub fn gen_org(&self) -> bool {
        self.0 & 0x100 != 0
    }
    /// Generate 'assume' directives?
    pub fn gen_assume(&self) -> bool {
        self.0 & 0x200 != 0
    }
    /// Generate try/catch directives?
    pub fn gen_tryblks(&self) -> bool {
        self.0 & 0x400 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CommentOptions(u8);
impl CommentOptions {
    fn new(value: u8) -> Self {
        Self(value)
    }
    /// show repeatable comments?
    pub fn is_rptcmt(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// comment all lines?
    pub fn is_allcmt(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// no comments at all
    pub fn is_nocmt(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// show source line numbers
    pub fn is_linnum(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// testida.idc is running
    pub fn is_testmode(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// show hidden instructions
    pub fn is_shhid_item(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// show hidden functions
    pub fn is_shhid_func(&self) -> bool {
        self.0 & 0x40 != 0
    }
    /// show hidden segments
    pub fn is_shhid_segm(&self) -> bool {
        self.0 & 0x80 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DelimiterOptions(u8);
impl DelimiterOptions {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x08);
        Ok(Self(value))
    }
    /// thin borders
    pub fn is_thin(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// thick borders
    pub fn is_thick(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// empty lines at the end of basic blocks
    pub fn is_empty(&self) -> bool {
        self.0 & 0x04 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LinePrefixOptions(u8);
impl LinePrefixOptions {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid LinePrefixOptions");
        Ok(Self(value))
    }
    /// show segment addresses?
    pub fn is_segadr(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// show function offsets?
    pub fn is_fncoff(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// show stack pointer?
    pub fn is_stack(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// truncate instruction bytes if they would need more than 1 line
    pub fn is_pfxtrunc(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StrLiteralFlags(u8);
impl StrLiteralFlags {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x40);
        Ok(Self(value))
    }
    /// generate names?
    pub fn is_gen(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// names have 'autogenerated' bit?
    pub fn is_auto(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// generate serial names?
    pub fn is_serial(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// unicode strings are present?
    pub fn is_unicode(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// generate auto comment for string references?
    pub fn is_comment(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// preserve case of strings for identifiers
    pub fn is_savecase(&self) -> bool {
        self.0 & 0x20 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AbiOptions(u16);
impl AbiOptions {
    fn new(value: u32) -> Result<Self> {
        ensure!(value < 0x400);
        Ok(Self(value as u16))
    }
    /// 4 byte alignment for 8byte scalars (__int64/double) inside structures?
    pub fn is_8align4(&self) -> bool {
        self.0 & 0x001 != 0
    }
    /// do not align stack arguments to stack slots
    pub fn is_pack_stkargs(&self) -> bool {
        self.0 & 0x002 != 0
    }
    /// use natural type alignment for argument if the alignment exceeds native word size.
    /// (e.g. __int64 argument should be 8byte aligned on some 32bit platforms)
    pub fn is_bigarg_align(&self) -> bool {
        self.0 & 0x004 != 0
    }
    /// long double arguments are passed on stack
    pub fn is_stack_ldbl(&self) -> bool {
        self.0 & 0x008 != 0
    }
    /// varargs are always passed on stack (even when there are free registers)
    pub fn is_stack_varargs(&self) -> bool {
        self.0 & 0x010 != 0
    }
    /// use the floating-point register set
    pub fn is_hard_float(&self) -> bool {
        self.0 & 0x020 != 0
    }
    /// compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
    pub fn is_set_by_user(&self) -> bool {
        self.0 & 0x040 != 0
    }
    /// use gcc layout for udts (used for mingw)
    pub fn is_gcc_layout(&self) -> bool {
        self.0 & 0x080 != 0
    }
    /// register arguments are mapped to stack area (and consume stack slots)
    pub fn is_map_stkargs(&self) -> bool {
        self.0 & 0x100 != 0
    }
    /// use natural type alignment for an argument even if its alignment exceeds double
    /// native word size (the default is to use double word max).
    /// e.g. if this bit is set, __int128 has 16-byte alignment.
    /// This bit is not used by ida yet
    pub fn is_hugearg_align(&self) -> bool {
        self.0 & 0x200 != 0
    }
}

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x7e6ee0
#[derive(Debug, Clone)]
pub enum FileType {
    Raw,
    MsdosDriver,
    Ne,
    IntelHex,
    Mex,
    Lx,
    Le,
    Nlm,
    Coff,
    Pe,
    Omf,
    RRecords,
    Zip,
    Omflib,
    Ar,
    LoaderSpecific,
    Elf,
    W32run,
    Aout,
    Palmpilot,
    MsdosExe,
    MsdosCom,
    Aixar,
    Macho,
    Psxobj,
}

impl FileType {
    fn from_value(value: u16) -> Result<Self> {
        Ok(match value {
            0x2 => Self::Raw,
            0x3 => Self::MsdosDriver,
            0x4 => Self::Ne,
            0x5 => Self::IntelHex,
            0x6 => Self::Mex,
            0x7 => Self::Lx,
            0x8 => Self::Le,
            0x9 => Self::Nlm,
            0xA => Self::Coff,
            0xB => Self::Pe,
            0xC => Self::Omf,
            0xD => Self::RRecords,
            0xE => Self::Zip,
            0xF => Self::Omflib,
            0x10 => Self::Ar,
            0x11 => Self::LoaderSpecific,
            0x12 => Self::Elf,
            0x13 => Self::W32run,
            0x14 => Self::Aout,
            0x15 => Self::Palmpilot,
            // 0x0 is for older ida version.
            0x0 | 0x16 => Self::MsdosExe,
            // 0x1 is for older ida version.
            0x1 | 0x17 => Self::MsdosCom,
            0x18 => Self::Aixar,
            0x19 => Self::Macho,
            0x1A => Self::Psxobj,
            _ => {
                return Err(anyhow!("Invalid RootInfo File Format {value:#X}"))
            }
        })
    }
}

use crate::til::flag::cm::comp::*;
// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x7e6cc0
// InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x3a03c0
#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Compiler {
    Unknown = COMP_UNK,
    VisualStudio = COMP_MS,
    Borland = COMP_BC,
    Watcom = COMP_WATCOM,
    Gnu = COMP_GNU,
    VisualAge = COMP_VISAGE,
    Delphi = COMP_BP,

    Unsure = COMP_UNSURE,
}
