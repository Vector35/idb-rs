use std::io::Read;

use anyhow::Result;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::ida_reader::IdaUnpack;

use super::*;

#[derive(Clone, Debug)]
pub enum IDBRootInfo<'a> {
    /// it's just the "Root Node" String
    RootNodeName,
    InputFile(&'a [u8]),
    Crc(u64),
    ImageBase(u64),
    OpenCount(u64),
    CreatedDate(u64),
    Version(u64),
    Md5(&'a [u8; 16]),
    VersionString(&'a str),
    Sha256(&'a [u8; 32]),
    IDAInfo(Box<IDBParam>),
    Unknown(&'a ID0Entry),
}

#[derive(Clone, Debug)]
pub enum IDBParam {
    V1(IDBParam1),
    V2(IDBParam2),
}

#[derive(Clone, Debug)]
pub struct IDBParam1 {
    pub version: u16,
    pub cpu: Vec<u8>,
    pub lflags: u8,
    pub demnames: u8,
    pub filetype: u16,
    pub fcoresize: u64,
    pub corestart: u64,
    pub ostype: u16,
    pub apptype: u16,
    pub startsp: u64,
    pub af: u16,
    pub startip: u64,
    pub startea: u64,
    pub minea: u64,
    pub maxea: u64,
    pub ominea: u64,
    pub omaxea: u64,
    pub lowoff: u64,
    pub highoff: u64,
    pub maxref: u64,
    pub ascii_break: u8,
    pub wide_high_byte_first: u8,
    pub indent: u8,
    pub comment: u8,
    pub xrefnum: u8,
    pub entab: u8,
    pub specsegs: u8,
    pub voids: u8,
    pub showauto: u8,
    pub auto: u8,
    pub border: u8,
    pub null: u8,
    pub genflags: u8,
    pub showpref: u8,
    pub prefseg: u8,
    pub asmtype: u8,
    pub baseaddr: u64,
    pub xrefs: u8,
    pub binpref: u16,
    pub cmtflag: u8,
    pub nametype: u8,
    pub showbads: u8,
    pub prefflag: u8,
    pub packbase: u8,
    pub asciiflags: u8,
    pub listnames: u8,
    pub asciiprefs: [u8; 16],
    pub asciisernum: u64,
    pub asciizeroes: u8,
    pub tribyte_order: u8,
    pub mf: u8,
    pub org: u8,
    pub assume: u8,
    pub checkarg: u8,
    // offset 131
    pub start_ss: u64,
    pub start_cs: u64,
    pub main: u64,
    pub short_dn: u64,
    pub long_dn: u64,
    pub datatypes: u64,
    pub strtype: u64,
    pub af2: u16,
    pub namelen: u16,
    pub margin: u16,
    pub lenxref: u16,
    pub lprefix: [u8; 16],
    pub lprefixlen: u8,
    pub compiler: u8,
    pub model: u8,
    pub sizeof_int: u8,
    pub sizeof_bool: u8,
    pub sizeof_enum: u8,
    pub sizeof_algn: u8,
    pub sizeof_short: u8,
    pub sizeof_long: u8,
    pub sizeof_llong: u8,
    pub change_counter: u32,
    pub sizeof_ldbl: u8,
    pub abiname: [u8; 16],
    pub abibits: u32,
    pub refcmts: u8,
}

#[derive(Clone, Debug)]
pub struct IDBParam2 {
    pub version: u16,
    pub cpu: Vec<u8>,
    pub genflags: Inffl,
    pub lflags: Lflg,
    pub database_change_count: u32,
    pub filetype: FileType,
    pub ostype: u16,
    pub apptype: u16,
    pub asmtype: u8,
    pub specsegs: u8,
    pub af: Af,
    pub baseaddr: u64,
    pub start_ss: u64,
    pub start_cs: u64,
    pub start_ip: u64,
    pub start_ea: u64,
    pub start_sp: u64,
    pub main: u64,
    pub min_ea: u64,
    pub max_ea: u64,
    pub omin_ea: u64,
    pub omax_ea: u64,
    pub lowoff: u64,
    pub highoff: u64,
    pub maxref: u64,
    pub privrange_start_ea: u64,
    pub privrange_end_ea: u64,
    pub netdelta: u64,
    pub xrefnum: u8,
    pub type_xrefnum: u8,
    pub refcmtnum: u8,
    pub xrefflag: XRef,
    pub max_autoname_len: u16,
    pub nametype: NameType,
    pub short_demnames: u32,
    pub long_demnames: u32,
    pub demnames: DemName,
    pub listnames: ListName,
    pub indent: u8,
    pub cmt_ident: u8,
    pub margin: u16,
    pub lenxref: u16,
    pub outflags: OutputFlags,
    pub cmtflg: CommentOptions,
    pub limiter: DelimiterOptions,
    pub bin_prefix_size: u16,
    pub prefflag: LinePrefixOptions,
    pub strlit_flags: StrLiteralFlags,
    pub strlit_break: u8,
    pub strlit_zeroes: u8,
    pub strtype: u32,
    pub strlit_pref: String,
    pub strlit_sernum: u64,
    pub datatypes: u64,
    pub cc_id: Compiler,
    pub cc_cm: u8,
    pub cc_size_i: u8,
    pub cc_size_b: u8,
    pub cc_size_e: u8,
    pub cc_defalign: u8,
    pub cc_size_s: u8,
    pub cc_size_l: u8,
    pub cc_size_ll: u8,
    pub cc_size_ldbl: u8,
    pub abibits: AbiOptions,
    pub appcall_options: u32,
}

impl IDBParam {
    pub(crate) fn read(data: &[u8], is_64: bool) -> Result<Self> {
        let mut input = IdaUnpacker::new(data, is_64);
        let magic: [u8; 3] = bincode::deserialize_from(&mut input)?;
        let magic_old = match &magic[..] {
            b"ida" => {
                let zero: u8 = input.read_u8()?;
                ensure!(zero == 0);
                true
            }
            b"IDA" => false,
            _ => return Err(anyhow!("Invalid IDBParam Magic")),
        };
        let version: u16 = bincode::deserialize_from(&mut input)?;

        let cpu_len = match (magic_old, version) {
            (_, ..=699) => 8,
            (true, 700..) => 16,
            (false, 700..) => {
                let cpu_len: u8 = bincode::deserialize_from(&mut input)?;
                cpu_len.into()
            }
        };
        let mut cpu = vec![0; cpu_len];
        input.read_exact(&mut cpu)?;
        // remove any \x00 that marks the end of the str
        let cpu_str_part = parse_maybe_cstr(&cpu[..])
            .ok_or_else(|| anyhow!("Invalid RootInfo CStr cpu name"))?;
        cpu.truncate(cpu_str_part.len());

        // TODO tight those ranges up
        let param = match version {
            ..=699 => Self::read_v1(&mut input, version, cpu)?,
            700.. => Self::read_v2(&mut input, magic_old, version, cpu)?,
        };
        match version {
            // TODO old version may contain extra data at the end with unknown purpose
            ..=699 => {}
            700.. => ensure!(
                input.inner().is_empty(),
                "Data left after the IDBParam",
            ),
        }
        Ok(param)
    }

    pub(crate) fn read_v1(
        mut input: &mut impl IdaUnpack,
        version: u16,
        cpu: Vec<u8>,
    ) -> Result<Self> {
        let lflags: u8 = bincode::deserialize_from(&mut input)?;
        let demnames: u8 = bincode::deserialize_from(&mut input)?;
        let filetype: u16 = bincode::deserialize_from(&mut input)?;
        let fcoresize: u64 = input.read_word()?;
        let corestart: u64 = input.read_word()?;
        let ostype: u16 = bincode::deserialize_from(&mut input)?;
        let apptype: u16 = bincode::deserialize_from(&mut input)?;
        let startsp: u64 = input.read_word()?;
        let af: u16 = bincode::deserialize_from(&mut input)?;
        let startip: u64 = input.read_word()?;
        let startea: u64 = input.read_word()?;
        let minea: u64 = input.read_word()?;
        let maxea: u64 = input.read_word()?;
        let ominea: u64 = input.read_word()?;
        let omaxea: u64 = input.read_word()?;
        let lowoff: u64 = input.read_word()?;
        let highoff: u64 = input.read_word()?;
        let maxref: u64 = input.read_word()?;
        let ascii_break: u8 = bincode::deserialize_from(&mut input)?;
        let wide_high_byte_first: u8 = bincode::deserialize_from(&mut input)?;
        let indent: u8 = bincode::deserialize_from(&mut input)?;
        let comment: u8 = bincode::deserialize_from(&mut input)?;
        let xrefnum: u8 = bincode::deserialize_from(&mut input)?;
        let entab: u8 = bincode::deserialize_from(&mut input)?;
        let specsegs: u8 = bincode::deserialize_from(&mut input)?;
        let voids: u8 = bincode::deserialize_from(&mut input)?;
        let _unkownw: u8 = bincode::deserialize_from(&mut input)?;
        let showauto: u8 = bincode::deserialize_from(&mut input)?;
        let auto: u8 = bincode::deserialize_from(&mut input)?;
        let border: u8 = bincode::deserialize_from(&mut input)?;
        let null: u8 = bincode::deserialize_from(&mut input)?;
        let genflags: u8 = bincode::deserialize_from(&mut input)?;
        let showpref: u8 = bincode::deserialize_from(&mut input)?;
        let prefseg: u8 = bincode::deserialize_from(&mut input)?;
        let asmtype: u8 = bincode::deserialize_from(&mut input)?;
        let baseaddr: u64 = input.read_word()?;
        let xrefs: u8 = bincode::deserialize_from(&mut input)?;
        let binpref: u16 = bincode::deserialize_from(&mut input)?;
        let cmtflag: u8 = bincode::deserialize_from(&mut input)?;
        let nametype: u8 = bincode::deserialize_from(&mut input)?;
        let showbads: u8 = bincode::deserialize_from(&mut input)?;
        let prefflag: u8 = bincode::deserialize_from(&mut input)?;
        let packbase: u8 = bincode::deserialize_from(&mut input)?;
        let asciiflags: u8 = bincode::deserialize_from(&mut input)?;
        let listnames: u8 = bincode::deserialize_from(&mut input)?;
        let asciiprefs: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let asciisernum: u64 = input.read_word()?;
        let asciizeroes: u8 = bincode::deserialize_from(&mut input)?;
        let _unknown2: u16 = bincode::deserialize_from(&mut input)?;
        let tribyte_order: u8 = bincode::deserialize_from(&mut input)?;
        let mf: u8 = bincode::deserialize_from(&mut input)?;
        let org: u8 = bincode::deserialize_from(&mut input)?;
        let assume: u8 = bincode::deserialize_from(&mut input)?;
        let checkarg: u8 = bincode::deserialize_from(&mut input)?;
        // offset 131
        let start_ss: u64 = input.read_word()?;
        let start_cs: u64 = input.read_word()?;
        let main: u64 = input.read_word()?;
        let short_dn: u64 = input.read_word()?;
        let long_dn: u64 = input.read_word()?;
        let datatypes: u64 = input.read_word()?;
        let strtype: u64 = input.read_word()?;
        let af2: u16 = bincode::deserialize_from(&mut input)?;
        let namelen: u16 = bincode::deserialize_from(&mut input)?;
        let margin: u16 = bincode::deserialize_from(&mut input)?;
        let lenxref: u16 = bincode::deserialize_from(&mut input)?;
        let lprefix: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let lprefixlen: u8 = bincode::deserialize_from(&mut input)?;
        let compiler: u8 = bincode::deserialize_from(&mut input)?;
        let model: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_int: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_bool: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_enum: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_algn: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_short: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_long: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_llong: u8 = bincode::deserialize_from(&mut input)?;
        let change_counter: u32 = bincode::deserialize_from(&mut input)?;
        let sizeof_ldbl: u8 = bincode::deserialize_from(&mut input)?;
        let _unknown_3: u32 = bincode::deserialize_from(&mut input)?;
        let abiname: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let abibits: u32 = bincode::deserialize_from(&mut input)?;
        let refcmts: u8 = bincode::deserialize_from(&mut input)?;

        Ok(IDBParam::V1(IDBParam1 {
            version,
            cpu,
            lflags,
            demnames,
            filetype,
            fcoresize,
            corestart,
            ostype,
            apptype,
            startsp,
            af,
            startip,
            startea,
            minea,
            maxea,
            ominea,
            omaxea,
            lowoff,
            highoff,
            maxref,
            ascii_break,
            wide_high_byte_first,
            indent,
            comment,
            xrefnum,
            entab,
            specsegs,
            voids,
            showauto,
            auto,
            border,
            null,
            genflags,
            showpref,
            prefseg,
            asmtype,
            baseaddr,
            xrefs,
            binpref,
            cmtflag,
            nametype,
            showbads,
            prefflag,
            packbase,
            asciiflags,
            listnames,
            asciiprefs,
            asciisernum,
            asciizeroes,
            tribyte_order,
            mf,
            org,
            assume,
            checkarg,
            start_ss,
            start_cs,
            main,
            short_dn,
            long_dn,
            datatypes,
            strtype,
            af2,
            namelen,
            margin,
            lenxref,
            lprefix,
            lprefixlen,
            compiler,
            model,
            sizeof_int,
            sizeof_bool,
            sizeof_enum,
            sizeof_algn,
            sizeof_short,
            sizeof_long,
            sizeof_llong,
            change_counter,
            sizeof_ldbl,
            abiname,
            abibits,
            refcmts,
        }))
    }

    pub(crate) fn read_v2(
        mut input: &mut impl IdaUnpack,
        magic_old: bool,
        version: u16,
        cpu: Vec<u8>,
    ) -> Result<Self> {
        // NOTE in this version parse_* functions are used
        let genflags = Inffl::new(input.unpack_dw()?)?;
        let lflags = Lflg::new(input.unpack_dd()?)?;
        let database_change_count = input.unpack_dd()?;
        let filetype = FileType::from_value(input.unpack_dw()?)
            .ok_or_else(|| anyhow!("Invalid FileType value"))?;
        let ostype = input.unpack_dw()?;
        let apptype = input.unpack_dw()?;
        let asmtype = input.read_u8()?;
        let specsegs = input.read_u8()?;
        let af1 = input.unpack_dd()?;
        let af2 = input.unpack_dd()?;
        let af = Af::new(af1, af2)?;
        let baseaddr = input.unpack_usize()?;
        let start_ss = input.unpack_usize()?;
        let start_cs = input.unpack_usize()?;
        let start_ip = input.unpack_usize()?;
        let start_ea = input.unpack_usize()?;
        let start_sp = input.unpack_usize()?;
        let main = input.unpack_usize()?;
        let min_ea = input.unpack_usize()?;
        let max_ea = input.unpack_usize()?;
        let omin_ea = input.unpack_usize()?;
        let omax_ea = input.unpack_usize()?;
        let lowoff = input.unpack_usize()?;
        let highoff = input.unpack_usize()?;
        let maxref = input.unpack_usize()?;
        let privrange_start_ea = input.unpack_usize()?;
        let privrange_end_ea = input.unpack_usize()?;
        let netdelta = input.unpack_usize()?;
        let xrefnum = input.read_u8()?;
        let type_xrefnum = input.read_u8()?;
        let refcmtnum = input.read_u8()?;
        let xrefflag = XRef::new(input.read_u8()?)?;
        let max_autoname_len = input.unpack_dw()?;

        if magic_old {
            let _unknown: [u8; 17] = bincode::deserialize_from(&mut input)?;
        }

        let nametype = input.read_u8()?;
        let nametype = NameType::new(nametype)
            .ok_or_else(|| anyhow!("Invalid NameType value"))?;
        let short_demnames = input.unpack_dd()?;
        let long_demnames = input.unpack_dd()?;
        let demnames = DemName::new(input.read_u8()?)?;
        let listnames = ListName::new(input.read_u8()?)?;
        let indent = input.read_u8()?;
        let cmt_ident = input.read_u8()?;
        let margin = input.unpack_dw()?;
        let lenxref = input.unpack_dw()?;
        let outflags = OutputFlags::new(input.unpack_dd()?)?;
        let cmtflg = CommentOptions::new(input.read_u8()?);
        let limiter = DelimiterOptions::new(input.read_u8()?)?;
        let bin_prefix_size = input.unpack_dw()?;
        let prefflag = LinePrefixOptions::new(input.read_u8()?)?;
        let strlit_flags = StrLiteralFlags::new(input.read_u8()?)?;
        let strlit_break = input.read_u8()?;
        let strlit_zeroes = input.read_u8()?;
        let strtype = input.unpack_dd()?;

        // TODO read the len and the ignore it?
        let strlit_pref_len = input.read_u8()?;
        let strlit_pref_len = if magic_old { 16 } else { strlit_pref_len };
        let mut strlit_pref = vec![0; strlit_pref_len.into()];
        input.read_exact(&mut strlit_pref)?;
        let strlit_pref = String::from_utf8(strlit_pref)?;

        let strlit_sernum = input.unpack_usize()?;
        let datatypes = input.unpack_usize()?;
        let cc_id = Compiler::from(input.read_u8()?);
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

        Ok(IDBParam::V2(IDBParam2 {
            version,
            cpu,
            genflags,
            lflags,
            database_change_count,
            filetype,
            ostype,
            apptype,
            asmtype,
            specsegs,
            af,
            baseaddr,
            start_ss,
            start_cs,
            start_ip,
            start_ea,
            start_sp,
            main,
            min_ea,
            max_ea,
            omin_ea,
            omax_ea,
            lowoff,
            highoff,
            maxref,
            privrange_start_ea,
            privrange_end_ea,
            netdelta,
            xrefnum,
            type_xrefnum,
            refcmtnum,
            xrefflag,
            max_autoname_len,
            nametype,
            short_demnames,
            long_demnames,
            demnames,
            listnames,
            indent,
            cmt_ident,
            margin,
            lenxref,
            outflags,
            cmtflg,
            limiter,
            bin_prefix_size,
            prefflag,
            strlit_flags,
            strlit_break,
            strlit_zeroes,
            strtype,
            strlit_pref,
            strlit_sernum,
            datatypes,
            cc_id,
            cc_cm,
            cc_size_i,
            cc_size_b,
            cc_size_e,
            cc_defalign,
            cc_size_s,
            cc_size_l,
            cc_size_ll,
            cc_size_ldbl,
            abibits,
            appcall_options,
        }))
    }
}

/// General idainfo flags
#[derive(Debug, Clone, Copy)]
pub struct Inffl(u8);
impl Inffl {
    fn new(value: u16) -> Result<Self> {
        ensure!(value < 0x100, "Invalid INFFL flag");
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
        ensure!(value < 0x1000, "Invalid LFLG flag");
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
    fn from_value(value: u16) -> Option<Self> {
        Some(match value {
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
            0x16 => Self::MsdosExe,
            0x17 => Self::MsdosCom,
            0x18 => Self::Aixar,
            0x19 => Self::Macho,
            0x1A => Self::Psxobj,
            _ => return None,
        })
    }
}

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x7e6cc0
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Compiler {
    Unknown = 0,
    VisualStudio = 1,
    Borland = 2,
    Watcom = 3,
    Gnu = 6,
    VisualAge = 7,
    Delphi = 8,

    // IDA LIB pring compiler_name allow any value here, printing it as "?"
    #[num_enum(default)]
    Other,
}
