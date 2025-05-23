use std::borrow::{Borrow, Cow};
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::iter::Peekable;
use std::{fs::File, io::Write};

use anyhow::{anyhow, ensure, Context, Result};

use idb_rs::id0::function::{IDBFunctionNonTail, IDBFunctionTail};
use idb_rs::id0::{AddressInfo, Comments, ID0Section};
use idb_rs::id1::{
    ByteData, ByteDataType, ByteInfoRaw, ByteRawType, ByteType, ID1Section,
    InstOpInfo,
};
use idb_rs::til::section::TILSection;
use idb_rs::til::TILTypeInfo;
use idb_rs::{IDAKind, IDAVariants, IDBFormat};

use crate::{Args, FileType, ProduceIdcArgs};

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb6e80
pub fn produce_idc(args: &Args, idc_args: &ProduceIdcArgs) -> Result<()> {
    let mut input = BufReader::new(File::open(&args.input)?);
    match args.input_type() {
        FileType::Til => Err(anyhow!(
            "Produce IDC file from til file is not implemented yet"
        )),
        FileType::Idb => {
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    produce_idc_section(sections, input, idc_args)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    produce_idc_section(sections, input, idc_args)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)
                        .unwrap();
                    produce_idc_section(
                        sections,
                        Cursor::new(decompressed),
                        idc_args,
                    )
                }
            }
        }
    }
}

fn produce_idc_section<R: IDBFormat, I: BufRead + Seek>(
    sections: R,
    mut input: I,
    idc_args: &ProduceIdcArgs,
) -> Result<()> {
    let id0_location = sections
        .id0_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a ID0 sector"))?;
    let id1_location = sections
        .id1_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a ID1 sector"))?;
    let til_location = sections
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    let id0 = sections.read_id0(&mut input, id0_location)?;
    let id1 = sections.read_id1(&mut input, id1_location)?;
    let til = sections.read_til(&mut input, til_location)?;
    match id0 {
        IDAVariants::IDA32(id0) => produce_idc_inner(
            &mut std::io::stdout(),
            idc_args,
            &id0,
            &id1,
            &til,
        ),
        IDAVariants::IDA64(id0) => produce_idc_inner(
            &mut std::io::stdout(),
            idc_args,
            &id0,
            &id1,
            &til,
        ),
    }
}

fn produce_idc_inner<K: IDAKind>(
    fmt: &mut impl Write,
    args: &ProduceIdcArgs,
    id0: &ID0Section<K>,
    id1: &ID1Section,
    til: &TILSection,
) -> Result<()> {
    if !args.banner.is_empty() {
        writeln!(fmt, "//\n// +-------------------------------------------------------------------------+")?;
        for line in &args.banner {
            writeln!(fmt, "// |{line:^73}|")?;
        }
        writeln!(fmt, "// +-------------------------------------------------------------------------+\n//")?;
    }
    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb6e80
    let _unknown_value1 = true; // all database, or just range?
    let _unknown_value2 = true; // export user types?
    match (_unknown_value1, _unknown_value2) {
        (false, false) => {
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb919a
            // TODO implement range dump
            //writeln!(fmt)?;
            //writeln!(fmt, "// DUMP OF RANGE {start}..{end}")?;
            todo!();
        }
        (false, true) => {
            // TODO also implement user type definitions
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb6fd4
            writeln!(fmt, "//")?;
            writeln!(
                fmt,
                "//      This file contains the user-defined type definitions."
            )?;
            writeln!(fmt, "//      To use it press F2 in IDA and enter the name of this file.")?;
            writeln!(fmt, "//")?;
        }
        (true, _) => {
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb71a9
            writeln!(fmt, "//")?;
            writeln!(
                fmt,
                "//      This file should be used in the following way:"
            )?;
            writeln!(
                fmt,
                "//         - reload executable into IDA with using switch -c"
            )?;
            writeln!(
                fmt,
                "//         - use File, Load IDC file and load this file."
            )?;
            writeln!(fmt, "//")?;
            writeln!(fmt, "//      NOTE: This file doesn't contain all information from the database.")?;
            writeln!(fmt, "//")?;
        }
    }
    writeln!(fmt)?;

    writeln!(fmt, "#define UNLOADED_FILE   1")?;
    writeln!(fmt, "#include <idc.idc>")?;
    writeln!(fmt)?;
    writeln!(fmt, "extern ltf;  // load_type flags")?;
    writeln!(fmt)?;

    produce_main(fmt, _unknown_value1, _unknown_value2)?;

    if _unknown_value1 {
        writeln!(fmt)?;
        produce_gen_info(fmt, id0, til)?;
        writeln!(fmt)?;
        produce_segments(fmt, id0)?;
    }

    if _unknown_value2 {
        writeln!(fmt)?;
        produce_types(fmt, til)?;
    }

    produce_patches(fmt, id0, id1)?;

    writeln!(fmt)?;
    produce_bytes_info(fmt, id0, id1, til)?;

    produce_functions(fmt, id0, til)?;

    writeln!(fmt)?;
    produce_seg_regs(fmt, id0, til)?;

    writeln!(fmt)?;
    produce_all_patches(fmt, id0, til)?;

    writeln!(fmt)?;
    produce_bytes(fmt, id0, til)?;

    writeln!(fmt)?;
    writeln!(fmt, "// End of file.")?;
    Ok(())
}

fn produce_main(
    fmt: &mut impl Write,
    _unknown_value1: bool,
    _unknown_value2: bool,
) -> Result<()> {
    writeln!(fmt, "static main(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  ltf = ARGV.count > 1 ? ARGV[1] : LOADTYPE_DEFAULT;")?;

    match (_unknown_value1, _unknown_value2) {
        (false, false) => {
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb91bc
            writeln!(fmt, "  Patches();      // info about patches bytes")?;
            writeln!(fmt, "  SegRegs();      // segment register values")?;
            writeln!(fmt, "  Bytes();        // individual bytes (code,data)")?;
            writeln!(fmt, "  Functions();    // function definitions")?;
        }
        (false, true) => {
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb6ff6
            writeln!(fmt, "  LocalTypes();")?;
        }
        (true, _) => {
            // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb71cb
            writeln!(fmt, "  // set \'loading idc file\' mode")?;
            writeln!(fmt, "  set_inf_attr(INF_GENFLAGS, INFFL_LOADIDC|get_inf_attr(INF_GENFLAGS));")?;
            writeln!(fmt, "  GenInfo();     // various settings")?;
            writeln!(fmt, "  Segments();    // segmentation")?;
            writeln!(fmt, "  LocalTypes();  // local types")?;
            writeln!(fmt, "  Patches();     // manual patches")?;
            writeln!(fmt, "  SegRegs();     // segment register values")?;
            writeln!(fmt, "  Bytes();       // individual bytes (code,data)")?;
            writeln!(fmt, "  Functions();   // function definitions")?;
            writeln!(fmt, "  // clear 'loading idc file' mode")?;
            writeln!(fmt, "  set_inf_attr(INF_GENFLAGS, ~INFFL_LOADIDC&get_inf_attr(INF_GENFLAGS));")?;
        }
    }
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_gen_info<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    til: &TILSection,
) -> Result<()> {
    let info = id0.ida_info()?;
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// General information")?;
    writeln!(fmt)?;
    writeln!(fmt, "static GenInfo(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  delete_all_segments();   // purge database")?;
    let cpu = match &info {
        idb_rs::id0::IDBParam::V1(x) => &x.cpu,
        idb_rs::id0::IDBParam::V2(x) => &x.cpu,
    };
    writeln!(
        fmt,
        "  set_processor_type(\"{}\", SETPROC_USER);",
        String::from_utf8_lossy(cpu)
    )?;
    let compiler = match &info {
        idb_rs::id0::IDBParam::V1(x) => x.compiler,
        idb_rs::id0::IDBParam::V2(x) => x.cc_id.into(),
    };
    writeln!(fmt, "  set_inf_attr(INF_COMPILER, {compiler});")?;
    let strlit_break = match &info {
        idb_rs::id0::IDBParam::V1(x) => x.ascii_break,
        idb_rs::id0::IDBParam::V2(x) => x.strlit_break,
    };
    writeln!(fmt, "  set_inf_attr(INF_STRLIT_BREAK, {strlit_break:#X});",)?;
    let scf_allcmt = match &info {
        idb_rs::id0::IDBParam::V1(_x) => {
            // TODO todo!("flag from V1 x.cmtflag.is_allcmt()")
            false as u8
        }
        idb_rs::id0::IDBParam::V2(x) => x.cmtflg.is_allcmt() as u8,
    };
    writeln!(fmt, "  set_flag(INF_CMTFLG, SCF_ALLCMT, {scf_allcmt});")?;
    let oflg_show_void = match &info {
        idb_rs::id0::IDBParam::V1(_x) => {
            // TODO todo!("flag from V1 x.outflags.show_void()")
            false as u8
        }
        idb_rs::id0::IDBParam::V2(x) => x.outflags.show_void() as u8,
    };
    writeln!(
        fmt,
        "  set_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, {oflg_show_void});"
    )?;
    let xrefnum = match &info {
        idb_rs::id0::IDBParam::V1(x) => x.xrefnum,
        idb_rs::id0::IDBParam::V2(x) => x.xrefnum,
    };
    writeln!(fmt, "  set_inf_attr(INF_XREFNUM, {xrefnum});")?;
    let oflg_show_auto = match &info {
        idb_rs::id0::IDBParam::V1(_x) => {
            // TODO todo!("flag from V1 x.outflags.show_auto()")
            false as u8
        }
        idb_rs::id0::IDBParam::V2(x) => x.outflags.show_auto() as u8,
    };
    writeln!(
        fmt,
        "  set_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, {oflg_show_auto});",
    )?;
    let indent = match &info {
        idb_rs::id0::IDBParam::V1(x) => x.indent,
        idb_rs::id0::IDBParam::V2(x) => x.indent,
    };
    writeln!(fmt, "  set_inf_attr(INF_INDENT, {indent});")?;
    let cmd_indent = match &info {
        idb_rs::id0::IDBParam::V1(_x) => {
            // TODO todo!("value from V1.cmd_indent")
            0
        }
        idb_rs::id0::IDBParam::V2(x) => x.cmt_ident,
    };
    writeln!(fmt, "  set_inf_attr(INF_CMT_INDENT, {cmd_indent});")?;
    let max_ref = match &info {
        idb_rs::id0::IDBParam::V1(x) => x.maxref,
        idb_rs::id0::IDBParam::V2(x) => x.maxref,
    };
    writeln!(fmt, "  set_inf_attr(INF_MAXREF, {max_ref:#X});")?;
    for dep in &til.header.dependencies {
        writeln!(fmt, "  add_default_til(\"{}\");", dep.as_utf8_lossy())?;
    }
    writeln!(fmt, "}}")?;

    Ok(())
}

fn produce_segments<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
) -> Result<()> {
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about segmentation")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Segments(void)")?;
    writeln!(fmt, "{{")?;
    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7480
    // https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/292
    let segs: Vec<_> = id0.segments()?.collect::<Result<_, _>>()?;
    let mut segs_sorted: Vec<&_> = segs.iter().collect();
    segs_sorted.sort_unstable_by_key(|seg| seg.selector);
    for seg in segs_sorted {
        let sel = seg.selector;
        let val = seg.orgbase;
        writeln!(fmt, "  set_selector({sel:#X}, {val:#X});")?;
    }
    writeln!(fmt)?;

    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb74b7
    for seg in segs {
        let startea = seg.address.start;
        let endea = seg.address.end;
        let base = seg.selector;
        let use32 = match seg.bitness {
            idb_rs::id0::SegmentBitness::S16Bits => 0,
            idb_rs::id0::SegmentBitness::S32Bits => 1,
            idb_rs::id0::SegmentBitness::S64Bits => 2,
        };
        let align: u8 = seg.align.into();
        // TODO InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb754f
        let comb = 2;
        // TODO InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7544
        let flags = if false { "|ADDSEG_SPARSE" } else { "" };
        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb75f4
        // https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/299
        writeln!(
            fmt,
            "  add_segm_ex({startea:#X}, {endea:#X}, {base:#X}, {use32}, {align}, {comb}, ADDSEG_NOSREG{flags});",
        )?;

        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7666
        let name = seg
            .name
            .as_ref()
            .map(|x| id0.segment_name(*x).map(|x| String::from_utf8_lossy(x)))
            .transpose()?;
        writeln!(
            fmt,
            "  set_segm_name({startea:#X}, \"{}\");",
            name.as_ref().unwrap_or(&Cow::Borrowed(""))
        )?;

        let seg_class_name = match seg.seg_type {
            idb_rs::id0::SegmentType::Norm if name.is_some() => {
                name.as_ref().unwrap().borrow()
            }
            idb_rs::id0::SegmentType::Norm => "NORM",
            idb_rs::id0::SegmentType::Xtrn => "XTRN",
            idb_rs::id0::SegmentType::Code => "CODE",
            idb_rs::id0::SegmentType::Data => "DATA",
            idb_rs::id0::SegmentType::Imp => "IMP",
            idb_rs::id0::SegmentType::Grp => "GRP",
            idb_rs::id0::SegmentType::Null => "NULL",
            idb_rs::id0::SegmentType::Undf => "UNDF",
            idb_rs::id0::SegmentType::Bss => "BSS",
            idb_rs::id0::SegmentType::Abssym => "ABSSYM",
            idb_rs::id0::SegmentType::Comm => "COMM",
            idb_rs::id0::SegmentType::Imem => "IMEM",
        };
        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7699
        writeln!(fmt, "  set_segm_class({startea:#X}, \"{seg_class_name}\");")?;

        //// TODO InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb76ac
        //for _def_ref in seg.defsr.iter().filter(|x| **x != 0) {
        //    writeln!(fmt, "SegDefReg({startea:#X}, \"{seg_class_raw}\", {:X});")?;
        //    todo!();
        //}

        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb74e1
        // https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/310
        let seg_class_raw: u8 = seg.seg_type.into();
        if seg_class_raw != 0 {
            writeln!(fmt, "  set_segm_type({startea:#X}, {seg_class_raw});")?;
        }
    }

    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb8c35
    let ida_info = id0.ida_info()?;
    let low_off = match &ida_info {
        idb_rs::id0::IDBParam::V1(x) => x.lowoff,
        idb_rs::id0::IDBParam::V2(x) => x.lowoff,
    };
    writeln!(fmt, "  set_inf_attr(INF_LOW_OFF, {low_off:#X});")?;
    let high_off = match &ida_info {
        idb_rs::id0::IDBParam::V1(x) => x.highoff,
        idb_rs::id0::IDBParam::V2(x) => x.highoff,
    };
    writeln!(fmt, "  set_inf_attr(INF_HIGH_OFF, {high_off:#X});")?;

    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_types(fmt: &mut impl Write, til: &TILSection) -> Result<()> {
    // TODO types is 0, symbols is 1, etc, til files are 2..?
    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb8ca9
    writeln!(fmt, "static LocalTypes_0() ")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  auto p_type, p_fields, p_cmt, p_fldcmts;")?;
    writeln!(fmt)?;
    for ty in &til.types {
        produce_type_load(fmt, til, ty)?;
    }
    writeln!(fmt, "}}")?;
    writeln!(fmt)?;
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about local types")?;
    writeln!(fmt)?;
    writeln!(fmt, "static LocalTypes()")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  LocalTypes_0();")?;
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_patches<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    id1: &ID1Section,
) -> Result<()> {
    let Some(patches_idx) = id0.segment_patches_idx() else {
        return Ok(());
    };
    let patches = id0.segment_patches_original_value(patches_idx);
    if patches.len() == 0 {
        return Ok(());
    }

    writeln!(fmt)?;
    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b170e
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about patches")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Patches_0(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  auto x;")?;
    writeln!(fmt, "#define id x")?;
    writeln!(fmt)?;
    for patch in patches {
        let patch = patch?;
        let address = patch.address;
        let value = id1
            .byte_by_address(patch.address.into())
            .map(|x| x.byte_raw())
            .unwrap_or(0);
        writeln!(fmt, "  patch_byte({address:#X}, {value:#X});")?;
    }
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_type_load(
    fmt: &mut impl Write,
    _til: &TILSection,
    ty: &TILTypeInfo,
) -> Result<()> {
    // TODO serialize the til will take a lot of time, better use a read_raw API
    // although it could be a good test for code quality
    writeln!(fmt, "  p_type = \"TODO\";")?;
    let have_fields = false;
    let have_fldcmts = false;
    if have_fields {
        writeln!(fmt, "  p_fields = \"TODO\";")?;
    }
    if let Some(cmt) = &ty.tinfo.comment {
        writeln!(fmt, "  p_cmt = \"{}\";", cmt.as_utf8_lossy())?;
    }
    if have_fldcmts {
        writeln!(fmt, "  p_fldcmts = \"TODO\";")?;
    }
    let ord = ty.ordinal;
    let name = ty.name.as_utf8_lossy();
    write!(fmt, "  load_type(ltf, {ord}, \"{name}\", p_type")?;
    if have_fields {
        write!(fmt, ", p_fields")?;
    }
    if ty.tinfo.comment.is_some() {
        write!(fmt, ", p_cmt")?;
    }
    if have_fldcmts {
        write!(fmt, ", p_fldcmts")?;
    }
    writeln!(fmt, ");")?;
    Ok(())
}

fn produce_bytes_info<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    id1: &ID1Section,
    _til: &TILSection,
) -> Result<()> {
    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb70ce
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about bytes")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Bytes_0(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  auto x;")?;
    writeln!(fmt, "#define id x")?;
    writeln!(fmt)?;

    let mut all_bytes = id1.all_bytes().peekable();
    loop {
        let Some((address, byte_info_raw)) = all_bytes.next() else {
            break;
        };

        let byte_info = byte_info_raw.decode().unwrap();
        let addr_info =
            id0.address_info_at(K::Usize::try_from(address).unwrap())?;
        // print comments
        // TODO byte_info.has_comment() ignored?
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1822
        for addr_info in addr_info {
            if let AddressInfo::Comment(Comments::Comment(cmt)) = addr_info? {
                writeln!(
                    fmt,
                    "  set_cmt({address:#X}, \"{}\", 0);",
                    String::from_utf8_lossy(cmt)
                )?;
            }
        }

        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1ddd
        if byte_info.has_comment_ext {
            let pre_cmts = addr_info.filter_map(|x| match x {
                Ok(AddressInfo::Comment(Comments::PreComment(cmt))) => {
                    Some(Ok(cmt))
                }
                Ok(_x) => None,
                Err(e) => Some(Err(e)),
            });
            for (i, cmt) in pre_cmts.enumerate() {
                writeln!(
                    fmt,
                    "  update_extra_cmt({address:#X}, E_PREV + {i:>3}, \"{}\");",
                    String::from_utf8_lossy(cmt?)
                )?;
            }

            let post_cmts = addr_info.filter_map(|x| match x {
                Ok(AddressInfo::Comment(Comments::PostComment(cmt))) => {
                    Some(Ok(cmt))
                }
                Ok(_x) => None,
                Err(e) => Some(Err(e)),
            });
            for (i, cmt) in post_cmts.enumerate() {
                writeln!(
                    fmt,
                    "  update_extra_cmt({address:#X}, E_NEXT + {i:>3}, \"{}\");",
                    String::from_utf8_lossy(cmt?)
                )?;
            }
        }

        // TODO InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1dee
        // if matches!(byte_type, (ByteType::Code | ByteType::Data)) {
        //   is_manual(byte_type, 0xf) ||
        //   (!is_off(byte_type, 0xf) && !is_seg(byte_type, 0xf) &&
        //   !is_char(byte_type, 0xf) && !is_enum(byte_type, 0xf) &&
        //   !is_stroff(byte_type, 0xf) && !is_stkvar(byte_type, 0xf) &&
        //   !is_numop(byte_type, 0xf))
        //   "x=\"\"" | ""
        // }
        let set_x = match byte_info.byte_type {
            ByteType::Data(ByteData {
                print_info:
                    InstOpInfo::Hex
                    | InstOpInfo::Dec
                    | InstOpInfo::Bin
                    | InstOpInfo::Oct,
                data_type: _,
            }) => "x=",
            _ => "",
        };

        match byte_info.byte_type {
            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1dee
            ByteType::Code(code) => {
                let _len = count_tails(&mut all_bytes) + 1;
                if !byte_info.exec_flow_from_prev_inst || code.is_func_start
                //  || TODO: byte_info.is_manual()
                {
                    writeln!(fmt, "  create_insn({set_x}{address:#X});")?;
                }
            }
            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1e37
            ByteType::Data(data) => {
                match data.data_type {
                    ByteDataType::Strlit => {
                        let len = count_tails(&mut all_bytes);
                        writeln!(
                            fmt,
                            "  create_strlit({set_x}{address:#X}, {len:#X});"
                        )?
                    }
                    ByteDataType::Dword => {
                        let len = count_element(&mut all_bytes, 4)?;
                        writeln!(fmt, "  create_dword({set_x}{address:#X});")?;
                        if len > 1 {
                            writeln!(
                                fmt,
                                "  make_array({address:#X}, {len:#X});"
                            )?
                        }
                    }
                    ByteDataType::Byte => {
                        let len = count_tails(&mut all_bytes);
                        writeln!(fmt, "  create_byte({set_x}{address:#X});")?;
                        if len > 1 {
                            writeln!(
                                fmt,
                                "  make_array({address:#X}, {len:#X});"
                            )?
                        }
                    }
                    ByteDataType::Word => {
                        let len = count_element(&mut all_bytes, 2)?;
                        writeln!(fmt, "  create_word({set_x}{address:#X});")?;
                        if len > 1 {
                            writeln!(
                                fmt,
                                "  make_array({address:#X}, {len:#X});"
                            )?
                        }
                    }
                    ByteDataType::Qword => {
                        let len = count_element(&mut all_bytes, 8)?;
                        writeln!(fmt, "  create_qword({set_x}{address:#X});")?;
                        if len > 1 {
                            writeln!(
                                fmt,
                                "  make_array({address:#X}, {len:#X});"
                            )?
                        }
                    }
                    ByteDataType::Tbyte => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO make array?
                        writeln!(fmt, "  create_tbyte({set_x}{address:#X});")?
                    }
                    ByteDataType::Float => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO make array?
                        writeln!(fmt, "  create_float({set_x}{address:#X});")?
                    }
                    ByteDataType::Packreal => writeln!(
                        fmt,
                        "  create_pack_real({set_x}{address:#X});"
                    )?,
                    ByteDataType::Yword => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO make array?
                        writeln!(fmt, "  create_yword({set_x}{address:#X});")?
                    }
                    ByteDataType::Double => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO make array?
                        writeln!(fmt, "  create_double({set_x}{address:#X});")?
                    }
                    ByteDataType::Oword => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO make array?
                        writeln!(fmt, "  create_oword({set_x}{address:#X});")?
                    }
                    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2690
                    ByteDataType::Struct => {
                        let _len = count_tails(&mut all_bytes);
                        // TODO ensure struct have the same len that _len
                        // TODO make a struct_def_at
                        // TODO make array?
                        let struct_id = id0
                            .address_info_at(
                                K::Usize::try_from(address).unwrap(),
                            )
                            .unwrap()
                            .find_map(|e| match e {
                                Ok(AddressInfo::DefinedStruct(s)) => {
                                    Some(Ok(s))
                                }
                                Err(e) => Some(Err(e)),
                                Ok(_) => None,
                            });
                        let struct_name = struct_id
                            .map(|idx| {
                                id0.struct_at(idx.unwrap())
                                    .with_context(|| {
                                        format!("ID1 addr {address:#X}")
                                    })
                                    .unwrap()
                            })
                            .unwrap_or(b"BAD_STRUCT");
                        writeln!(
                            fmt,
                            "  create_struct({address:#X}, -1, \"{}\");",
                            core::str::from_utf8(struct_name).unwrap()
                        )?;
                    }
                    ByteDataType::Align => {
                        let len = count_tails(&mut all_bytes);
                        if len > 1 {
                            writeln!(
                                fmt,
                                "  make_array({address:#X}, {len:#X});"
                            )?
                        }
                    }
                    ByteDataType::Zword | ByteDataType::Custom => {
                        let _len = count_tails(&mut all_bytes);
                        //TODO
                    }
                    ByteDataType::Reserved => {
                        todo!();
                    }
                }
                match data.print_info {
                    InstOpInfo::Hex => writeln!(fmt, "  op_hex(x, 0);")?,
                    InstOpInfo::Dec => writeln!(fmt, "  op_dec(x, 0);")?,
                    InstOpInfo::Bin => writeln!(fmt, "  op_bin(x, 0);")?,
                    InstOpInfo::Oct => writeln!(fmt, "  op_oct(x, 0);")?,
                    InstOpInfo::Void
                    | InstOpInfo::Char
                    | InstOpInfo::Seg
                    | InstOpInfo::Off
                    | InstOpInfo::Enum
                    | InstOpInfo::Fop
                    | InstOpInfo::StrOff
                    | InstOpInfo::StackVar
                    | InstOpInfo::Float
                    | InstOpInfo::Custom => {}
                }
                // TODO  get_data_elsize
                // TODO make_array
                // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2622
            }
            ByteType::Tail => {
                return Err(anyhow!("Unexpected ID1 Tail entry: {address:#X}"))
            }
            ByteType::Unknown => {}
        }

        // TODO InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1e5e
        // for bit in 0..8 {
        //  if id1.is_invsign(address, byte_info, bit) {
        //    todo!();
        //  }
        //  if id1.is_bnot(address, byte_info, bit) {
        //    todo!();
        //  }
        //  if id1.is_defarg(address, byte_info, bit) {
        //    break;
        //  }
        //  todo!();
        //}

        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2160
        if byte_info.has_name {
            for addr_info in addr_info {
                if let AddressInfo::Label(name) = addr_info? {
                    writeln!(
                        fmt,
                        "  set_name({address:#X}, \"{}\");",
                        String::from_utf8_lossy(name.as_bytes())
                    )?;
                }
            }
        }
    }

    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b28ea
    // TODO add_func and other getn_func related functions

    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2fee
    // TODO getn_fchunk related stuff

    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_functions<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    _til: &TILSection,
) -> Result<()> {
    use idb_rs::id0::function::FunctionsAndComments;
    use idb_rs::id0::function::FunctionsAndComments::*;
    use idb_rs::id0::function::IDBFunctionType::*;

    // TODO find the InnerRef for this, maybe it's just `$ dirtree/funcs`
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(());
    };
    let id0_funcs = id0.functions_and_comments(idx)?;
    let funcs: Vec<_> = id0_funcs
        .filter_map(|fun| match fun {
            Err(e) => Some(Err(e)),
            Ok(FunctionsAndComments::Function(fun)) => Some(Ok(fun)),
            Ok(
                Name
                | FunctionsAndComments::Comment { .. }
                | FunctionsAndComments::Unknown { .. },
            ) => None,
        })
        .collect::<Result<_>>()?;

    if funcs.is_empty() {
        return Ok(());
    }

    // TODO find the number of functions
    writeln!(fmt)?;
    writeln!(fmt, "static Functions_0(void)")?;
    writeln!(fmt, "{{")?;
    for fun in funcs {
        let addr = fun.address.start;
        writeln!(fmt, "  add_func({addr:#X}, {:#X});", fun.address.end)?;
        writeln!(
            fmt,
            "  set_func_flags({addr:#X}, {:#x});",
            fun.flags.into_raw()
        )?;
        writeln!(fmt, "  apply_type({addr:#X}, \"TODO\");")?;
        match &fun.extra {
            Tail(IDBFunctionTail {
                owner,
                _unknown4,
                _unknown5,
            }) => {
                writeln!(fmt, "  set_frame_size({addr:#X}, {owner:#X?});")?;
            }
            NonTail(IDBFunctionNonTail {
                frsize,
                frregs,
                argsize,
                ..
            }) if *frsize != K::Usize::from(0u8) => {
                writeln!(
                    fmt,
                    "  set_frame_size({addr:#X}, {frsize:#X}, {frregs}, {argsize:#X});"
                )?;
            }
            NonTail(_) => {}
        }
    }
    writeln!(fmt, "}}")?;
    writeln!(fmt)?;
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about functions")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Functions(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  Functions_0();")?;
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_seg_regs<K: IDAKind>(
    fmt: &mut impl Write,
    _id0: &ID0Section<K>,
    _til: &TILSection,
) -> Result<()> {
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about segment registers")?;
    writeln!(fmt)?;
    writeln!(fmt, "static SegRegs(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  TODO();")?;
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_all_patches<K: IDAKind>(
    fmt: &mut impl Write,
    _id0: &ID0Section<K>,
    _til: &TILSection,
) -> Result<()> {
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about all patched bytes:")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Patches(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  TODO();")?;
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_bytes<K: IDAKind>(
    fmt: &mut impl Write,
    _id0: &ID0Section<K>,
    _til: &TILSection,
) -> Result<()> {
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Call all byte feature functions:")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Bytes(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  Bytes_0();")?;
    writeln!(fmt, "}}")?;
    Ok(())
}

fn count_tails<I>(bytes: &mut Peekable<I>) -> usize
where
    I: Iterator<Item = (u64, ByteInfoRaw)>,
{
    bytes
        .take_while(|(_a, b)| b.byte_type() == ByteRawType::Tail)
        .count()
}

fn count_element<I>(bytes: &mut Peekable<I>, ele_len: usize) -> Result<usize>
where
    I: Iterator<Item = (u64, ByteInfoRaw)>,
{
    let len = count_tails(bytes) + 1;
    ensure!(len >= ele_len, "Expected more ID1 Tail entries");
    ensure!(
        len % ele_len == 0,
        "More ID1 Tails that expects or invalid array len"
    );
    Ok(len / ele_len)
}
