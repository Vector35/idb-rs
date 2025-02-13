use std::borrow::Cow;
use std::io::BufReader;
use std::{fs::File, io::Write};

use anyhow::{anyhow, Result};

use idb_rs::id0::{AddressInfo, Comments, ID0Section};
use idb_rs::til::section::TILSection;
use idb_rs::til::TILTypeInfo;
use idb_rs::IDBParser;

use crate::{Args, FileType, ProduceIdcArgs};

// InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb6e80
pub fn produce_idc(args: &Args, idc_args: &ProduceIdcArgs) -> Result<()> {
    let input = BufReader::new(File::open(&args.input)?);
    match args.input_type() {
        FileType::Til => {
            return Err(anyhow!(
                "Produce IDC file from til file is not implemented yet"
            ));
        }
        FileType::Idb => {
            let mut parser = IDBParser::new(input)?;
            let id0_offset = parser.id0_section_offset().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID0 sector")
            })?;
            let til_offset = parser.til_section_offset().ok_or_else(|| {
                anyhow!("IDB file don't contains a TIL sector")
            })?;
            let id0 = parser.read_id0_section(id0_offset)?;
            let til = parser.read_til_section(til_offset)?;
            inner_produce_idc(&mut std::io::stdout(), idc_args, &id0, &til)?;
        }
    }
    Ok(())
}

fn inner_produce_idc(
    fmt: &mut impl Write,
    args: &ProduceIdcArgs,
    id0: &ID0Section,
    til: &TILSection,
) -> Result<()> {
    if !args.banner.is_empty() {
        write!(fmt, "//\n// +-------------------------------------------------------------------------+\n")?;
        for line in &args.banner {
            write!(fmt, "// |{line:^73}|\n")?;
        }
        write!(fmt, "// +-------------------------------------------------------------------------+\n//\n")?;
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

    // TODO only if non-zero patches
    writeln!(fmt)?;
    produce_patches(fmt, id0)?;

    writeln!(fmt)?;
    produce_bytes_info(fmt, id0, til)?;

    // TODO only if non-zero functions
    writeln!(fmt)?;
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

fn produce_gen_info(
    fmt: &mut impl Write,
    id0: &ID0Section,
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

fn produce_segments(fmt: &mut impl Write, id0: &ID0Section) -> Result<()> {
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
            name.unwrap_or(Cow::Borrowed(""))
        )?;

        let seg_class_name = match seg.seg_type {
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

fn produce_patches(fmt: &mut impl Write, _id0: &ID0Section) -> Result<()> {
    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b170e
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about patches")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Patches_0(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  auto x;")?;
    writeln!(fmt, "#define id x")?;
    writeln!(fmt)?;
    writeln!(fmt, "  TODO();")?;
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

fn produce_bytes_info(
    fmt: &mut impl Write,
    id0: &ID0Section,
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
    let version = match id0.ida_info().unwrap() {
        idb_rs::id0::IDBParam::V1(x) => x.version,
        idb_rs::id0::IDBParam::V2(x) => x.version,
    };
    for addr_info in id0.address_info_by_address(version)? {
        let (addr, iter) = addr_info?;
        // first print comments
        for addr_info in iter {
            let (_addr_2, info) = addr_info?;
            if let AddressInfo::Comment(Comments::Comment(cmt)) = info {
                writeln!(
                    fmt,
                    "  set_cmt({addr:#X}, \"{}\", 0);",
                    String::from_utf8_lossy(cmt)
                )?;
            }
        }
        let pre_cmts = iter.filter_map(|x| match x {
            Ok((_, AddressInfo::Comment(Comments::PreComment(cmt)))) => {
                Some(Ok(cmt))
            }
            Ok(_x) => None,
            Err(e) => Some(Err(e)),
        });
        for (i, cmt) in pre_cmts.enumerate() {
            writeln!(
                fmt,
                "  update_extra_cmt({addr:#X}, E_PREV + {i:>2}, \"{}\");",
                String::from_utf8_lossy(cmt?)
            )?;
        }

        // names, NOTE there is only one!
        for addr_info in iter {
            let (_addr_2, info) = addr_info?;
            if let AddressInfo::Label(label) = info {
                writeln!(fmt, "  set_name({addr:#X}, \"{label}\");",)?;
            }
        }

        for addr_info in iter {
            let (_addr_2, info) = addr_info?;
            if let AddressInfo::TilType(til) = info {
                writeln!(fmt, "  set_name({addr:#X}, \"{til:?}\");",)?;
            }
        }

        // TODO other AddressInfo types
    }
    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_functions(
    fmt: &mut impl Write,
    _id0: &ID0Section,
    _til: &TILSection,
) -> Result<()> {
    // TODO find the number of functions
    writeln!(fmt, "static Functions_0(void) ")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  TODO();")?;
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

fn produce_seg_regs(
    fmt: &mut impl Write,
    _id0: &ID0Section,
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

fn produce_all_patches(
    fmt: &mut impl Write,
    _id0: &ID0Section,
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

fn produce_bytes(
    fmt: &mut impl Write,
    _id0: &ID0Section,
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
