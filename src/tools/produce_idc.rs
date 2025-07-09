use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek, Write};

use anyhow::{anyhow, ensure, Result};

use idb_rs::addr_info::{all_address_info, AddressInfo};
use idb_rs::id0::flag::netnode::nn_res::*;
use idb_rs::id0::function::{IDBFunctionNonTail, IDBFunctionTail};
use idb_rs::id0::{ID0Section, Netdelta, NetnodeIdx, ReferenceInfo};
use idb_rs::id1::{
    ByteCode, ByteData, ByteDataType, ByteExtended, ByteOp, ByteType,
    ID1Section,
};
use idb_rs::id2::ID2Section;
use idb_rs::til::section::TILSection;
use idb_rs::til::TILTypeInfo;
use idb_rs::{Address, IDAKind, IDAUsize, IDAVariants, IDBFormat, IDBStr};

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
    let id2_location = sections.id2_location();
    let til_location = sections
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    let id0 = sections.read_id0(&mut input, id0_location)?;
    let id1 = sections.read_id1(&mut input, id1_location)?;
    let id2 = id2_location
        .map(|id2| sections.read_id2(&mut input, id2))
        .transpose()?;
    let til = sections.read_til(&mut input, til_location)?;
    match (id0, id2) {
        (IDAVariants::IDA32(id0), Some(IDAVariants::IDA32(id2))) => {
            produce_idc_inner(
                &mut std::io::stdout(),
                idc_args,
                &id0,
                &id1,
                Some(&id2),
                &til,
            )
        }
        (IDAVariants::IDA32(id0), None) => produce_idc_inner(
            &mut std::io::stdout(),
            idc_args,
            &id0,
            &id1,
            None,
            &til,
        ),
        (IDAVariants::IDA64(id0), Some(IDAVariants::IDA64(id2))) => {
            produce_idc_inner(
                &mut std::io::stdout(),
                idc_args,
                &id0,
                &id1,
                Some(&id2),
                &til,
            )
        }
        (IDAVariants::IDA64(id0), None) => produce_idc_inner(
            &mut std::io::stdout(),
            idc_args,
            &id0,
            &id1,
            None,
            &til,
        ),
        (_, _) => unreachable!(),
    }
}

fn produce_idc_inner<K: IDAKind>(
    fmt: &mut impl Write,
    args: &ProduceIdcArgs,
    id0: &ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
    til: &TILSection,
) -> Result<()> {
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let image_base = id0.image_base(root_info_idx)?;
    let netdelta = root_info.netdelta();
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
        produce_segments(fmt, id0, id1)?;
    }

    if _unknown_value2 {
        writeln!(fmt)?;
        produce_types(fmt, til)?;
    }

    produce_patches(fmt, id0, id1)?;

    writeln!(fmt)?;
    produce_bytes_info(fmt, id0, id1, id2, til, image_base, netdelta)?;

    produce_functions(fmt, id0, til, netdelta)?;

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
    let root_netnode = id0.root_node()?;
    let info = id0.ida_info(root_netnode)?;
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// General information")?;
    writeln!(fmt)?;
    writeln!(fmt, "static GenInfo(void)")?;
    writeln!(fmt, "{{")?;
    writeln!(fmt, "  delete_all_segments();   // purge database")?;
    writeln!(
        fmt,
        "  set_processor_type({:?}, SETPROC_USER);",
        String::from_utf8_lossy(&info.target.processor)
    )?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_COMPILER, {});",
        info.compiler.compiler as u8
    )?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_STRLIT_BREAK, {:#X});",
        info.strlits.break_
    )?;
    writeln!(
        fmt,
        "  set_flag(INF_CMTFLG, SCF_ALLCMT, {});",
        u8::from(info.cmtflg.is_allcmt())
    )?;
    writeln!(
        fmt,
        "  set_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, {});",
        u8::from(info.outflag.show_void()),
    )?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_XREFNUM, {});",
        info.xrefs.max_displayed_xrefs
    )?;
    writeln!(
        fmt,
        "  set_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, {});",
        u8::from(info.outflag.show_auto()),
    )?;
    writeln!(fmt, "  set_inf_attr(INF_INDENT, {});", info.indent)?;
    writeln!(fmt, "  set_inf_attr(INF_CMT_INDENT, {});", info.cmt_ident)?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_MAXREF, {:#X});",
        info.xrefs.max_depth
    )?;
    for dep in &til.header.dependencies {
        writeln!(fmt, "  add_default_til({:?});", dep.as_utf8_lossy())?;
    }
    writeln!(fmt, "}}")?;

    Ok(())
}

fn produce_segments<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    id1: &ID1Section,
) -> Result<()> {
    writeln!(fmt, "//------------------------------------------------------------------------")?;
    writeln!(fmt, "// Information about segmentation")?;
    writeln!(fmt)?;
    writeln!(fmt, "static Segments(void)")?;
    writeln!(fmt, "{{")?;
    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7480
    // https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/292
    let segs_idx = id0.segments_idx()?;
    let segs: Vec<_> = segs_idx
        .map(|idx| id0.segments(idx).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
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
        let flags = if id1.segment_by_address(startea.into_u64()).is_none() {
            "|ADDSEG_SPARSE"
        } else {
            ""
        };
        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb75f4
        // https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/299
        writeln!(
            fmt,
            "  add_segm_ex({startea:#X}, {endea:#X}, {base:#X}, {use32}, {align}, {comb}, ADDSEG_NOSREG{flags});",
        )?;

        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7666
        let seg_name =
            id0.segment_name(seg.name).map(IDBStr::as_utf8_lossy).ok();
        writeln!(
            fmt,
            "  set_segm_name({startea:#X}, {:?});",
            seg_name
                .as_ref()
                .map(std::borrow::Borrow::borrow)
                .unwrap_or_else(|| "[NONAME]")
        )?;

        let seg_class_name = id0
            .segment_name(seg.class_id)
            .map(IDBStr::as_utf8_lossy)
            .ok();
        let seg_class_name = seg_class_name.or(seg_name).unwrap_or({
            Cow::Borrowed(match seg.seg_type {
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
            })
        });
        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb7699
        writeln!(fmt, "  set_segm_class({startea:#X}, {seg_class_name:?});")?;

        //// TODO InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0xb76ac
        //for _def_ref in seg.defsr.iter().filter(|x| **x != 0) {
        //    writeln!(fmt, "SegDefReg({startea:#X}, {seg_class_raw:?}, {:X});")?;
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
    let root_netnode = id0.root_node()?;
    let ida_info = id0.ida_info(root_netnode)?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_LOW_OFF, {:#X});",
        ida_info
            .suspiciousness_limits
            .low
            .map(|x| x.into_raw())
            .unwrap_or(0u8.into())
    )?;
    writeln!(
        fmt,
        "  set_inf_attr(INF_HIGH_OFF, {:#X});",
        ida_info
            .suspiciousness_limits
            .high
            .map(|x| x.into_raw())
            .unwrap_or(0u8.into())
    )?;

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
    let Some(patches_idx) = id0.segment_patches_idx()? else {
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
        match patch {
            Err(e) => {
                writeln!(fmt, "  patch_byte(-1, [NOPATCH: {e}]);")?;
                break;
            }
            Ok(patch) => {
                let address = patch.address;
                let value = id1
                    .byte_by_address(patch.address.into())
                    .map(|x| x.as_raw())
                    .unwrap_or(0);
                writeln!(fmt, "  patch_byte({address:#X}, {value:X});")?;
            }
        }
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
        writeln!(fmt, "  p_cmt = {:?};", cmt.as_utf8_lossy())?;
    }
    if have_fldcmts {
        writeln!(fmt, "  p_fldcmts = \"TODO\";")?;
    }
    let ord = ty.ordinal;
    let name = ty.name.as_utf8_lossy();
    write!(fmt, "  load_type(ltf, {ord}, {name:?}, p_type")?;
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
    id2: Option<&ID2Section<K>>,
    _til: &TILSection,
    image_base: Option<Address<K>>,
    netdelta: Netdelta<K>,
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

    for (address_info, len_bytes) in all_address_info(id0, id1, id2, netdelta) {
        let address = address_info.address();
        let address_raw = address.into_raw();
        let byte_info = address_info.byte_info();
        if let Some(addr_info) =
            AddressInfo::new(id0, id1, id2, netdelta, address)
        {
            // print comments
            // TODO byte_info.has_comment() ignored?
            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1822
            if let Some(cmt) = addr_info.comment() {
                writeln!(fmt, "  set_cmt({address_raw:#X}, {cmt:?}, 0);")?;
            }

            if let Some(cmt) = addr_info.comment_repeatable() {
                writeln!(fmt, "  set_cmt({address_raw:#X}, {cmt:?}, 1);")?;
            }

            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1ddd
            for (i, cmt) in
                addr_info.comment_pre().into_iter().flatten().enumerate()
            {
                writeln!(
                    fmt,
                    "  update_extra_cmt({address_raw:#X}, E_PREV + {i:>3}, {cmt:?});"
                )?;
            }

            for (i, cmt) in
                addr_info.comment_post().into_iter().flatten().enumerate()
            {
                writeln!(
                    fmt,
                    "  update_extra_cmt({address_raw:#X}, E_NEXT + {i:>3}, {cmt:?});"
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

        let set_x = if byte_info.op_invert_sig()
            || byte_info.op_bitwise_negation()
        {
            true
        } else {
            fn is_set_x(value: Option<ByteOp>) -> bool {
                matches!(
                    value,
                    Some(
                        ByteOp::Offset
                            | ByteOp::Seg
                            | ByteOp::Char
                            | ByteOp::Enum
                            | ByteOp::StructOffset
                            | ByteOp::StackVariable
                            | ByteOp::Hex
                            | ByteOp::Dec
                            | ByteOp::Bin
                            | ByteOp::Oct
                    )
                )
            }
            match byte_info.byte_type() {
                ByteType::Data(byte_data) => is_set_x(byte_data.operand0()?),
                ByteType::Code(byte_code) => {
                    let byte_code = byte_code.extend(id0, address_raw)?;
                    (0..8)
                        .map(|i| byte_code.operand_n(i).map(is_set_x))
                        .find_map(|x| match x {
                            Err(x) => Some(Err(x)),
                            Ok(true) => Some(Ok(())),
                            Ok(false) => None,
                        })
                        .transpose()?
                        .is_some()
                }
                ByteType::Tail(_) | ByteType::Unknown => false,
            }
        };
        let set_x_value = if set_x { "x=" } else { "" };

        match byte_info.byte_type() {
            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1dee
            ByteType::Code(byte_code) => {
                let byte_code = byte_code.extend(id0, address_raw)?;
                if !byte_code.exec_flow_from_prev_inst()
                    || byte_code.is_func_start()
                    || set_x
                {
                    writeln!(
                        fmt,
                        "  create_insn({set_x_value}{address_raw:#X});",
                    )?;
                }
                produce_bytes_info_op_code(
                    fmt, id0, id1, address, image_base, netdelta, byte_code,
                )?;
            }
            // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b1e37
            ByteType::Data(byte_data) => {
                match byte_data.data_type() {
                    ByteDataType::Strlit => writeln!(
                        fmt,
                        "  create_strlit({address_raw:#X}, {len_bytes:#X});",
                    )?,
                    ByteDataType::Dword => {
                        writeln!(
                            fmt,
                            "  create_dword({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_array(
                            fmt, address, set_x, len_bytes, 4,
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Byte => {
                        writeln!(
                            fmt,
                            "  create_byte({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_array(
                            fmt, address, set_x, len_bytes, 1,
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Word => {
                        writeln!(
                            fmt,
                            "  create_word({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_array(
                            fmt, address, set_x, len_bytes, 2,
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Qword => {
                        writeln!(
                            fmt,
                            "  create_qword({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_array(
                            fmt, address, set_x, len_bytes, 8,
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Tbyte => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO make array?
                        writeln!(
                            fmt,
                            "  create_tbyte({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Float => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO make array?
                        writeln!(
                            fmt,
                            "  create_float({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Packreal => {
                        writeln!(
                            fmt,
                            "  create_pack_real({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Yword => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO make array?
                        writeln!(
                            fmt,
                            "  create_yword({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Double => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO make array?
                        writeln!(
                            fmt,
                            "  create_double({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Oword => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO make array?
                        writeln!(
                            fmt,
                            "  create_oword({set_x_value}{address_raw:#X});"
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2690
                    ByteDataType::Struct => {
                        let _len = count_element(len_bytes, 1)?;
                        // TODO ensure struct have the same len that _len
                        // TODO make a struct_def_at
                        // TODO make array?
                        // TODO DB allow multiple refs into the same addr
                        // how to handle that?
                        let mut struct_ids = address_info.tinfo_ref();
                        let struct_id = struct_ids.next().transpose()?;
                        ensure!(struct_ids.next().is_none());
                        let struct_name = struct_id
                            .and_then(|idx| id0.struct_at(idx).ok())
                            .unwrap_or(b"BAD_STRUCT");
                        writeln!(
                            fmt,
                            "  create_struct({address_raw:#X}, -1, {:?});",
                            core::str::from_utf8(struct_name).unwrap()
                        )?;
                        produce_bytes_info_op_data(
                            fmt, id0, id1, address, image_base, netdelta,
                            byte_data,
                        )?;
                    }
                    ByteDataType::Align => {
                        produce_bytes_info_array(
                            fmt, address, set_x, len_bytes, 1,
                        )?;
                    }
                    ByteDataType::Zword | ByteDataType::Custom => {
                        let _len = count_element(len_bytes, 1)?;
                        //TODO
                    }
                    ByteDataType::Reserved => {
                        todo!();
                    }
                }
                // TODO  get_data_elsize
                // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2622
            }
            ByteType::Tail(_) => {
                return Err(anyhow!(
                    "Unexpected ID1 Tail entry: {address_raw:#X}"
                ))
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
        if let Some(name) = address_info.label()? {
            writeln!(fmt, "  set_name({address_raw:#X}, {name:?});")?;
        }
    }

    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b28ea
    // TODO add_func and other getn_func related functions

    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x1b2fee
    // TODO getn_fchunk related stuff

    writeln!(fmt, "}}")?;
    Ok(())
}

fn produce_bytes_info_array<K: IDAKind>(
    fmt: &mut impl Write,
    address: Address<K>,
    set_x: bool,
    len_bytes: usize,
    data_len: usize,
) -> Result<()> {
    let len = count_element(len_bytes, data_len)?;
    if len > 1 {
        if set_x {
            writeln!(fmt, "  make_array(x, {len:#X});")?
        } else {
            writeln!(fmt, "  make_array({:#X}, {len:#X});", address.into_raw())?
        }
    }
    Ok(())
}

fn produce_bytes_info_op_code<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    id1: &ID1Section,
    address: Address<K>,
    image_base: Option<Address<K>>,
    netdelta: Netdelta<K>,
    code: ByteExtended<ByteCode>,
) -> Result<()> {
    for n in 0..8 {
        if code.is_invsign(n)? {
            writeln!(fmt, "  toggle_sign(x, {n});")?;
        }
        if code.is_bnot(n)? {
            writeln!(fmt, "  toggle_sign(x, {n});")?;
        }

        if let Some(op) = code.operand_n(n)? {
            produce_bytes_info_op_op(
                fmt, id0, id1, address, image_base, netdelta, op, n,
            )?;
        }
    }

    Ok(())
}

fn produce_bytes_info_op_data<K: IDAKind>(
    fmt: &mut impl Write,
    _id0: &ID0Section<K>,
    _id1: &ID1Section,
    address: Address<K>,
    image_base: Option<Address<K>>,
    netdelta: Netdelta<K>,
    data: ByteData,
) -> Result<()> {
    if data.op_invert_sig() {
        writeln!(fmt, "  toggle_sign(x, 0);")?;
    }
    if data.op_bitwise_negation() {
        writeln!(fmt, "  toggle_sign(x, 0);")?;
    }

    if let Some(op) = data.operand0()? {
        produce_bytes_info_op_op(
            fmt, _id0, _id1, address, image_base, netdelta, op, 0,
        )?;
    };
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn produce_bytes_info_op_op<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    _id1: &ID1Section,
    address: Address<K>,
    image_base: Option<Address<K>>,
    netdelta: Netdelta<K>,
    data: ByteOp,
    n: u8,
) -> Result<()> {
    match data {
        ByteOp::Char => writeln!(fmt, "  op_chr(x, {n});")?,
        ByteOp::Seg => writeln!(fmt, "  op_seg(x, {n});")?,
        ByteOp::Offset => {
            let n_2 = n | 0x80;
            let ref_info = id0
                .reference_info(netdelta, address, n)?
                .unwrap_or(ReferenceInfo::default());
            let flags = ref_info.flags.into_primitive();
            let target = ref_info
                .target
                .map(|target| format!("{:#X}", target.into_raw()))
                .unwrap_or("BADADDR".into());
            let base = if ref_info.flags.is_based_reference() {
                image_base.map(Address::into_raw).unwrap_or(0u8.into())
            } else if ref_info.flags.is_self_ref() {
                address.into_raw()
            } else {
                ref_info
                    .base
                    .map(NetnodeIdx::into_raw)
                    .unwrap_or(0u8.into())
            };
            let tdelta = ref_info.tdelta.unwrap_or(0u8.into());
            writeln!(
                fmt,
                "  op_offset(x, {n}, {flags:#X}, {target}, {base:#X}, {tdelta:#X});"
            )?;
            writeln!(
                fmt,
                "  op_offset(x, {n_2}, {flags:#X}, {target}, {base:#X}, {tdelta:#X});"
            )?;
        }
        ByteOp::Enum => {
            // TODO check if typid & 0x100 != 0 && get_tinfo_pdata(GTP_NAME) != 0
            if let Some(enum_tid) = id0.sup_value(
                netdelta.ea2node(address),
                0xbu8.into(),
                ARRAY_ALT_TAG,
            ) {
                let netnode = NetnodeIdx::from_raw(
                    K::usize_try_from_le_bytes(enum_tid)
                        .map(|x| x - 1u8.into())
                        .ok_or_else(|| anyhow!("Invalid Enum typid value"))?,
                );
                let enum_name = id0
                    .netnode_name(netnode)
                    .map(String::from_utf8_lossy)
                    .unwrap_or("".into());
                // TODO find the serial or implement get_enum_id
                let serial = 0;
                writeln!(
                    fmt,
                    "  op_enum(x, {n}, get_enum({enum_name:?}), {serial});"
                )?
            }
        }
        ByteOp::ForceOp => todo!(),
        ByteOp::StructOffset => {
            writeln!(fmt, "  op_stroff(x, {n}, get_struc_id(\"TODO\"), TODO);")?
        }
        ByteOp::StackVariable => writeln!(fmt, "  op_stkvar(x, {n});")?,
        ByteOp::Hex => writeln!(fmt, "  op_hex(x, {n});")?,
        ByteOp::Dec => writeln!(fmt, "  op_dec(x, {n});")?,
        ByteOp::Oct => writeln!(fmt, "  op_oct(x, {n});")?,
        ByteOp::Bin => writeln!(fmt, "  op_bin(x, {n});")?,
        ByteOp::Float | ByteOp::Custom => {}
    }
    Ok(())
}

fn produce_functions<K: IDAKind>(
    fmt: &mut impl Write,
    id0: &ID0Section<K>,
    _til: &TILSection,
    netdelta: Netdelta<K>,
) -> Result<()> {
    use idb_rs::id0::function::FunctionsAndComments;
    use idb_rs::id0::function::FunctionsAndComments::*;
    use idb_rs::id0::function::IDBFunctionType::*;

    // TODO find the InnerRef for this, maybe it's just `$ dirtree/funcs`
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(());
    };
    let id0_funcs = id0.functions_and_comments(idx);
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
        let addr = fun.address.start.into_raw();
        let addr_end = fun.address.end.into_raw();
        writeln!(fmt, "  add_func({addr:#X}, {addr_end:#X});")?;
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
        for (address, label) in id0.local_labels(netdelta, fun.address.start)? {
            writeln!(
                fmt,
                "  set_name({:#X}, {:?}, SN_LOCAL);",
                address.into_raw(),
                String::from_utf8_lossy(&label),
            )?;
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

fn count_element(len_bytes: usize, len_elements: usize) -> Result<usize> {
    ensure!(len_bytes >= len_elements, "Expected more ID1 Tail entries");
    ensure!(
        len_bytes % len_elements == 0,
        "More ID1 Tails that expects or invalid array len"
    );
    Ok(len_bytes / len_elements)
}
