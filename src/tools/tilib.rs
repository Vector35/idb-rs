use idb_rs::id0::{Compiler, Id0TilOrd};
use idb_rs::til::array::Array;
use idb_rs::til::function::{CallingConvention, Function};
use idb_rs::til::pointer::Pointer;
use idb_rs::til::r#enum::Enum;
use idb_rs::til::r#struct::{Struct, StructMemberAtt};
use idb_rs::til::section::TILSection;
use idb_rs::til::union::Union;
use idb_rs::til::{Basic, TILTypeInfo, Type, TypeVariant, Typedef};

use std::borrow::Borrow;
use std::fs::File;
use std::io::{BufReader, Result, Write};
use std::num::NonZeroU8;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Parse IDA files and output it's data
#[derive(Clone, Debug, Parser)]
struct Args {
    #[command(subcommand)]
    operation: Operation,
    /// til-file
    #[arg(short, long)]
    input: PathBuf,
}

/// File type to parse
#[derive(Clone, Debug, Subcommand)]
enum Operation {
    /// show til-file contents
    PrintTil,
}

fn main() {
    let args = Args::parse();

    let file = BufReader::new(File::open(&args.input).unwrap());
    let section = TILSection::parse(file).unwrap();
    match &args.operation {
        Operation::PrintTil => print_til_section(std::io::stdout(), &section).unwrap(),
    }
}

fn print_til_section(mut fmt: impl Write, section: &TILSection) -> Result<()> {
    if let Some(dependency) = &section.dependency {
        let dep = core::str::from_utf8(dependency).unwrap();
        // TODO open those files? What todo with then?
        // TODO some files still missing this warning
        writeln!(fmt, "Warning: {dep}: No such file or directory")?;
    }

    writeln!(fmt)?;
    writeln!(fmt, "TYPE INFORMATION LIBRARY CONTENTS")?;
    print_header(&mut fmt, section)?;
    writeln!(fmt)?;

    writeln!(fmt, "SYMBOLS")?;
    print_symbols(&mut fmt, section)?;
    writeln!(fmt)?;

    writeln!(fmt, "TYPES")?;
    print_types(&mut fmt, section)?;
    writeln!(fmt)?;

    // TODO streams

    writeln!(fmt, "MACROS")?;
    print_macros(&mut fmt, section)?;
    writeln!(fmt)?;

    print_types_total(&mut fmt, section)?;

    Ok(())
}

fn print_header(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    // the description of the file
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b710
    writeln!(
        fmt,
        "Description: {}",
        core::str::from_utf8(&section.title).unwrap()
    )?;

    // flags from the section header
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b721
    print_section_flags(fmt, section)?;

    // base tils
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b775
    write!(fmt, "Base tils  : ")?;
    // TODO get the base tils
    //for (i, base) in section.base_tils.iter().enumerate() {
    //    write!(fmt, "{}", base)?;
    //    if i != section.base_tils.len() - 1 {
    //        write!(fmt, ", ")?;
    //    }
    //}
    writeln!(fmt)?;

    // compiler name
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b8c5
    writeln!(
        fmt,
        "Compiler   : {}",
        compiler_id_to_str(section.compiler_id)
    )?;

    // alignement and convention stuff
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b7ed
    if let Some((near, far)) = section.sizeof_near_far() {
        write!(fmt, "sizeof(near*) = {near} sizeof(far*) = {far}",)?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40ba3b
    if let Some((is_code_near, is_data_near)) = section.is_code_data_near() {
        if section.sizeof_near_far().is_some() {
            write!(fmt, " ")?;
        }
        let code = if is_code_near { "near" } else { "far" };
        let data = if is_data_near { "near" } else { "far" };
        write!(fmt, "{code} code, {data} data",)?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b860
    if section.cm & 0xc != 0 {
        if let Some(cc) = section.calling_convention() {
            if section.sizeof_near_far().is_some() || section.is_code_data_near().is_some() {
                write!(fmt, ",")?;
            }
            writeln!(fmt, "{}", calling_convention_to_str(cc))?;
        }
    }
    writeln!(fmt)?;

    // alignment
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b8e4
    writeln!(
        fmt,
        "default_align = {} sizeof(bool) = {} sizeof(long)  = {} sizeof(llong) = {}",
        section.def_align.map(|x| x.get()).unwrap_or(0),
        section.size_bool,
        section.sizeof_long(),
        section.sizeof_long_long(),
    )?;
    writeln!(
        fmt,
        "sizeof(enum) = {} sizeof(int) = {} sizeof(short) = {}",
        section.size_enum.map(NonZeroU8::get).unwrap_or(0),
        section.size_int,
        section.sizeof_short(),
    )?;
    writeln!(
        fmt,
        "sizeof(long double) = {}",
        section.size_long_double.map(NonZeroU8::get).unwrap_or(0)
    )?;
    Ok(())
}

fn print_section_flags(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    write!(fmt, "Flags      : {:04X}", section.flags.as_raw())?;
    if section.flags.is_zip() {
        write!(fmt, " compressed")?;
    }
    if section.flags.has_macro_table() {
        write!(fmt, " macro_table_present")?;
    }
    if section.flags.have_extended_sizeof_info() {
        write!(fmt, " extended_sizeof_info")?;
    }
    if section.flags.is_universal() {
        write!(fmt, " universal")?;
    }
    if section.flags.has_ordinal() {
        write!(fmt, " ordinals_present")?;
    }
    if section.flags.has_type_aliases() {
        write!(fmt, " aliases_present")?;
    }
    if section.flags.has_extra_stream() {
        write!(fmt, " extra_streams")?;
    }
    if section.flags.has_size_long_double() {
        write!(fmt, " sizeof_long_double")?;
    }
    writeln!(fmt)
}

fn compiler_id_to_str(compiler: Compiler) -> &'static str {
    match compiler {
        Compiler::Unknown => "Unknown",
        Compiler::VisualStudio => "Visual C++",
        Compiler::Borland => "Borland C++",
        Compiler::Watcom => "Watcom C++",
        Compiler::Gnu => "GNU C++",
        Compiler::VisualAge => "Visual Age C++",
        Compiler::Delphi => "Delphi",
        Compiler::Other => "?",
    }
}

fn print_symbols(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    for symbol in &section.symbols {
        print_til_type_len(fmt, section, None, &symbol.tinfo)?;
        let len = section.type_size_bytes(None, &symbol.tinfo).ok();
        match len {
            // TODO What is that???? Find it in InnerRef...
            Some(8) => write!(fmt, " {:016X}          ", symbol.ordinal)?,
            // TODO is limited to 32bits in InnerRef?
            _ => write!(fmt, " {:08X}          ", symbol.ordinal & 0xFFFF_FFFF)?,
        }
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type(fmt, section, Some(name), &symbol.tinfo, true, false)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_types(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    writeln!(fmt, "(enumerated by ordinals)")?;
    print_types_by_ordinals(fmt, section)?;
    writeln!(fmt, "(enumerated by names)")?;
    print_types_by_name(fmt, section)?;
    Ok(())
}

fn print_types_by_ordinals(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    enum OrdType<'a> {
        Alias(&'a (u32, u32)),
        Type { idx: usize, ty: &'a TILTypeInfo },
    }
    let mut types_sort: Vec<OrdType> = section
        .types
        .iter()
        .enumerate()
        .map(|(idx, ty)| OrdType::Type { idx, ty })
        .chain(
            section
                .type_ordinal_alias
                .iter()
                .flat_map(|x| x.iter())
                .map(OrdType::Alias),
        )
        .collect();
    types_sort.sort_by_key(|ord| match ord {
        OrdType::Alias(x) => x.0.into(),
        OrdType::Type { ty, .. } => ty.ordinal,
    });
    for ord_type in types_sort {
        let ord_num = match ord_type {
            OrdType::Alias((ord, _)) => (*ord).into(),
            OrdType::Type { ty, .. } => ty.ordinal,
        };
        let (idx, final_type) = match ord_type {
            OrdType::Alias((_alias_ord, type_ord)) => {
                let idx = section
                    .get_ord_idx(Id0TilOrd {
                        ord: (*type_ord).into(),
                    })
                    .unwrap();
                let ty = section.get_type_by_idx(idx);
                (idx, ty)
            }
            OrdType::Type { idx, ty } => (idx, ty),
        };
        print_til_type_len(fmt, section, Some(idx), &final_type.tinfo).unwrap();
        write!(fmt, "{:5}. ", ord_num)?;
        if let OrdType::Alias((_alias_ord, type_ord)) = ord_type {
            write!(fmt, "(aliased to {type_ord}) ")?;
        }
        let name = std::str::from_utf8(&final_type.name).unwrap();
        print_til_type_root(fmt, section, Some(name), &final_type.tinfo)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_types_by_name(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    for (idx, symbol) in section.types.iter().enumerate() {
        if symbol.name.is_empty() {
            continue;
        }
        print_til_type_len(fmt, section, Some(idx), &symbol.tinfo).unwrap();
        write!(fmt, " ")?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type_root(fmt, section, Some(name), &symbol.tinfo)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_til_type_root(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_type: &Type,
) -> Result<()> {
    match &til_type.type_variant {
        TypeVariant::Struct(_) | TypeVariant::Union(_) | TypeVariant::Enum(_) => {}
        _ => write!(fmt, "typedef ")?,
    }
    print_til_type(fmt, section, name, til_type, true, true)
}

fn print_til_type(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_type: &Type,
    print_pointer_space: bool,
    print_type_prefix: bool,
) -> Result<()> {
    if til_type.is_volatile {
        write!(fmt, "volatile ")?;
    }
    if til_type.is_const {
        write!(fmt, "const ")?;
    }
    match &til_type.type_variant {
        TypeVariant::Basic(til_basic) => print_til_type_basic(fmt, section, name, til_basic),
        TypeVariant::Pointer(pointer) => print_til_type_pointer(
            fmt,
            section,
            name,
            pointer,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Function(function) => {
            print_til_type_function(fmt, section, name, function, false)
        }
        TypeVariant::Array(array) => print_til_type_array(
            fmt,
            section,
            name,
            array,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Typedef(typedef) => print_til_type_typedef(fmt, section, name, typedef),
        TypeVariant::StructRef(ref_type) => print_til_type(
            fmt,
            section,
            name,
            ref_type,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Struct(til_struct) => print_til_type_struct(fmt, section, name, til_struct),
        TypeVariant::UnionRef(ref_type) => {
            print_til_type(fmt, section, name, ref_type, true, print_type_prefix)
        }
        TypeVariant::Union(til_union) => print_til_type_union(fmt, section, name, til_union),
        TypeVariant::EnumRef(ref_type) => print_til_type(
            fmt,
            section,
            name,
            ref_type,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Enum(til_enum) => print_til_type_enum(fmt, section, name, til_enum),
        TypeVariant::Bitfield(_bitfield) => write!(fmt, "todo!(\"Bitfield\")"),
    }
}

fn print_til_type_basic(
    fmt: &mut impl Write,
    _section: &TILSection,
    name: Option<&str>,
    til_basic: &Basic,
) -> Result<()> {
    const fn signed_name(is_signed: Option<bool>) -> &'static str {
        match is_signed {
            Some(true) | None => "",
            Some(false) => "unsigned ",
        }
    }

    let name_space = if name.is_some() { " " } else { "" };
    let name = name.unwrap_or("");
    match til_basic {
        Basic::Bool => write!(fmt, "bool{name_space}{name}",)?,
        Basic::Char => write!(fmt, "char{name_space}{name}",)?,
        Basic::Short { is_signed } => {
            write!(fmt, "{}short{name_space}{name}", signed_name(*is_signed))?
        }
        Basic::Void => write!(fmt, "void{name_space}{name}",)?,
        Basic::SegReg => write!(fmt, "SegReg{name_space}{name}")?,
        Basic::Unknown { bytes: 1 } => write!(fmt, "_BYTE")?,
        Basic::Unknown { bytes: 2 } => write!(fmt, "_WORD")?,
        Basic::Unknown { bytes: 4 } => write!(fmt, "_DWORD")?,
        Basic::Unknown { bytes: 8 } => write!(fmt, "_QWORD")?,
        Basic::Unknown { bytes } => write!(fmt, "unknown{bytes}{name_space}{name}")?,
        Basic::Int { is_signed } => {
            write!(fmt, "{}int{name_space}{name}", signed_name(*is_signed))?
        }
        Basic::Long { is_signed } => {
            write!(fmt, "{}long{name_space}{name}", signed_name(*is_signed))?
        }
        Basic::LongLong { is_signed } => {
            write!(fmt, "{}longlong{name_space}{name}", signed_name(*is_signed))?
        }
        Basic::IntSized { bytes, is_signed } => {
            if let Some(false) = is_signed {
                write!(fmt, "unsigned ")?;
            }
            write!(fmt, "__int{}{name_space}{name}", bytes.get() * 8)?
        }
        Basic::LongDouble => write!(fmt, "longfloat{name_space}{name}")?,
        Basic::Float { bytes } if bytes.get() == 4 => write!(fmt, "float{name_space}{name}")?,
        Basic::Float { bytes } if bytes.get() == 8 => write!(fmt, "double{name_space}{name}")?,
        Basic::Float { bytes } => write!(fmt, "float{bytes}{name_space}{name}")?,
        Basic::BoolSized { bytes } if bytes.get() == 1 => write!(fmt, "bool{name_space}{name}")?,
        Basic::BoolSized { bytes } => write!(fmt, "bool{bytes}{name_space}{name}")?,
    }
    Ok(())
}

fn print_til_type_pointer(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    pointer: &Pointer,
    print_pointer_space: bool,
    print_type_prefix: bool,
) -> Result<()> {
    if let TypeVariant::Function(inner_fun) = &pointer.typ.type_variant {
        // How to handle modifier here?
        print_til_type_function(fmt, section, name, inner_fun, true)?;
    } else {
        // TODO name
        print_til_type(
            fmt,
            section,
            None,
            &pointer.typ,
            print_pointer_space,
            print_type_prefix,
        )?;
        if print_pointer_space {
            write!(fmt, " ")?;
        }
        let modifier = match pointer.modifier {
            None => "",
            Some(idb_rs::til::pointer::PointerModifier::Ptr32) => "__ptr32 ",
            Some(idb_rs::til::pointer::PointerModifier::Ptr64) => "__ptr64 ",
            Some(idb_rs::til::pointer::PointerModifier::Restricted) => "__restricted ",
        };
        write!(fmt, "*{modifier}{}", name.unwrap_or(""))?;
    }
    Ok(())
}

fn print_til_type_function(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_type: &Function,
    is_pointer: bool,
) -> Result<()> {
    // return type
    print_til_type(fmt, section, None, &til_type.ret, false, true)?;

    // print name and calling convention, except for Ellipsis, just put the "..." as last param
    let name = name.unwrap_or("");
    let cc = (section.calling_convention() != Some(til_type.calling_convention)
        && til_type.calling_convention != CallingConvention::Ellipsis)
        .then(|| calling_convention_to_str(til_type.calling_convention));
    match (is_pointer, cc) {
        (true, None) => write!(fmt, " (*{name})")?,
        (false, None) => write!(fmt, " {name}")?,
        (true, Some(cc)) => write!(fmt, " ({cc} *{name})")?,
        (false, Some(cc)) => write!(fmt, " {cc} {name}")?,
    }

    write!(fmt, "(")?;
    for (i, (param_name, param, _argloc)) in til_type.args.iter().enumerate() {
        if i != 0 {
            write!(fmt, ", ")?;
        }
        let param_name = param_name
            .as_ref()
            .map(|name| String::from_utf8_lossy(&name[..]));
        print_til_type(
            fmt,
            section,
            param_name.as_ref().map(|name| name.borrow()),
            param,
            true,
            false,
        )?;
    }
    if til_type.calling_convention == CallingConvention::Ellipsis {
        if !til_type.args.is_empty() {
            write!(fmt, ", ")?;
        }
        write!(fmt, "...")?;
    }
    write!(fmt, ")")
}

fn print_til_type_array(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_array: &Array,
    print_pointer_space: bool,
    print_type_prefix: bool,
) -> Result<()> {
    print_til_type(
        fmt,
        section,
        None,
        &til_array.elem_type,
        print_pointer_space,
        print_type_prefix,
    )?;
    let name_space = if name.is_some() { " " } else { "" };
    let name = name.unwrap_or("");
    write!(fmt, "{name_space}{name}")?;
    if til_array.nelem != 0 {
        write!(fmt, "[{}]", til_array.nelem)?;
    } else {
        write!(fmt, "[]")?;
    }
    Ok(())
}

fn print_til_type_typedef(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    typedef: &Typedef,
) -> Result<()> {
    // only print prefix, if is root
    match typedef {
        idb_rs::til::Typedef::Ordinal(ord) => {
            let ty = section
                .get_ord(idb_rs::id0::Id0TilOrd { ord: (*ord).into() })
                .unwrap();
            print_til_type_name(fmt, &ty.name, &ty.tinfo, false)?;
        }
        idb_rs::til::Typedef::Name(name) => {
            let ty = section.get_name(name);
            match ty {
                Some(ty) => print_til_type_name(fmt, &ty.name, &ty.tinfo, false)?,
                // if we can't find the type, just print the name
                None => write!(fmt, "{}", core::str::from_utf8(name).unwrap())?,
            }
        }
    }
    let name_space = if name.is_some() { " " } else { "" };
    let name = name.unwrap_or("");
    write!(fmt, "{name_space}{name}")
}

fn print_til_type_struct(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_struct: &Struct,
) -> Result<()> {
    let name = name.unwrap_or("");
    write!(fmt, "struct ")?;
    if til_struct.is_unaligned {
        write!(fmt, "__unaligned ")?;
    }
    if til_struct.is_msstruct {
        write!(fmt, "__attribute__((msstruct)) ")?;
    }
    if til_struct.is_cpp_obj {
        write!(fmt, "__cppobj ")?;
    }
    if til_struct.is_vftable {
        write!(fmt, "/*VFT*/ ")?;
    }
    if let Some(align) = til_struct.alignment {
        write!(fmt, "__attribute__((aligned({align}))) ")?;
    }
    if let Some(others) = til_struct.others {
        write!(fmt, "__other({others:04x}) ")?;
    }
    write!(fmt, "{name} {{")?;
    for member in &til_struct.members {
        let name = member
            .name
            .as_ref()
            .map(|x| core::str::from_utf8(x).unwrap());
        print_til_type(fmt, section, name, &member.member_type, true, false)?;
        if let Some(att) = &member.att {
            print_til_struct_member_att(fmt, &member.member_type, att)?;
        }
        write!(fmt, ";")?;
    }
    write!(fmt, "}}")
}

fn print_til_type_union(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_union: &Union,
) -> Result<()> {
    let name = name.unwrap_or("");
    write!(fmt, "union ")?;
    if let Some(align) = til_union.alignment {
        write!(fmt, "__attribute__((aligned({align}))) ")?;
    }
    write!(fmt, "{name} {{")?;
    for (member_name, member) in &til_union.members {
        let member_name = member_name
            .as_ref()
            .map(|x| core::str::from_utf8(x).unwrap());
        print_til_type(fmt, section, member_name, member, true, false)?;
        write!(fmt, ";")?;
    }
    write!(fmt, "}}")
}

fn print_til_type_enum(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_enum: &Enum,
) -> Result<()> {
    use idb_rs::til::r#enum::EnumFormat::*;

    let name = name.unwrap_or("");
    let output_fmt_name = match til_enum.output_format {
        Char => "__char ",
        Hex => "",
        SignedDecimal => "__dec ",
        UnsignedDecimal => "__udec ",
    };
    write!(fmt, "enum {output_fmt_name}{name} ")?;
    match (til_enum.storage_size, section.size_enum) {
        (None, None) => {}
        (Some(storage_size), Some(size_enum)) => {
            if storage_size != size_enum {
                let bits_required = til_enum
                    .members
                    .iter()
                    .map(|(_, value)| u64::BITS - value.leading_zeros())
                    .max()
                    .map(|x| x.max(1)) //can't have a value being represented in 0bits
                    .unwrap_or(8);
                if bits_required / 8 < storage_size.get().into() {
                    write!(fmt, ": __int{} ", storage_size.get() as usize * 8)?;
                }
            }
        }
        (None, Some(_)) => {}
        (Some(_), None) => {}
    }
    write!(fmt, "{{")?;
    for (member_name, value) in &til_enum.members {
        let name = member_name
            .as_ref()
            .map(|x| core::str::from_utf8(x).unwrap())
            .unwrap_or("_");
        write!(fmt, "{name} = ")?;
        match til_enum.output_format {
            Char if *value <= 0xFF => write!(fmt, "'{}'", (*value) as u8 as char)?,
            Char => write!(fmt, "'\\xu{value:X}'")?,
            Hex => write!(fmt, "{value:#X}")?,
            SignedDecimal => write!(fmt, "{}", (*value) as i64)?,
            UnsignedDecimal => write!(fmt, "{value:X}")?,
        }
        // TODO find this in InnerRef
        if let Some(8) = til_enum.storage_size.map(NonZeroU8::get) {
            write!(fmt, "LL")?;
        }
        write!(fmt, ",")?;
    }
    write!(fmt, "}}")
}

fn print_til_struct_member_att(
    fmt: &mut impl Write,
    tinfo: &Type,
    att: &StructMemberAtt,
) -> Result<()> {
    match &tinfo.type_variant {
        TypeVariant::Pointer(pointer) => match &pointer.typ.type_variant {
            TypeVariant::Basic(Basic::Char) => print_til_struct_member_string_att(fmt, att)?,
            _ => {}
        },
        TypeVariant::Array(array) => match &array.elem_type.type_variant {
            TypeVariant::Basic(Basic::Char) => print_til_struct_member_string_att(fmt, att)?,
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn print_til_struct_member_string_att(fmt: &mut impl Write, att: &StructMemberAtt) -> Result<()> {
    let Some(value) = att.str_type() else {
        // todo att is unknown
        return Ok(());
    };
    write!(fmt, " __strlit(0x{:08X})", value.as_strlib())
}

fn print_til_type_name(
    fmt: &mut impl Write,
    name: &[u8],
    tinfo: &Type,
    print_prefix: bool,
) -> Result<()> {
    let name = String::from_utf8_lossy(name);
    let prefix = match &tinfo.type_variant {
        TypeVariant::Basic(_)
        | TypeVariant::Pointer(_)
        | TypeVariant::Function(_)
        | TypeVariant::Array(_)
        | TypeVariant::Typedef(_)
        | TypeVariant::Bitfield(_) => "",
        TypeVariant::UnionRef(_) | TypeVariant::Union(_) => "union ",
        TypeVariant::StructRef(_) | TypeVariant::Struct(_) => "struct ",
        TypeVariant::EnumRef(_) | TypeVariant::Enum(_) => "enum ",
    };
    write!(fmt, "{}{name}", if print_prefix { prefix } else { "" })
}

fn print_til_type_len(
    fmt: &mut impl Write,
    section: &TILSection,
    idx: Option<usize>,
    tinfo: &Type,
) -> Result<()> {
    if let TypeVariant::Function(_function) = &tinfo.type_variant {
        write!(fmt, "FFFFFFFF")?;
    } else {
        // if the type is unknown it just prints "FFFFFFF"
        let len = section.type_size_bytes(idx, tinfo).unwrap_or(0xFFFF_FFFF);
        write!(fmt, "{len:08X}")?;
    }
    Ok(())
}

fn calling_convention_to_str(cc: CallingConvention) -> &'static str {
    use idb_rs::til::function::CallingConvention::*;
    match cc {
        Unknown => "__unknown",
        Voidarg => "__voidarg",
        Cdecl => "__cdecl",
        Ellipsis => "__ellipsis",
        Stdcall => "__stdcall",
        Pascal => "__pascal",
        Fastcall => "__fastcall",
        Thiscall => "__thiscall",
        Swift => "__swift",
        Golang => "__golang",
        Userpurge => "__userpurge",
        Uservars => "__uservars",
        Usercall => "__usercall",
        Reserved3 => "__ccreserved3",
    }
}

fn print_macros(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    let macro_iter = section.macros.iter().flat_map(Vec::as_slice);
    for macro_entry in macro_iter {
        fmt.write_all(&macro_entry.name)?;
        let mut buf = vec![];
        if let Some(param_num) = macro_entry.param_num {
            buf.push(b'(');
            for i in 0..param_num {
                if i != 0 {
                    buf.push(b',');
                }
                buf.push(i | 0x80);
            }
            buf.push(b')');
            fmt.write_all(&buf)?;
            buf.clear();
        }
        write!(fmt, " ")?;
        buf.extend(macro_entry.value.iter().map(|c| match c {
            idb_rs::til::TILMacroValue::Char(c) => *c,
            idb_rs::til::TILMacroValue::Param(p) => *p | 0x80,
        }));
        fmt.write_all(&buf)?;
        writeln!(fmt)?;
    }
    Ok(())
}

fn print_types_total(fmt: &mut impl Write, section: &TILSection) -> Result<()> {
    let macros_num = section
        .macros
        .as_ref()
        .map(|macros| macros.len())
        .unwrap_or(0);
    let alias_num = section
        .type_ordinal_alias
        .as_ref()
        .map(Vec::len)
        .unwrap_or(0);
    let types_num = section.types.len() + alias_num;
    let symbols_num = section.symbols.len();
    writeln!(
        fmt,
        "Total {symbols_num} symbols, {types_num} types, {macros_num} macros"
    )
}
