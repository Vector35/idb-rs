use idb_rs::id0::Compiler;
use idb_rs::til::function::Function;
use idb_rs::til::r#enum::Enum;
use idb_rs::til::r#struct::Struct;
use idb_rs::til::section::TILSection;
use idb_rs::til::union::Union;
use idb_rs::til::Basic;
use idb_rs::til::Type;

use std::borrow::Borrow;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
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

fn print_til_section(mut fmt: impl Write, section: &TILSection) -> std::io::Result<()> {
    if let Some(dependency) = &section.dependency {
        let dep = core::str::from_utf8(dependency).unwrap();
        // TODO open those files? What todo with then?
        writeln!(fmt, "Warning: {dep}: No such file or directory")?;
    }
    // TODO add missing dependencies: "Warning: gnulnx_x64: No such file or directory"
    writeln!(fmt)?;
    writeln!(fmt, "TYPE INFORMATION LIBRARY CONTENTS")?;

    // the description of the file
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b710
    writeln!(
        fmt,
        "Description: {}",
        core::str::from_utf8(&section.title).unwrap()
    )?;

    // flags from the section header
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b721
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
    writeln!(fmt)?;

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
    let compiler_name = match section.compiler_id {
        Compiler::Unknown => "Unknown",
        Compiler::VisualStudio => "Visual C++",
        Compiler::Borland => "Borland C++",
        Compiler::Watcom => "Watcom C++",
        Compiler::Gnu => "GNU C++",
        Compiler::VisualAge => "Visual Age C++",
        Compiler::Delphi => "Delphi",
        Compiler::Other => "?",
    };
    writeln!(fmt, "Compiler   : {}", compiler_name)?;

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
            use idb_rs::til::section::CallingConvention::*;
            let cc_name = match cc {
                CCInvalid => "ccinvalid",
                Voidarg => "voidarg",
                Cdecl => "cdecl",
                Ellipsis => "ellipsis",
                Stdcall => "stdcall",
                Pascal => "pascal",
                Fastcall => "fastcall",
                Thiscall => "thiscall",
                Swift => "swift",
                Golang => "golang",
                Userpurge => "userpurge",
                Uservars => "uservars",
                Usercall => "usercall",
            };
            writeln!(fmt, "{cc_name}")?;
        }
    }
    writeln!(fmt)?;

    // alignment
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b8e4
    writeln!(
        fmt,
        "default_align = {} sizeof(bool) = {} sizeof(long)  = {} sizeof(llong) = {}",
        section.def_align,
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
    writeln!(fmt)?;

    // Print Symbols
    writeln!(fmt, "SYMBOLS")?;
    for symbol in &section.symbols {
        print_til_type_len(&mut fmt, section, &symbol.tinfo).unwrap();
        write!(fmt, " {:08X}          ", symbol.ordinal)?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type_root(&mut fmt, section, Some(name), &symbol.tinfo, true)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt)?;

    writeln!(fmt, "TYPES")?;
    writeln!(fmt, "(enumerated by ordinals)")?;
    let mut types_sort: Vec<_> = section.types.iter().collect();
    types_sort.sort_by_key(|ord| ord.ordinal);
    for symbol in types_sort {
        print_til_type_len(&mut fmt, section, &symbol.tinfo).unwrap();
        write!(fmt, "{:5}. ", symbol.ordinal)?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type_root(&mut fmt, section, Some(name), &symbol.tinfo, false)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt, "(enumerated by names)")?;
    for symbol in &section.types {
        if symbol.name.is_empty() {
            continue;
        }
        print_til_type_len(&mut fmt, section, &symbol.tinfo).unwrap();
        write!(fmt, " ")?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type_root(&mut fmt, section, Some(name), &symbol.tinfo, false)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt)?;

    // macros
    writeln!(fmt, "MACROS")?;
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
    writeln!(fmt)?;

    // TODO streams

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

fn print_til_type_root(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_type: &Type,
    is_symbol: bool,
) -> std::io::Result<()> {
    if !is_symbol {
        match til_type {
            Type::Struct(Struct::NonRef { .. })
            | Type::Union(Union::NonRef { .. })
            | Type::Enum(Enum::NonRef { .. }) => {}
            _ => write!(fmt, "typedef ")?,
        }
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
) -> std::io::Result<()> {
    let name_helper = name.map(|name| format!(" {name}")).unwrap_or_default();
    const fn signed_name(is_signed: Option<bool>) -> &'static str {
        match is_signed {
            Some(true) | None => "",
            Some(false) => "unsigned ",
        }
    }

    match til_type {
        Type::Basic(Basic::Bool) => write!(fmt, "bool{name_helper}",),
        Type::Basic(Basic::Char) => write!(fmt, "char{name_helper}",),
        Type::Basic(Basic::Short { is_signed }) => {
            write!(fmt, "{}short{name_helper}", signed_name(*is_signed))
        }
        Type::Basic(Basic::Void) => write!(fmt, "void{name_helper}",),
        Type::Basic(Basic::SegReg) => write!(fmt, "SegReg{name_helper}"),
        Type::Basic(Basic::Unknown { bytes }) => write!(fmt, "unknown{bytes}{name_helper}"),
        Type::Basic(Basic::Int { is_signed }) => {
            write!(fmt, "{}int{name_helper}", signed_name(*is_signed))
        }
        Type::Basic(Basic::Long { is_signed }) => {
            write!(fmt, "{}long{name_helper}", signed_name(*is_signed))
        }
        Type::Basic(Basic::LongLong { is_signed }) => {
            write!(fmt, "{}longlong{name_helper}", signed_name(*is_signed))
        }
        Type::Basic(Basic::IntSized { bytes, is_signed }) => {
            match is_signed {
                Some(false) => write!(fmt, "unsigned ")?,
                Some(true) | None => {}
            }
            write!(fmt, "__int{}{name_helper}", bytes.get() * 8)
        }
        Type::Basic(Basic::LongDouble) => {
            write!(fmt, "longfloat{name_helper}")
        }
        Type::Basic(Basic::Float { bytes }) if bytes.get() == 4 => {
            write!(fmt, "float{name_helper}")
        }
        Type::Basic(Basic::Float { bytes }) if bytes.get() == 8 => {
            write!(fmt, "double{name_helper}")
        }
        Type::Basic(Basic::Float { bytes }) => write!(fmt, "float{bytes}{name_helper}"),
        Type::Basic(Basic::BoolSized { bytes }) if bytes.get() == 1 => {
            write!(fmt, "bool{name_helper}")
        }
        Type::Basic(Basic::BoolSized { bytes }) => write!(fmt, "bool{bytes}{name_helper}"),
        Type::Pointer(pointer) => {
            if let Type::Function(inner_fun) = &*pointer.typ {
                let name = format!("(*{})", name.unwrap_or(""));
                print_til_type_function(fmt, section, &name, inner_fun)
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
                write!(fmt, "*{}", name.unwrap_or(""))
            }
        }
        Type::Function(function) => {
            print_til_type_function(fmt, section, name.unwrap_or("_"), function)
        }
        Type::Array(array) => {
            print_til_type(
                fmt,
                section,
                None,
                &array.elem_type,
                print_pointer_space,
                print_type_prefix,
            )?;
            write!(fmt, "{name_helper}[{}]", array.nelem)
        }
        Type::Typedef(typedef) => {
            // only print prefix, if is root
            match typedef {
                idb_rs::til::Typedef::Ordinal(ord) => {
                    let ty = section
                        .get_ord(idb_rs::id0::Id0TilOrd { ord: (*ord).into() })
                        .unwrap();
                    print_til_type_name(fmt, &ty.name, &ty.tinfo, print_type_prefix)?;
                }
                idb_rs::til::Typedef::Name(name) => {
                    let ty = section.get_name(name);
                    match ty {
                        Some(ty) => {
                            print_til_type_name(fmt, &ty.name, &ty.tinfo, print_type_prefix)?
                        }
                        // if we can't find the type, just print the name
                        None => write!(fmt, "{}", core::str::from_utf8(name).unwrap())?,
                    }
                }
            }
            write!(fmt, "{name_helper}")
        }
        Type::Struct(str_type) => match str_type {
            Struct::Ref { ref_type, .. } => print_til_type(
                fmt,
                section,
                name,
                ref_type,
                print_pointer_space,
                print_type_prefix,
            ),
            Struct::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "struct {name} {{")?;
                for member in members {
                    let name = member
                        .name
                        .as_ref()
                        .map(|x| core::str::from_utf8(x).unwrap());
                    print_til_type(fmt, section, name, &member.member_type, true, false)?;
                    write!(fmt, ";")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Union(union_type) => match union_type {
            Union::Ref { ref_type, .. } => {
                print_til_type(fmt, section, name, ref_type, true, print_type_prefix)
            }
            Union::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "union {name} {{")?;
                for (member_name, member) in members {
                    let member_name = member_name
                        .as_ref()
                        .map(|x| core::str::from_utf8(x).unwrap());
                    print_til_type(fmt, section, member_name, member, true, false)?;
                    write!(fmt, ";")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Enum(enum_type) => match enum_type {
            Enum::Ref { ref_type, .. } => print_til_type(
                fmt,
                section,
                name,
                ref_type,
                print_pointer_space,
                print_type_prefix,
            ),
            Enum::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "enum {name} {{")?;
                for (member_name, value) in members {
                    let name = member_name
                        .as_ref()
                        .map(|x| core::str::from_utf8(x).unwrap())
                        .unwrap_or("_");
                    write!(fmt, "{name} = {value:#X},")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Bitfield(_bitfield) => write!(fmt, "todo!(\"function\")"),
    }
}

fn print_til_type_function(
    fmt: &mut impl Write,
    section: &TILSection,
    name: &str,
    til_type: &Function,
) -> std::io::Result<()> {
    print_til_type(fmt, section, None, &til_type.ret, false, true)?;
    write!(fmt, " {name}(")?;
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
    write!(fmt, ")")
}

fn print_til_type_name(
    fmt: &mut impl Write,
    name: &[u8],
    tinfo: &Type,
    print_prefix: bool,
) -> std::io::Result<()> {
    let name = String::from_utf8_lossy(name);
    let prefix = match tinfo {
        Type::Basic(_)
        | Type::Pointer(_)
        | Type::Function(_)
        | Type::Array(_)
        | Type::Typedef(_)
        | Type::Bitfield(_) => "",
        Type::Union(_) => "union ",
        Type::Struct(_) => "struct ",
        Type::Enum(_) => "enum ",
    };
    write!(fmt, "{}{name}", if print_prefix { prefix } else { "" })
}

fn print_til_type_len(
    fmt: &mut impl Write,
    section: &TILSection,
    tinfo: &Type,
) -> std::io::Result<()> {
    if let Type::Function(_function) = &tinfo {
        write!(fmt, "FFFFFFFF")?;
    } else {
        // if the type is unknown it just prints "FFFFFFF"
        let len = tinfo.type_size_bytes(section).ok().unwrap_or(0xFFFF_FFFF);
        write!(fmt, "{len:08X}")?;
    }
    Ok(())
}
