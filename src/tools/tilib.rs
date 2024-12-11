use idb_rs::id0::Compiler;
use idb_rs::til::r#enum::Enum;
use idb_rs::til::r#struct::Struct;
use idb_rs::til::section::TILSection;
use idb_rs::til::union::Union;
use idb_rs::til::Basic;
use idb_rs::til::Type;

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
    writeln!(fmt, "")?;

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
        let code = is_code_near.then_some("near").unwrap_or("far");
        let data = is_data_near.then_some("near").unwrap_or("far");
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
        let len = symbol.tinfo.type_size_bytes(section).unwrap();
        write!(fmt, "{len:08X} {:08X}          ", symbol.ordinal)?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type(&mut fmt, section, Some(name), &symbol.tinfo)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt)?;

    writeln!(fmt, "TYPES")?;
    writeln!(fmt, "(enumerated by ordinals)")?;
    let mut types_sort: Vec<_> = section.types.iter().collect();
    types_sort.sort_by_key(|ord| ord.ordinal);
    for symbol in types_sort {
        let len = symbol.tinfo.type_size_bytes(section).unwrap();
        write!(fmt, "{len:08X}    {}. ", symbol.ordinal)?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type(&mut fmt, section, Some(name), &symbol.tinfo)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt, "(enumerated by names)")?;
    for symbol in &section.types {
        if symbol.name.len() == 0 {
            continue;
        }
        let len = symbol.tinfo.type_size_bytes(section).unwrap();
        write!(fmt, "{len:08X} ")?;
        let name = std::str::from_utf8(&symbol.name).unwrap();
        print_til_type(&mut fmt, section, Some(name), &symbol.tinfo)?;
        writeln!(fmt, ";")?;
    }
    writeln!(fmt)?;

    // macros
    writeln!(fmt, "MACROS")?;
    let macro_iter = section.macros.iter().map(|x| x.iter()).flatten();
    for macro_entry in macro_iter {
        let name = std::str::from_utf8(&macro_entry.name).unwrap();
        let value = std::str::from_utf8(&macro_entry.value).unwrap();
        writeln!(fmt, "{name} = {value}")?;
    }
    writeln!(fmt)?;

    // TODO streams

    let macros_num = section
        .macros
        .as_ref()
        .map(|macros| macros.len())
        .unwrap_or(0);
    let types_num = section.types.len();
    let symbols_num = section.symbols.len();
    writeln!(
        fmt,
        "Total {symbols_num} symbols, {types_num} types, {macros_num} macros"
    )
}

fn print_til_type(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&str>,
    til_type: &Type,
) -> std::io::Result<()> {
    let name_helper = name.map(|name| format!(" {name}")).unwrap_or(String::new());
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
            // TODO name
            print_til_type(fmt, section, None, &pointer.typ)?;
            write!(fmt, "*{name_helper}")
        }
        Type::Function(_function) => write!(fmt, "todo!()"),
        Type::Array(array) => {
            print_til_type(fmt, section, None, &array.elem_type)?;
            write!(fmt, "{name_helper}[{}]", array.nelem)
        }
        Type::Typedef(typedef) => match typedef {
            idb_rs::til::Typedef::Ordinal(ord) => {
                let ord_type = section
                    .get_ord(idb_rs::id0::Id0TilOrd { ord: (*ord).into() })
                    .unwrap();
                print_til_type_name(fmt, &ord_type.name, &ord_type.tinfo)?;
                write!(fmt, "{name_helper}")
            }
            idb_rs::til::Typedef::Name(vec) => {
                let name = core::str::from_utf8(&vec).unwrap();
                write!(fmt, "{name}{name_helper}")
            }
        },
        Type::Struct(str_type) => match str_type {
            Struct::Ref { ref_type, .. } => print_til_type(fmt, section, name, &*ref_type),
            Struct::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "struct {name} {{")?;
                for member in members {
                    print_til_type(
                        fmt,
                        section,
                        member
                            .name
                            .as_ref()
                            .map(|x| core::str::from_utf8(&x).unwrap()),
                        &member.member_type,
                    )?;
                    write!(fmt, ";")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Union(union_type) => match union_type {
            Union::Ref { ref_type, .. } => print_til_type(fmt, section, name, &*ref_type),
            Union::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "union {name} {{")?;
                for (member_name, member) in members {
                    print_til_type(
                        fmt,
                        section,
                        member_name
                            .as_ref()
                            .map(|x| core::str::from_utf8(&x).unwrap()),
                        member,
                    )?;
                    write!(fmt, ";")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Enum(enum_type) => match enum_type {
            Enum::Ref { ref_type, .. } => print_til_type(fmt, section, name, &*ref_type),
            Enum::NonRef { members, .. } => {
                let name = name.unwrap_or("");
                write!(fmt, "enum {name} {{")?;
                for (member_name, value) in members {
                    let name = member_name
                        .as_ref()
                        .map(|x| core::str::from_utf8(&x).unwrap())
                        .unwrap_or("_");
                    write!(fmt, "{name} = {value:#x},")?;
                }
                write!(fmt, "}}")
            }
        },
        Type::Bitfield(_bitfield) => write!(fmt, "todo!(\"function\")"),
    }
}

fn print_til_type_name(fmt: &mut impl Write, name: &[u8], tinfo: &Type) -> std::io::Result<()> {
    let name = String::from_utf8_lossy(name);
    match tinfo {
        Type::Basic(_)
        | Type::Pointer(_)
        | Type::Function(_)
        | Type::Array(_)
        | Type::Typedef(_)
        | Type::Bitfield(_) => write!(fmt, "{name}"),
        Type::Struct(_) => write!(fmt, "struct {name}"),
        Type::Union(_) => write!(fmt, "union {name}"),
        Type::Enum(_) => write!(fmt, "enum {name}"),
    }
}
