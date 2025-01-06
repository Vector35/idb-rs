use idb_rs::id0::{Compiler, Id0TilOrd};
use idb_rs::til::array::Array;
use idb_rs::til::bitfield::Bitfield;
use idb_rs::til::function::{CallingConvention, Function};
use idb_rs::til::pointer::Pointer;
use idb_rs::til::r#enum::Enum;
use idb_rs::til::r#struct::{Struct, StructMemberAtt};
use idb_rs::til::section::{TILSection, TILTypeSizeSolver};
use idb_rs::til::union::Union;
use idb_rs::til::{Basic, TILTypeInfo, Type, TypeVariant, Typedef};
use idb_rs::IDBParser;

use std::fs::File;
use std::io::{BufReader, Result, Write};
use std::num::NonZeroU8;

use crate::{Args, FileType};

pub fn tilib_print(args: &Args) -> anyhow::Result<()> {
    // parse the id0 sector/file
    let input = BufReader::new(File::open(&args.input)?);
    match args.input_type() {
        FileType::Til => {
            let section = TILSection::parse(input)?;
            print_til_section(std::io::stdout(), &section)?;
        }
        FileType::Idb => {
            let mut parser = IDBParser::new(input)?;
            let til_offset = parser
                .til_section_offset()
                .ok_or_else(|| anyhow::anyhow!("IDB file don't contains a TIL sector"))?;
            let section = parser.read_til_section(til_offset)?;
            print_til_section(std::io::stdout(), &section)?;
        }
    }
    Ok(())
}

fn print_til_section(mut fmt: impl Write, section: &TILSection) -> Result<()> {
    if let Some(dependency) = &section.dependency {
        // TODO open those files? What todo with then?
        // TODO some files still missing this warning
        if !dependency.is_empty() {
            write!(fmt, "Warning: ")?;
            fmt.write_all(dependency)?;
            writeln!(fmt, ": No such file or directory")?;
        }
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b6d0
    writeln!(fmt)?;
    writeln!(fmt, "TYPE INFORMATION LIBRARY CONTENTS")?;
    print_header(&mut fmt, section)?;
    writeln!(fmt)?;

    let mut size_solver = TILTypeSizeSolver::new(section);

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b926
    writeln!(fmt, "SYMBOLS")?;
    print_symbols(&mut fmt, section, &mut size_solver)?;
    writeln!(fmt)?;

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b94d
    writeln!(fmt, "TYPES")?;
    print_types(&mut fmt, section, &mut size_solver)?;
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
    write!(fmt, "Description: ")?;
    fmt.write_all(&section.title)?;
    writeln!(fmt)?;

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
    if let Some(cn) = section.cn {
        write!(
            fmt,
            "sizeof(near*) = {} sizeof(far*) = {}",
            cn.near_bytes(),
            cn.far_bytes()
        )?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40ba3b
    if let Some(cm) = section.cm {
        if section.cn.is_some() {
            write!(fmt, " ")?;
        }
        let code = if cm.is_code_near() { "near" } else { "far" };
        let data = if cm.is_data_near() { "near" } else { "far" };
        write!(fmt, "{code} code, {data} data",)?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b860
    if let Some(cc) = section.cc {
        if section.cm.is_some() || section.cn.is_some() {
            write!(fmt, ", ")?;
        }
        write!(fmt, "{}", calling_convention_to_str(cc))?;
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

fn print_symbols(
    fmt: &mut impl Write,
    section: &TILSection,
    solver: &mut TILTypeSizeSolver<'_>,
) -> Result<()> {
    for symbol in &section.symbols {
        print_til_type_len(fmt, None, &symbol.tinfo, solver)?;
        let len = solver.type_size_bytes(None, &symbol.tinfo);
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x409a80
        match len.and_then(|b| u32::try_from(b).ok()) {
            Some(8) => write!(fmt, " {:016X}", symbol.ordinal)?,
            Some(bytes @ 0..=7) => {
                write!(fmt, " {:08X}", symbol.ordinal & !(u64::MAX << (bytes * 8)))?
            }
            _ => write!(fmt, " {:08X}", symbol.ordinal)?,
        }

        // TODO find this in InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x409a49
        //let sym_kind = match arg8 {
        //    0 => "        ",
        //    1 => "typedef ",
        //    2 => "extern  ",
        //    3 => "static  ",
        //    4 => "register",
        //    5 => "auto    ",
        //    6 => "friend  ",
        //    7 => "virtual ",
        //    _ => "?!",
        //};
        let sym_kind = "        ";
        write!(fmt, " {} ", sym_kind)?;

        // TODO investiage this
        let name = if symbol.ordinal == 0 && symbol.name.get(0) == Some(&b'_') {
            // remove the first "_", if any
            &symbol.name[1..]
        } else {
            &symbol.name
        };
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x409a3a
        print_til_type(fmt, section, Some(name), &symbol.tinfo, true, false, true)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_types(
    fmt: &mut impl Write,
    section: &TILSection,
    solver: &mut TILTypeSizeSolver<'_>,
) -> Result<()> {
    // TODO only print by ordinals if there are ordinals
    writeln!(fmt, "(enumerated by ordinals)")?;
    print_types_by_ordinals(fmt, section, solver)?;
    writeln!(fmt, "(enumerated by names)")?;
    print_types_by_name(fmt, section, solver)?;
    Ok(())
}

fn print_types_by_ordinals(
    fmt: &mut impl Write,
    section: &TILSection,
    solver: &mut TILTypeSizeSolver<'_>,
) -> Result<()> {
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
        print_til_type_len(fmt, Some(idx), &final_type.tinfo, solver).unwrap();
        write!(fmt, "{:5}. ", ord_num)?;
        if let OrdType::Alias((_alias_ord, type_ord)) = ord_type {
            write!(fmt, "(aliased to {type_ord}) ")?;
        }
        print_til_type_root(fmt, section, Some(&final_type.name), &final_type.tinfo)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_types_by_name(
    fmt: &mut impl Write,
    section: &TILSection,
    solver: &mut TILTypeSizeSolver<'_>,
) -> Result<()> {
    for (idx, symbol) in section.types.iter().enumerate() {
        if symbol.name.is_empty() {
            continue;
        }
        print_til_type_len(fmt, Some(idx), &symbol.tinfo, solver).unwrap();
        write!(fmt, " ")?;
        print_til_type_root(fmt, section, Some(&symbol.name), &symbol.tinfo)?;
        writeln!(fmt, ";")?;
    }
    Ok(())
}

fn print_til_type_root(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
) -> Result<()> {
    // TODO: InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4438d1
    // TODO: if a is a typedef and ComplexRef or something like it, also print typedef
    match &til_type.type_variant {
        TypeVariant::Struct(_) | TypeVariant::Union(_) | TypeVariant::Enum(_) => {}
        TypeVariant::StructRef(Typedef::Name(None))
        | TypeVariant::UnionRef(Typedef::Name(None))
        | TypeVariant::EnumRef(Typedef::Name(None)) => {}
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x443906
        _ => write!(fmt, "typedef ")?,
    }
    print_til_type(fmt, section, name, til_type, true, true, true)
}

fn print_til_type(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    print_pointer_space: bool,
    print_type_prefix: bool,
    print_name: bool,
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
        TypeVariant::Typedef(ref_type) => {
            print_til_type_typedef(fmt, section, name, ref_type, false, None)
        }
        TypeVariant::UnionRef(ref_type) => {
            print_til_type_complex_ref(fmt, section, name, ref_type, "union", true)
        }
        TypeVariant::EnumRef(ref_type) => {
            print_til_type_complex_ref(fmt, section, name, ref_type, "enum", true)
        }
        TypeVariant::StructRef(ref_type) => {
            print_til_type_complex_ref(fmt, section, name, ref_type, "struct", true)
        }
        TypeVariant::Struct(til_struct) => {
            print_til_type_struct(fmt, section, name, til_struct, print_name)
        }
        TypeVariant::Union(til_union) => {
            print_til_type_union(fmt, section, name, til_union, print_name)
        }
        TypeVariant::Enum(til_enum) => print_til_type_enum(fmt, section, name, til_enum),
        TypeVariant::Bitfield(bitfield) => print_til_type_bitfield(fmt, name, bitfield),
    }
}

fn print_til_type_basic(
    fmt: &mut impl Write,
    _section: &TILSection,
    name: Option<&[u8]>,
    til_basic: &Basic,
) -> Result<()> {
    print_basic_type(fmt, til_basic)?;
    if let Some(name) = name {
        write!(fmt, " ")?;
        fmt.write_all(name)?;
    }
    Ok(())
}

fn print_til_type_pointer(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
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
            true,
        )?;
        // if the innertype is also a pointer, don't print the space
        if print_pointer_space && !matches!(&pointer.typ.type_variant, TypeVariant::Pointer(_)) {
            write!(fmt, " ")?;
        }
        let modifier = match pointer.modifier {
            None => "",
            Some(idb_rs::til::pointer::PointerModifier::Ptr32) => "__ptr32 ",
            Some(idb_rs::til::pointer::PointerModifier::Ptr64) => "__ptr64 ",
            Some(idb_rs::til::pointer::PointerModifier::Restricted) => "__restricted ",
        };
        write!(fmt, "*{modifier}")?;
        if let Some((ty, value)) = &pointer.shifted {
            write!(fmt, "__shifted(")?;
            print_til_type_only(fmt, section, ty)?;
            write!(fmt, ",{value:#X}) ")?;
        }
        if let Some(name) = name {
            fmt.write_all(name)?;
        }

        // if the pointed type itself is a VFT then the pointer need to print that
        if is_vft(section, &pointer.typ) {
            write!(fmt, " /*VFT*/")?;
        }
    }
    Ok(())
}

fn print_til_type_function(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Function,
    is_pointer: bool,
) -> Result<()> {
    // return type
    print_til_type(fmt, section, None, &til_type.ret, true, true, true)?;
    if !matches!(&til_type.ret.type_variant, TypeVariant::Pointer(_)) {
        write!(fmt, " ")?;
    }

    let cc = match (section.cc, til_type.calling_convention) {
        // don't print if using the til section default cc
        | (_, None)
        // if elipsis just print the '...' as last param
        | (_, Some(CallingConvention::Ellipsis))
        // if void arg, just don't print the args (there will be none)
        | (_, Some(CallingConvention::Voidarg)) => None,

        (_, Some(cc)) => Some(calling_convention_to_str(cc)),
    };

    // print name and calling convention and some flags
    match (is_pointer, cc) {
        (true, None) => write!(fmt, "(")?,
        (false, None) => {}
        (true, Some(cc)) => write!(fmt, "(__{cc} ")?,
        (false, Some(cc)) => write!(fmt, "__{cc} ")?,
    }

    // between the name and cc print some flags
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x442ccf
    if til_type.is_noret {
        write!(fmt, "__noreturn ")?;
    }
    if til_type.is_pure {
        write!(fmt, "__pure ")?;
    }
    if til_type.is_high {
        write!(fmt, "__high ")?;
    }

    if is_pointer {
        write!(fmt, "*")?;
    }

    if let Some(name) = name {
        fmt.write_all(name)?;
    }
    if is_pointer {
        write!(fmt, ")")?;
    }

    write!(fmt, "(")?;
    for (i, (param_name, param, _argloc)) in til_type.args.iter().enumerate() {
        if i != 0 {
            write!(fmt, ", ")?;
        }
        let param_name = param_name.as_ref().map(Vec::as_slice);
        print_til_type(fmt, section, param_name, param, true, false, true)?;
    }
    if til_type.args.len() == 0 {
        write!(fmt, "void")?;
    }
    if til_type.calling_convention == Some(CallingConvention::Ellipsis) {
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
    name: Option<&[u8]>,
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
        true,
    )?;
    if let Some(name) = name {
        write!(fmt, " ")?;
        fmt.write_all(name)?;
    }
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
    name: Option<&[u8]>,
    typedef: &Typedef,
    print_prefix: bool,
    ref_prefix: Option<&str>,
) -> Result<()> {
    // only print prefix, if is root
    match typedef {
        idb_rs::til::Typedef::Ordinal(ord) => {
            let ty = section
                .get_ord(idb_rs::id0::Id0TilOrd { ord: (*ord).into() })
                .unwrap();
            print_til_type_name(fmt, &ty.name, &ty.tinfo, print_prefix)?;
        }
        idb_rs::til::Typedef::Name(None) => {
            // TODO print nothing?
        }
        idb_rs::til::Typedef::Name(Some(name)) => {
            let ty = section.get_name(name);
            match ty {
                Some(ty) => print_til_type_name(fmt, &ty.name, &ty.tinfo, print_prefix)?,
                // if we can't find the type, just print the name
                None => {
                    if print_prefix {
                        if let Some(ref_prefix) = ref_prefix {
                            write!(fmt, "{ref_prefix} ")?;
                        }
                    }
                    write!(fmt, "{}", String::from_utf8_lossy(name))?
                }
            }
        }
    }
    if let Some(name) = name {
        write!(fmt, " ")?;
        fmt.write_all(name)?;
    }
    Ok(())
}

fn print_til_type_complex_ref(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    typedef: &Typedef,
    prefix_name: &str,
    print_prefix: bool,
) -> Result<()> {
    if let idb_rs::til::Typedef::Name(None) = typedef {
        if print_prefix {
            write!(fmt, "{}", prefix_name)?;
            if let Some(name) = name {
                write!(fmt, " ")?;
                fmt.write_all(name)?;
            }
        }
    } else {
        print_til_type_typedef(fmt, section, name, typedef, print_prefix, Some(prefix_name))?;
    }
    Ok(())
}

fn print_til_type_struct(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_struct: &Struct,
    print_name: bool,
) -> Result<()> {
    write!(fmt, "struct ")?;
    if til_struct.is_unaligned {
        if til_struct.is_uknown_8 {
            write!(fmt, "__attribute__((packed)) ")?;
        } else {
            write!(fmt, "__unaligned ")?;
        }
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
    if let Some(name) = name {
        if print_name {
            fmt.write_all(name)?;
            write!(fmt, " ")?;
        }
    }
    write!(fmt, "{{")?;
    for member in &til_struct.members {
        let member_name = member.name.as_deref();
        print_til_type_complex_member(
            fmt,
            section,
            name,
            member_name,
            &member.member_type,
            true,
            true,
        )?;
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
    name: Option<&[u8]>,
    til_union: &Union,
    print_name: bool,
) -> Result<()> {
    write!(fmt, "union ")?;
    if let Some(align) = til_union.alignment {
        write!(fmt, "__attribute__((aligned({align}))) ")?;
    }
    if let Some(name) = name {
        if print_name {
            fmt.write_all(name)?;
            write!(fmt, " ")?;
        }
    }
    write!(fmt, "{{")?;
    for (member_name, member) in &til_union.members {
        let member_name = member_name.as_deref();
        print_til_type_complex_member(fmt, section, name, member_name, member, true, true)?;
        write!(fmt, ";")?;
    }
    write!(fmt, "}}")
}

// just print the type, unless we want to embed it
fn print_til_type_complex_member(
    fmt: &mut impl Write,
    section: &TILSection,
    parent_name: Option<&[u8]>,
    name: Option<&[u8]>,
    til: &Type,
    print_pointer_space: bool,
    print_name: bool,
) -> Result<()> {
    // if parent is not named, don't embeded it, because we can verify if it's part
    // of the parent
    let Some(parent_name) = parent_name else {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            print_pointer_space,
            false,
            print_name,
        );
    };
    let qualified_parent_name: Vec<_> = parent_name.iter().chain(b"::").copied().collect();

    // TODO if the field is named, don't embeded it?
    if name.is_some() {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            print_pointer_space,
            false,
            print_name,
        );
    }

    // if typedef of complex ref, we may want to embed the definition inside the type
    // otherwise just print the type regularly
    let typedef = match &til.type_variant {
        TypeVariant::EnumRef(typedef)
        | TypeVariant::StructRef(typedef)
        | TypeVariant::UnionRef(typedef)
        | TypeVariant::Typedef(typedef) => typedef,
        _ => {
            return print_til_type(
                fmt,
                section,
                name,
                til,
                print_pointer_space,
                false,
                print_name,
            );
        }
    };

    let inner_type = match typedef {
        Typedef::Ordinal(ord) => section.get_ord(Id0TilOrd { ord: (*ord).into() }).unwrap(),
        Typedef::Name(None) => {
            return print_til_type(
                fmt,
                section,
                name,
                til,
                print_pointer_space,
                false,
                print_name,
            );
        }
        Typedef::Name(Some(name)) => section.get_name(name).unwrap(),
    };

    // if the inner_type name is in the format `parent_name::something_else` then
    // we embed it
    if !inner_type.name.starts_with(&qualified_parent_name) {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            print_pointer_space,
            false,
            print_name,
        );
    }

    print_til_type(
        fmt,
        section,
        Some(&inner_type.name),
        &inner_type.tinfo,
        print_pointer_space,
        true,
        false,
    )
}

fn print_til_type_enum(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_enum: &Enum,
) -> Result<()> {
    use idb_rs::til::r#enum::EnumFormat::*;

    let output_fmt_name = match til_enum.output_format {
        Char => "__char ",
        Hex => "",
        SignedDecimal => "__dec ",
        UnsignedDecimal => "__udec ",
    };
    write!(fmt, "enum {output_fmt_name}")?;
    if let Some(name) = name {
        fmt.write_all(name)?;
        write!(fmt, " ")?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4443b0
    if til_enum.storage_size.is_some() || til_enum.is_signed || til_enum.is_unsigned {
        let bytes = til_enum.storage_size.or(section.size_enum).unwrap();
        let signed = if til_enum.is_unsigned {
            "unsigned "
        } else {
            ""
        };
        write!(fmt, ": {signed}__int{} ", bytes.get() as usize * 8)?;
    }
    write!(fmt, "{{")?;
    for (member_name, value) in &til_enum.members {
        if let Some(member_name) = member_name {
            fmt.write_all(member_name)?;
        }
        write!(fmt, " = ")?;
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

fn print_til_type_bitfield(
    fmt: &mut impl Write,
    name: Option<&[u8]>,
    bitfield: &Bitfield,
) -> Result<()> {
    print_basic_type(
        fmt,
        &Basic::IntSized {
            bytes: bitfield.nbytes,
            is_signed: Some(!bitfield.unsigned),
        },
    )?;
    if let Some(name) = name {
        write!(fmt, " ")?;
        fmt.write_all(name)?;
    }
    write!(fmt, " : {}", bitfield.width)?;
    Ok(())
}

// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x423c20
fn print_til_struct_member_att(
    fmt: &mut impl Write,
    tinfo: &Type,
    att: &StructMemberAtt,
) -> Result<()> {
    match &tinfo.type_variant {
        TypeVariant::Basic(_) => print_til_struct_member_basic_att(fmt, att)?,
        TypeVariant::Pointer(pointer) => match &pointer.typ.type_variant {
            TypeVariant::Basic(Basic::Char) => print_til_struct_member_string_att(fmt, att)?,
            // TODO is valid for other then void?
            TypeVariant::Basic(Basic::Void) => print_til_struct_member_void_pointer_att(fmt, att)?,
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

// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4872f0
fn print_til_struct_member_string_att(fmt: &mut impl Write, att: &StructMemberAtt) -> Result<()> {
    let Some(value) = att.str_type() else {
        // TODO don't ignore errors
        return Ok(());
    };
    write!(fmt, " __strlit(0x{:08X})", value.as_strlib())?;
    Ok(())
}

fn print_til_struct_member_void_pointer_att(
    fmt: &mut impl Write,
    att: &StructMemberAtt,
) -> Result<()> {
    let Some(value) = att.offset_type() else {
        // TODO don't ignore errors
        return Ok(());
    };
    write!(fmt, " __offset({:#X}", value.offset)?;
    // InnerRef InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x720aa0
    if value.is_rvaoff() {
        write!(fmt, "|RVAOFF")?;
    }
    if value.is_pastend() {
        write!(fmt, "|PASTEND")?;
    }
    if value.is_nobase() {
        write!(fmt, "|NOBASE")?;
    }
    if value.is_subtract() {
        write!(fmt, "|SUBTRACT")?;
    }
    if value.is_signedop() {
        write!(fmt, "|SIGNEDOP")?;
    }
    if value.is_nozeroes() {
        write!(fmt, "|NOZEROES")?;
    }
    if value.is_noones() {
        write!(fmt, "|NOONES")?;
    }
    if value.is_selfref() {
        write!(fmt, "|SELFREF")?;
    }
    write!(fmt, ")")?;
    Ok(())
}

fn print_til_struct_member_basic_att(fmt: &mut impl Write, att: &StructMemberAtt) -> Result<()> {
    // TODO incomplete implementation
    if let Some((val, is_auto)) = att.basic_offset_type() {
        write!(
            fmt,
            " __offset({val:#x}{})",
            if is_auto { "|AUTO" } else { "" }
        )?;
        return Ok(());
    }

    let Some(basic_att) = att.basic() else {
        // TODO don't ignore errors
        return Ok(());
    };

    use idb_rs::til::r#struct::ExtAttBasicFmt::*;
    if basic_att.is_inv_bits {
        write!(fmt, " __invbits")?
    }
    if basic_att.is_inv_sign {
        write!(fmt, " __invsign")?
    }
    if basic_att.is_lzero {
        write!(fmt, " __lzero")?
    }
    match (basic_att.fmt, basic_att.is_signed) {
        (Bin, true) => write!(fmt, " __sbin")?,
        (Bin, false) => write!(fmt, " __bin")?,
        (Oct, true) => write!(fmt, " __soct")?,
        (Oct, false) => write!(fmt, " __oct")?,
        (Hex, true) => write!(fmt, " __shex")?,
        (Hex, false) => write!(fmt, " __hex")?,
        (Dec, true) => write!(fmt, " __dec")?,
        (Dec, false) => write!(fmt, " __udec")?,
        (Float, _) => write!(fmt, " __float")?,
        (Char, _) => write!(fmt, " __char")?,
        (Segm, _) => write!(fmt, " __segm")?,
        (Off, _) => write!(fmt, " __off")?,
    };
    match (basic_att.fmt, basic_att.is_signed) {
        (_, false) => {}
        // already included on the name
        (Bin | Dec | Oct | Hex, _) => {}
        (Float | Char | Segm | Off, true) => write!(fmt, " __signed")?,
    };

    if let Some(tabform) = basic_att.tabform {
        // InnerRef InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48857f
        let val1 = match tabform.val1 {
            idb_rs::til::r#struct::ExtAttBasicTabformVal1::NODUPS => "NODUPS",
            idb_rs::til::r#struct::ExtAttBasicTabformVal1::HEX => "HEX",
            idb_rs::til::r#struct::ExtAttBasicTabformVal1::DEC => "DEC",
            idb_rs::til::r#struct::ExtAttBasicTabformVal1::OCT => "OCT",
            idb_rs::til::r#struct::ExtAttBasicTabformVal1::BIN => "BIN",
        };
        write!(fmt, " __tabform({val1},{})", tabform.val2)?;
    }
    Ok(())
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

fn print_til_type_only(fmt: &mut impl Write, section: &TILSection, tinfo: &Type) -> Result<()> {
    match &tinfo.type_variant {
        TypeVariant::Typedef(Typedef::Name(Some(name))) => {
            fmt.write_all(name)?;
        }
        TypeVariant::Typedef(Typedef::Ordinal(ord)) => {
            let ty = section.get_ord(Id0TilOrd { ord: (*ord).into() }).unwrap();
            fmt.write_all(&ty.name)?;
        }
        _ => {}
    };
    Ok(())
}

fn print_til_type_len(
    fmt: &mut impl Write,
    idx: Option<usize>,
    tinfo: &Type,
    size_solver: &mut TILTypeSizeSolver<'_>,
) -> Result<()> {
    if let TypeVariant::Function(_function) = &tinfo.type_variant {
        write!(fmt, "FFFFFFFF")?;
    } else {
        // if the type is unknown it just prints "FFFFFFF"
        let len = size_solver
            .type_size_bytes(idx, tinfo)
            .unwrap_or(0xFFFF_FFFF);
        write!(fmt, "{len:08X}")?;
    }
    Ok(())
}

fn calling_convention_to_str(cc: CallingConvention) -> &'static str {
    use idb_rs::til::function::CallingConvention::*;
    match cc {
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
        Reserved3 => "ccreserved3",
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

fn is_vft(section: &TILSection, typ: &Type) -> bool {
    match &typ.type_variant {
        // propagate the search?
        //TypeVariant::Pointer(pointer) => todo!(),
        // TODO struct with only function-pointers is also vftable?
        TypeVariant::Struct(ty) => ty.is_vftable,
        TypeVariant::Typedef(typedef) | TypeVariant::StructRef(typedef) => {
            let inner_type = match typedef {
                Typedef::Ordinal(ord) => section.get_ord(Id0TilOrd { ord: (*ord).into() }),
                Typedef::Name(None) => return false,
                Typedef::Name(Some(name)) => section.get_name(name),
            };
            let Some(inner_type) = inner_type else {
                return false;
            };
            is_vft(section, &inner_type.tinfo)
        }
        _ => false,
    }
}

fn print_basic_type(fmt: &mut impl Write, til_basic: &Basic) -> Result<()> {
    const fn signed_name(is_signed: Option<bool>) -> &'static str {
        match is_signed {
            Some(true) | None => "",
            Some(false) => "unsigned ",
        }
    }

    match til_basic {
        Basic::Bool => write!(fmt, "bool")?,
        Basic::Char => write!(fmt, "char")?,
        Basic::Short { is_signed } => write!(fmt, "{}short", signed_name(*is_signed))?,
        Basic::Void => write!(fmt, "void")?,
        Basic::SegReg => write!(fmt, "SegReg")?,
        Basic::Unknown { bytes: 1 } => write!(fmt, "_BYTE")?,
        Basic::Unknown { bytes: 2 } => write!(fmt, "_WORD")?,
        Basic::Unknown { bytes: 4 } => write!(fmt, "_DWORD")?,
        Basic::Unknown { bytes: 8 } => write!(fmt, "_QWORD")?,
        Basic::Unknown { bytes } => write!(fmt, "unknown{bytes}")?,
        Basic::Int { is_signed } => write!(fmt, "{}int", signed_name(*is_signed))?,
        Basic::Long { is_signed } => write!(fmt, "{}long", signed_name(*is_signed))?,
        Basic::LongLong { is_signed } => write!(fmt, "{}longlong", signed_name(*is_signed))?,
        Basic::IntSized { bytes, is_signed } => {
            if let Some(false) = is_signed {
                write!(fmt, "unsigned ")?;
            }
            write!(fmt, "__int{}", bytes.get() * 8)?
        }
        Basic::LongDouble => write!(fmt, "longfloat")?,
        Basic::Float { bytes } if bytes.get() == 4 => write!(fmt, "float")?,
        Basic::Float { bytes } if bytes.get() == 8 => write!(fmt, "double")?,
        Basic::Float { bytes } => write!(fmt, "float{bytes}")?,
        Basic::BoolSized { bytes } if bytes.get() == 1 => write!(fmt, "bool")?,
        Basic::BoolSized { bytes } => write!(fmt, "bool{bytes}")?,
    }
    Ok(())
}
