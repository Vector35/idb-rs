use idb_rs::id0::{Compiler, Id0TilOrd};
use idb_rs::til::array::Array;
use idb_rs::til::bitfield::Bitfield;
use idb_rs::til::function::{CallingConvention, Function};
use idb_rs::til::pointer::Pointer;
use idb_rs::til::r#enum::Enum;
use idb_rs::til::r#struct::{Struct, StructMemberAtt};
use idb_rs::til::section::TILSection;
use idb_rs::til::union::Union;
use idb_rs::til::{
    Basic, TILTypeInfo, TILTypeSizeSolver, Type, TypeVariant, Typeref,
    TyperefType, TyperefValue,
};
use idb_rs::{IDBParser, IDBSectionCompression, IDBString};

use std::fs::File;
use std::io::{BufReader, Result, Write};
use std::num::NonZeroU8;

use crate::{Args, FileType};

pub fn tilib_print(args: &Args) -> anyhow::Result<()> {
    // parse the id0 sector/file
    let mut input = BufReader::new(File::open(&args.input)?);
    match args.input_type() {
        FileType::Til => {
            let section =
                TILSection::read(&mut input, IDBSectionCompression::None)?;
            print_til_section(std::io::stdout(), &section)?;
        }
        FileType::Idb => {
            let mut parser = IDBParser::new(input)?;
            let til_offset = parser.til_section_offset().ok_or_else(|| {
                anyhow::anyhow!("IDB file don't contains a TIL sector")
            })?;
            let section = parser.read_til_section(til_offset)?;
            print_til_section(std::io::stdout(), &section)?;
        }
    }
    Ok(())
}

fn print_til_section(mut fmt: impl Write, section: &TILSection) -> Result<()> {
    if !section.header.dependencies.is_empty() {
        // TODO open those files? What todo with then?
        write!(fmt, "Warning: ")?;
        for dependency in &section.header.dependencies {
            fmt.write_all(dependency.as_bytes())?;
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
    fmt.write_all(&section.header.description.as_bytes())?;
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
        compiler_id_to_str(section.header.compiler_id)
    )?;

    // alignement and convention stuff
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b7ed
    if let Some(cn) = section.header.cn {
        write!(
            fmt,
            "sizeof(near*) = {} sizeof(far*) = {}",
            cn.near_bytes(),
            cn.far_bytes()
        )?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40ba3b
    if let Some(cm) = section.header.cm {
        if section.header.cn.is_some() {
            write!(fmt, " ")?;
        }
        let code = if cm.is_code_near() { "near" } else { "far" };
        let data = if cm.is_data_near() { "near" } else { "far" };
        write!(fmt, "{code} code, {data} data",)?;
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b860
    if let Some(cc) = section.header.cc {
        if section.header.cm.is_some() || section.header.cn.is_some() {
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
        section.header.def_align.map(|x| x.get()).unwrap_or(0),
        section.header.size_bool,
        section.sizeof_long(),
        section.sizeof_long_long(),
    )?;
    writeln!(
        fmt,
        "sizeof(enum) = {} sizeof(int) = {} sizeof(short) = {}",
        section.header.size_enum.map(NonZeroU8::get).unwrap_or(0),
        section.header.size_int,
        section.sizeof_short(),
    )?;
    writeln!(
        fmt,
        "sizeof(long double) = {}",
        section
            .header
            .size_long_double
            .map(NonZeroU8::get)
            .unwrap_or(0)
    )?;
    Ok(())
}

fn print_section_flags(
    fmt: &mut impl Write,
    section: &TILSection,
) -> Result<()> {
    let flags = section.header.flags;
    write!(fmt, "Flags      : {:04X}", flags.as_raw())?;
    if flags.is_zip() {
        write!(fmt, " compressed")?;
    }
    if flags.has_macro_table() {
        write!(fmt, " macro_table_present")?;
    }
    if flags.have_extended_sizeof_info() {
        write!(fmt, " extended_sizeof_info")?;
    }
    if flags.is_universal() {
        write!(fmt, " universal")?;
    }
    if flags.has_ordinal() {
        write!(fmt, " ordinals_present")?;
    }
    if flags.has_type_aliases() {
        write!(fmt, " aliases_present")?;
    }
    if flags.has_extra_stream() {
        write!(fmt, " extra_streams")?;
    }
    if flags.has_size_long_double() {
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
            Some(bytes @ 0..=7) => write!(
                fmt,
                " {:08X}",
                symbol.ordinal & !(u64::MAX << (bytes * 8))
            )?,
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
        let symbol_name = symbol.name.as_bytes();
        let name = if symbol.ordinal == 0 && symbol_name.first() == Some(&b'_')
        {
            // remove the first "_", if any
            &symbol.name.as_bytes()[1..]
        } else {
            symbol.name.as_bytes()
        };
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x409a3a
        print_til_type(
            fmt,
            section,
            Some(name),
            &symbol.tinfo,
            false,
            true,
            false,
            true,
        )?;
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
    if section.header.flags.has_ordinal() {
        writeln!(fmt, "(enumerated by ordinals)")?;
        print_types_by_ordinals(fmt, section, solver)?;
        writeln!(fmt, "(enumerated by names)")?;
    }
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
                .header
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
        print_til_type_root(
            fmt,
            section,
            Some(final_type.name.as_bytes()),
            &final_type.tinfo,
        )?;
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
        if symbol.name.as_bytes().is_empty() {
            continue;
        }
        print_til_type_len(fmt, Some(idx), &symbol.tinfo, solver).unwrap();
        write!(fmt, " ")?;
        print_til_type_root(
            fmt,
            section,
            Some(symbol.name.as_bytes()),
            &symbol.tinfo,
        )?;
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
        TypeVariant::Struct(_)
        | TypeVariant::Union(_)
        | TypeVariant::Enum(_) => {}
        TypeVariant::Typeref(Typeref {
            typeref_value: TyperefValue::UnsolvedName(None),
            ref_type: Some(_),
        }) => {}
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x443906
        _ => write!(fmt, "typedef ")?,
    }
    print_til_type(fmt, section, name, til_type, false, true, true, true)
}

fn print_til_type(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    is_vft: bool,
    print_pointer_space: bool,
    print_type_prefix: bool,
    print_name: bool,
) -> Result<()> {
    match &til_type.type_variant {
        TypeVariant::Basic(til_basic) => {
            print_til_type_basic(fmt, section, name, til_type, til_basic)
        }
        TypeVariant::Pointer(pointer) => print_til_type_pointer(
            fmt,
            section,
            name,
            til_type,
            pointer,
            is_vft,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Function(function) => print_til_type_function(
            fmt, section, name, til_type, function, false,
        ),
        TypeVariant::Array(array) => print_til_type_array(
            fmt,
            section,
            name,
            til_type,
            array,
            print_pointer_space,
            print_type_prefix,
        ),
        TypeVariant::Typeref(ref_type) => print_til_type_typedef(
            fmt,
            section,
            name,
            til_type,
            ref_type,
            print_type_prefix,
        ),
        TypeVariant::Struct(til_struct) => print_til_type_struct(
            fmt, section, name, til_type, til_struct, print_name,
        ),
        TypeVariant::Union(til_union) => print_til_type_union(
            fmt, section, name, til_type, til_union, print_name,
        ),
        TypeVariant::Enum(til_enum) => {
            print_til_type_enum(fmt, section, name, til_type, til_enum)
        }
        TypeVariant::Bitfield(bitfield) => {
            print_til_type_bitfield(fmt, name, til_type, bitfield)
        }
    }
}

fn print_til_type_basic(
    fmt: &mut impl Write,
    _section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    til_basic: &Basic,
) -> Result<()> {
    if til_type.is_volatile {
        write!(fmt, "volatile ")?;
    }
    if til_type.is_const {
        write!(fmt, "const ")?;
    }
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
    til_type: &Type,
    pointer: &Pointer,
    is_vft_parent: bool,
    print_pointer_space: bool,
    print_type_prefix: bool,
) -> Result<()> {
    if let TypeVariant::Function(inner_fun) = &pointer.typ.type_variant {
        // How to handle modifier here?
        print_til_type_function(fmt, section, name, til_type, inner_fun, true)?;
    } else {
        // TODO name
        print_til_type(
            fmt,
            section,
            None,
            &pointer.typ,
            is_vft_parent,
            print_pointer_space,
            print_type_prefix,
            true,
        )?;
        // if the innertype is also a pointer, don't print the space
        if print_pointer_space
            && !matches!(&pointer.typ.type_variant, TypeVariant::Pointer(_))
        {
            write!(fmt, " ")?;
        }
        write!(fmt, "*")?;
        if til_type.is_volatile {
            write!(fmt, "volatile ")?;
        }
        if til_type.is_const {
            write!(fmt, "const ")?;
        }
        match pointer.modifier {
            None => {}
            Some(idb_rs::til::pointer::PointerModifier::Ptr32) => {
                write!(fmt, "__ptr32 ")?
            }
            Some(idb_rs::til::pointer::PointerModifier::Ptr64) => {
                write!(fmt, "__ptr64 ")?
            }
            Some(idb_rs::til::pointer::PointerModifier::Restricted) => {
                write!(fmt, "__restricted ")?
            }
        }
        if let Some((ty, value)) = &pointer.shifted {
            write!(fmt, "__shifted(")?;
            print_til_type_only(fmt, section, ty)?;
            write!(fmt, ",{value:#X}) ")?;
        }
        if let Some(name) = name {
            fmt.write_all(name)?;
        }

        // if the pointed type itself is a VFT then the pointer need to print that
        // TODO maybe the above is not ture, it it was inheritec from the
        // struct member att
        if is_vft_parent || is_vft(section, &pointer.typ) {
            write!(fmt, " /*VFT*/")?;
        }
    }
    Ok(())
}

fn print_til_type_function(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    til_function: &Function,
    is_pointer: bool,
) -> Result<()> {
    if til_type.is_volatile {
        write!(fmt, "volatile ")?;
    }
    if til_type.is_const {
        write!(fmt, "const ")?;
    }
    // return type
    print_til_type(
        fmt,
        section,
        None,
        &til_function.ret,
        false,
        true,
        true,
        true,
    )?;
    if !matches!(&til_function.ret.type_variant, TypeVariant::Pointer(_)) {
        write!(fmt, " ")?;
    }

    let cc = match (section.header.cc, til_function.calling_convention) {
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
    if til_function.is_noret {
        write!(fmt, "__noreturn ")?;
    }
    if til_function.is_pure {
        write!(fmt, "__pure ")?;
    }
    if til_function.is_high {
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
    for (i, (param_name, param, _argloc)) in
        til_function.args.iter().enumerate()
    {
        if i != 0 {
            write!(fmt, ", ")?;
        }
        let param_name = param_name.as_ref().map(IDBString::as_bytes);
        print_til_type(
            fmt, section, param_name, param, false, true, false, true,
        )?;
    }
    match til_function.calling_convention {
        Some(CallingConvention::Voidarg) => write!(fmt, "void")?,
        Some(CallingConvention::Ellipsis) => {
            if !til_function.args.is_empty() {
                write!(fmt, ", ")?;
            }
            write!(fmt, "...")?;
        }
        _ => {}
    }
    write!(fmt, ")")
}

fn print_til_type_array(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    til_array: &Array,
    print_pointer_space: bool,
    _print_type_prefix: bool,
) -> Result<()> {
    if til_type.is_volatile {
        write!(fmt, "volatile ")?;
    }
    if til_type.is_const {
        write!(fmt, "const ")?;
    }
    print_til_type(
        fmt,
        section,
        None,
        &til_array.elem_type,
        false,
        print_pointer_space,
        true,
        true,
    )?;
    if let Some(name) = name {
        // only print space if not a pointer
        match &til_array.elem_type.type_variant {
            TypeVariant::Pointer(_) => {}
            _ => write!(fmt, " ")?,
        }
        fmt.write_all(name)?;
    }
    if let Some(nelem) = til_array.nelem {
        write!(fmt, "[{nelem}]")?;
    } else {
        write!(fmt, "[]")?;
    }
    Ok(())
}

fn print_til_type_typedef(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    til_type: &Type,
    typedef: &Typeref,
    print_prefix: bool,
) -> Result<()> {
    if til_type.is_volatile {
        write!(fmt, "volatile ")?;
    }
    if til_type.is_const {
        write!(fmt, "const ")?;
    }
    let mut need_space = false;
    if print_prefix {
        if let Some(ref_prefix) = typedef.ref_type {
            print_typeref_type_prefix(fmt, ref_prefix)?;
            need_space = true;
        }
    }
    // get the type referenced by the typdef
    match &typedef.typeref_value {
        TyperefValue::Ref(idx) => {
            if need_space {
                write!(fmt, " ")?;
            }
            let inner_ty = &section.types[*idx];
            fmt.write_all(inner_ty.name.as_bytes())?;
            need_space = true;
        }
        TyperefValue::UnsolvedName(Some(name)) => {
            if need_space {
                write!(fmt, " ")?;
            }
            fmt.write_all(name.as_bytes())?;
            need_space = true;
        }
        // Nothing to print
        TyperefValue::UnsolvedName(None) | TyperefValue::UnsolvedOrd(_) => {}
    };
    // print the type name, if some
    if let Some(name) = name {
        if need_space {
            write!(fmt, " ")?;
        }
        fmt.write_all(name)?;
    }
    Ok(())
}

fn print_til_type_struct(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    _til_type: &Type,
    til_struct: &Struct,
    print_name: bool,
) -> Result<()> {
    // TODO check innerref, maybe baseclass don't need to be the first, nor
    // need to only one
    let is_cppobj = til_struct.is_cppobj
        || matches!(til_struct.members.first(), Some(first) if first.is_baseclass);

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
    if is_cppobj {
        write!(fmt, "__cppobj ")?;
    }
    if til_struct.is_vft {
        write!(fmt, "/*VFT*/ ")?;
    }
    if let Some(align) = til_struct.alignment {
        write!(fmt, "__attribute__((aligned({align}))) ")?;
    }
    if let Some(name) = name {
        if print_name {
            fmt.write_all(name)?;
            write!(fmt, " ")?;
        }
    }
    let mut members = &til_struct.members[..];
    if is_cppobj {
        match members.first() {
            Some(baseclass) if baseclass.is_baseclass => {
                members = &members[1..];
                write!(fmt, ": ")?;
                print_til_type(
                    fmt,
                    section,
                    None,
                    &baseclass.member_type,
                    baseclass.is_vft,
                    true,
                    true,
                    false,
                )?;
                write!(fmt, " ")?;
            }
            _ => {}
        }
    }

    write!(fmt, "{{")?;
    for member in members {
        let member_name = member.name.as_ref().map(IDBString::as_bytes);
        print_til_type_complex_member(
            fmt,
            section,
            name,
            member_name,
            &member.member_type,
            member.is_vft,
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
    _til_type: &Type,
    til_union: &Union,
    print_name: bool,
) -> Result<()> {
    write!(fmt, "union ")?;
    if let Some(align) = til_union.alignment {
        write!(fmt, "__attribute__((aligned({align}))) ")?;
    }
    if let Some(name) = &name {
        if print_name {
            fmt.write_all(name)?;
            write!(fmt, " ")?;
        }
    }
    write!(fmt, "{{")?;
    for (member_name, member) in &til_union.members {
        let member_name = member_name.as_ref().map(IDBString::as_bytes);
        print_til_type_complex_member(
            fmt,
            section,
            name,
            member_name,
            member,
            false,
            true,
            true,
        )?;
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
    is_vft: bool,
    print_pointer_space: bool,
    print_name: bool,
) -> Result<()> {
    // TODO make closure that print member atts: VFT, align, unaligned, packed, etc
    // if parent is not named, don't embeded it, because we can verify if it's part
    // of the parent
    let Some(parent_name) = parent_name else {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            is_vft,
            print_pointer_space,
            true,
            print_name,
        );
    };

    // TODO if the field is named, don't embeded it?
    if name.is_some() {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            is_vft,
            print_pointer_space,
            true,
            print_name,
        );
    }

    // if typedef of complex ref, we may want to embed the definition inside the type
    // otherwise just print the type regularly
    let typedef = match &til.type_variant {
        TypeVariant::Typeref(typedef) => typedef,
        _ => {
            return print_til_type(
                fmt,
                section,
                name,
                til,
                is_vft,
                print_pointer_space,
                true,
                print_name,
            );
        }
    };

    let inner_type = match &typedef.typeref_value {
        TyperefValue::Ref(idx) => &section.types[*idx],
        TyperefValue::UnsolvedName(Some(name)) => {
            if let Some(ref_type) = &typedef.ref_type {
                print_typeref_type_prefix(fmt, *ref_type)?;
            }
            fmt.write_all(name.as_bytes())?;
            return Ok(());
        }
        TyperefValue::UnsolvedOrd(_) | TyperefValue::UnsolvedName(None) => {
            return print_til_type(
                fmt,
                section,
                name,
                til,
                is_vft,
                print_pointer_space,
                true,
                print_name,
            );
        }
    };

    // if the inner_type name is in the format `parent_name::something_else` then
    // we embed it
    let qualified_parent_name: Vec<_> =
        parent_name.iter().chain(b"::").copied().collect();
    if !inner_type
        .name
        .as_bytes()
        .starts_with(&qualified_parent_name)
    {
        return print_til_type(
            fmt,
            section,
            name,
            til,
            is_vft,
            print_pointer_space,
            true,
            print_name,
        );
    }

    print_til_type(
        fmt,
        section,
        Some(inner_type.name.as_bytes()),
        &inner_type.tinfo,
        is_vft,
        print_pointer_space,
        true,
        false,
    )
}

fn print_til_type_enum(
    fmt: &mut impl Write,
    section: &TILSection,
    name: Option<&[u8]>,
    _til_type: &Type,
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
    if til_enum.storage_size.is_some()
        || til_enum.is_signed
        || til_enum.is_unsigned
    {
        let bytes = til_enum.storage_size.or(section.header.size_enum).unwrap();
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
            fmt.write_all(member_name.as_bytes())?;
        }
        write!(fmt, " = ")?;
        match til_enum.output_format {
            Char if *value <= 0xFF => {
                write!(fmt, "'{}'", (*value) as u8 as char)?
            }
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
    _til_type: &Type,
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
            TypeVariant::Basic(Basic::Char) => {
                print_til_struct_member_string_att(fmt, att)?
            }
            // TODO is valid for other then void?
            TypeVariant::Basic(Basic::Void) => {
                print_til_struct_member_void_pointer_att(fmt, att)?
            }
            _ => {}
        },
        TypeVariant::Array(array) => match &array.elem_type.type_variant {
            TypeVariant::Basic(Basic::Char) => {
                print_til_struct_member_string_att(fmt, att)?
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4872f0
fn print_til_struct_member_string_att(
    fmt: &mut impl Write,
    att: &StructMemberAtt,
) -> Result<()> {
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

fn print_til_struct_member_basic_att(
    fmt: &mut impl Write,
    att: &StructMemberAtt,
) -> Result<()> {
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

fn print_til_type_only(
    fmt: &mut impl Write,
    section: &TILSection,
    tinfo: &Type,
) -> Result<()> {
    match &tinfo.type_variant {
        TypeVariant::Typeref(Typeref {
            typeref_value: TyperefValue::UnsolvedName(Some(name)),
            ref_type: _,
        }) => {
            fmt.write_all(name.as_bytes())?;
        }
        TypeVariant::Typeref(Typeref {
            typeref_value: TyperefValue::UnsolvedName(None),
            ref_type: _,
        }) => {}
        TypeVariant::Typeref(Typeref {
            typeref_value: TyperefValue::Ref(idx),
            ref_type: _,
        }) => {
            //TypeVariant::Typeref(Typeref::Ordinal(ord)) => {
            let ty = &section.types[*idx];
            fmt.write_all(ty.name.as_bytes())?;
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
        .header
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
        TypeVariant::Struct(ty) => ty.is_vft,
        TypeVariant::Typeref(typedef) => {
            let inner_type = match &typedef.typeref_value {
                TyperefValue::Ref(idx) => &section.types[*idx],
                TyperefValue::UnsolvedOrd(_)
                | TyperefValue::UnsolvedName(_) => return false,
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
        Basic::Short { is_signed } => {
            write!(fmt, "{}short", signed_name(*is_signed))?
        }
        Basic::Void => write!(fmt, "void")?,
        Basic::SegReg => write!(fmt, "SegReg")?,
        Basic::Unknown { bytes: 1 } => write!(fmt, "_BYTE")?,
        Basic::Unknown { bytes: 2 } => write!(fmt, "_WORD")?,
        Basic::Unknown { bytes: 4 } => write!(fmt, "_DWORD")?,
        Basic::Unknown { bytes: 8 } => write!(fmt, "_QWORD")?,
        Basic::Unknown { bytes } => write!(fmt, "unknown{bytes}")?,
        Basic::Int { is_signed } => {
            write!(fmt, "{}int", signed_name(*is_signed))?
        }
        Basic::Long { is_signed } => {
            write!(fmt, "{}long", signed_name(*is_signed))?
        }
        Basic::LongLong { is_signed } => {
            write!(fmt, "{}longlong", signed_name(*is_signed))?
        }
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

fn print_typeref_type_prefix(
    fmt: &mut impl Write,
    ref_type: TyperefType,
) -> Result<()> {
    match ref_type {
        idb_rs::til::TyperefType::Union => write!(fmt, "union"),
        idb_rs::til::TyperefType::Struct => write!(fmt, "struct"),
        idb_rs::til::TyperefType::Enum => write!(fmt, "enum"),
    }
}
