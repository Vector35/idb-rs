use std::fs::File;
use std::io::BufReader;

use anyhow::{anyhow, Result};
use idb_rs::til::section::TILSection;
use idb_rs::til::TILMacro;
use idb_rs::IDBParser;

use crate::{Args, FileType};

pub fn dump_til(args: &Args) -> Result<()> {
    // parse the til sector/file
    let til = match args.input_type() {
        FileType::Idb => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IDBParser::new(input)?;
            let til_offset = parser
                .til_section_offset()
                .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
            parser.read_til_section(til_offset)?
        }
        FileType::Til => {
            let input = BufReader::new(File::open(&args.input)?);
            idb_rs::til::section::TILSection::parse(input)?
        }
    };

    // this deconstruction is to changes on TILSection to force a review on this code
    let TILSection {
        format,
        title,
        flags: _,
        dependency,
        compiler_id,
        cc,
        cm,
        cn,
        def_align,
        type_ordinal_alias,
        size_int,
        size_enum,
        size_bool,
        extended_sizeof_info: _,
        size_long_double,
        is_universal,
        symbols,
        types,
        macros,
    } = &til;
    // write the header info
    println!("format: {format}");
    println!("title: {}", String::from_utf8_lossy(title));
    if let Some(dependency) = dependency {
        println!("dependency: {}", String::from_utf8_lossy(dependency));
    }
    println!("id: {compiler_id:?}");
    println!("cc: {cc:?}");
    println!("cm: {cm:?}");
    println!("cn: {cn:?}");
    println!("def_align: {}", def_align.map(|x| x.get()).unwrap_or(0));
    println!("size_int: {size_int}");
    println!("size_bool: {size_bool}");
    println!("size_enum: {size_enum:?}");
    println!("is_universal: {is_universal}");
    if let Some(type_ordinal_numbers) = type_ordinal_alias {
        println!("type_ordinal_numbers: {type_ordinal_numbers:?}");
    }
    if let Some(size_long_double) = size_long_double {
        println!("size_long_double: {size_long_double}");
    }
    println!("size short: {}", til.sizeof_short());
    println!("size long: {}", til.sizeof_long());
    println!("size long_long: {}", til.sizeof_long_long());

    // TODO implement Display for TILTypeInfo
    println!("types:");
    for til_type in types {
        println!("  {til_type:?}");
    }
    println!("\nsymbols:");
    for til_type in symbols {
        println!("  {til_type:?}");
    }

    if let Some(macros) = macros {
        println!("\n------------------------------macros------------------------------");
        for TILMacro {
            name,
            value,
            param_num: _,
        } in macros
        {
            let name = String::from_utf8_lossy(name);
            let value: String = value
                .iter()
                .map(|c| match c {
                    idb_rs::til::TILMacroValue::Char(c) => format!("{}", *c as char),
                    idb_rs::til::TILMacroValue::Param(param) => format!("{{P{}}}", *param),
                })
                .collect();
            println!("------------------------------`{name}`------------------------------");
            println!("{value}");
            println!("------------------------------`{name}`-end------------------------------",);
        }
        println!("------------------------------macros-end------------------------------");
    }
    Ok(())
}
