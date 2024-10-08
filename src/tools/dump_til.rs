use std::fs::File;
use std::io::BufReader;

use anyhow::{anyhow, Result};
use idb_rs::til::section::{TILSection, TILSizes};
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
        description,
        id,
        cm,
        def_align,
        type_ordinal_numbers,
        size_i,
        size_b,
        sizes,
        size_long_double,
        is_universal,
        symbols,
        types,
        macros,
    } = til;
    // write the header info
    println!("format: {format}");
    println!("title: {}", String::from_utf8_lossy(&title));
    println!("description: {}", String::from_utf8_lossy(&description));
    println!("id: {id}");
    println!("cm: {cm}");
    println!("def_align: {def_align}");
    println!("size_i: {size_i}");
    println!("size_b: {size_b}");
    println!("is_universal: {is_universal}");
    if let Some(type_ordinal_numbers) = type_ordinal_numbers {
        println!("type_ordinal_numbers: {type_ordinal_numbers:?}");
    }
    if let Some(size_long_double) = size_long_double {
        println!("size_long_double: {size_long_double}");
    }
    if let Some(TILSizes {
        size_short,
        size_long,
        size_long_long,
    }) = sizes
    {
        println!("size short: {size_short}");
        println!("size long: {size_long}");
        println!("size long_long: {size_long_long}");
    }

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
        for TILMacro { name, value } in macros {
            let name = String::from_utf8_lossy(&name);
            let value = String::from_utf8_lossy(&value);
            println!("------------------------------`{name}`------------------------------");
            println!("{value}");
            println!("------------------------------`{name}`-end------------------------------",);
        }
        println!("------------------------------macros-end------------------------------");
    }
    Ok(())
}
