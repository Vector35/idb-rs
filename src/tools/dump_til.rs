use anyhow::Result;

use idb_rs::til::section::{TILSection, TILSectionExtendedSizeofInfo};
use idb_rs::til::TILMacro;

use crate::{get_til_section, Args};

pub fn dump_til(args: &Args) -> Result<()> {
    // parse the til sector/file
    let til = get_til_section(args)?;

    // this deconstruction is to changes on TILSection to force a review on this code
    let TILSection {
        symbols,
        types,
        macros,
        header:
            idb_rs::til::section::TILSectionHeader {
                flags: _,
                format,
                description,
                dependencies,
                compiler_id,
                cc,
                compiler_guessed,
                cn,
                cm,
                def_align,
                type_ordinal_alias,
                size_int,
                size_bool,
                size_enum,
                extended_sizeof_info,
                size_long_double,
                is_universal,
            },
    } = &til;
    // write the header info
    println!("format: {format}");
    println!("description: {}", description.as_utf8_lossy());
    for (i, dependency) in dependencies.iter().enumerate() {
        println!("dependency-{i}: {}", dependency.as_utf8_lossy());
    }
    println!("id: {compiler_id:?}");
    let cc_guessed = if *compiler_guessed { " (guessed)" } else { "" };
    println!("cc: {cc:?}{cc_guessed}");
    println!("cm: {cm:?}");
    println!("cn: {cn:?}");
    println!("def_align: {}", def_align.map(|x| x.get()).unwrap_or(0));
    println!("size_int: {size_int}");
    println!("size_bool: {size_bool}");
    println!("size_enum: {size_enum:?}");
    if let Some(TILSectionExtendedSizeofInfo {
        size_short,
        size_long,
        size_long_long,
    }) = extended_sizeof_info
    {
        println!("size_short: {size_short}");
        println!("size_long: {size_long}");
        println!("size_long_long: {size_long_long}");
    }
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
                    idb_rs::til::TILMacroValue::Char(c) => {
                        format!("{}", *c as char)
                    }
                    idb_rs::til::TILMacroValue::Param(param) => {
                        format!("{{P{}}}", *param)
                    }
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
