use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_root_info(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    println!("Segments AKA `Root Node`: ");
    let root_info_idx = id0.root_node()?;
    println!("image_base: {:X?}", id0.image_base(root_info_idx)?);
    if let Some(input_file) = id0.input_file(root_info_idx) {
        println!("input_file: {}", String::from_utf8_lossy(input_file));
    };
    if let Some(input_file_size) = id0.input_file_size(root_info_idx)? {
        println!("input_file_size: {input_file_size}");
    };
    if let Some(crc32) = id0.input_file_crc32(root_info_idx)? {
        println!("input_file_crc32: {crc32}");
    };
    if let Some(sha256) = id0.input_file_sha256(root_info_idx)? {
        println!("input_file_sha256: {sha256:X?}");
    };
    if let Some(md5) = id0.input_file_md5(root_info_idx)? {
        println!("input_file_md5: {md5:X?}");
    };
    if let Some(num_opens) = id0.database_num_opens(root_info_idx)? {
        println!("database_num_opens: {num_opens}");
    };
    if let Some(secs_opens) = id0.database_secs_opens(root_info_idx)? {
        println!("database_secs_opens: {secs_opens}");
    };
    if let Some(creation_time) = id0.database_creation_time(root_info_idx)? {
        println!("database_creation_time (timestamp): {creation_time}");
    }
    if let Some(initial_version) =
        id0.database_initial_version(root_info_idx)?
    {
        println!("database_initial_version: {initial_version}");
    }
    if let Some(creation_version) = id0.database_creation_version(root_info_idx)
    {
        println!("database_creation_version: {creation_version:?}");
    }
    if let Some(c) = id0.c_predefined_macros(root_info_idx) {
        println!("c_predefined_macros: {c}");
    }
    if let Some(c) = id0.c_header_path(root_info_idx) {
        println!("c_header_path: {c}");
    }
    println!("ida_info: {:X?}", id0.ida_info(root_info_idx)?);
    // TODO identify the data
    //let Some(_) = id0.output_file_encoding_idx(root_info_idx) else {todo!()};
    //let Some(_) = id0.ids_modenode_id(root_info_idx) else {todo!()};
    //id0.user_closed_source_files(root_info_idx).unwrap().collect();
    //let Some(_) = id0.problem_lists(root_info_idx) else {todo!()};
    //let Some(_) = id0.archive_file_path(root_info_idx) else {todo!()};
    //let Some(_) = id0.abi_name(root_info_idx) else {todo!()};
    //id0.debug_binary_paths(root_info_idx).unwrap().collect();
    //let Some(_) = id0.strings_encodings(root_info_idx) else {todo!()};
    //let Some(_) = id0.text_representation_options(root_info_idx) else {todo!()};
    //let Some(_) = id0.graph_representation_options(root_info_idx) else {todo!()};
    //let Some(_) = id0.instant_idc_statements(root_info_idx) else {todo!()};
    //let Some(_) = id0.assembler_include_filename(root_info_idx) else {todo!()};
    //id0.notepad_data(root_info_idx).unwrap().collect();
    //let Some(_) = id0.instant_idc_statements_old(root_info_idx) else {todo!()};
    //let Some(_) = id0.segment_group_info(root_info_idx) else {todo!()};
    //id0.selectors(root_info_idx).unwrap().collect();
    //let Some(_) = id0.file_format_name_loader(root_info_idx) else {todo!()};

    Ok(())
}
