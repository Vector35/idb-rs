use rstest::rstest;

use std::fs::File;
use std::hash::Hasher;
use std::io::{BufWriter, Cursor};
use std::path::{Path, PathBuf};

use crate::id0::function::{IDBFunction, RegisterName, StackNames};
use crate::id0::segment_register::Srarea;
use crate::id0::{FileRegions, Segment};
use crate::*;

macro_rules! assert_dyn {
    ($test_root:literal, $(&)? $filename:ident, $(&)? $value:ident $(,)?) => {{
        assert_dyn_data($test_root, &$filename, stringify!($value), &$value);
    }};
}

fn assert_dyn_data<T: Serialize>(
    test_root: &str,
    filename: &str,
    test_name: &str,
    data: &T,
) {
    let root_env = env!("CARGO_MANIFEST_DIR");
    let snapfile = format!(
        "{root_env}/src/snapshots/{test_root}@{}__{test_name}.snap",
        filename.replace("/", "__"),
    );

    if !std::fs::exists(&snapfile).unwrap() {
        // just create the file
        generate_file(&snapfile, test_name, data);
        return;
    }

    // output the file into a new and compare with the original
    let snapfile_new = format!("{snapfile}.new");
    let new_hash = generate_file(&snapfile_new, test_name, data);
    let old_hash = read_hash(&snapfile);

    // ensure the new file is equal to the old one
    // what's the chance of a hash colistion? 1 in u64::MAX?
    assert!(
        new_hash == old_hash,
        "Files Hash don't match: {snapfile:?} {snapfile_new:?}"
    );
    // if the files are equal delete the new one
    std::fs::remove_file(&snapfile_new).unwrap();
}

const HASH_SIZE: usize = 8;
const HASH_PREV: &str = "---\nhash: ";

fn read_hash(filename: &str) -> u64 {
    let mut file = File::open(filename).unwrap();
    let mut buf = [0u8; HASH_SIZE * 2]; // 2 because 1 byte is 2 chars
    file.seek(SeekFrom::Start(HASH_PREV.len().try_into().unwrap()))
        .unwrap();
    file.read_exact(&mut buf).unwrap();
    u64::from_str_radix(str::from_utf8(&buf).unwrap(), 16).unwrap()
}

fn generate_file<T: Serialize>(
    filename: &str,
    test_name: &str,
    data: &T,
) -> u64 {
    let mut file = BufWriter::new(File::create(filename).unwrap());
    let hash_dummy = core::str::from_utf8(&[b'!'; HASH_SIZE * 2]).unwrap();
    file.write_fmt(format_args!(
        "{HASH_PREV}{hash_dummy}\nsource: {}\nexpression: {}\n---\n",
        file!(),
        test_name,
    ))
    .unwrap();
    struct MyFile<W: std::io::Write> {
        file: W,
        hash: rustc_hash::FxHasher,
    }
    impl<W: std::io::Write> std::fmt::Write for MyFile<W> {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.hash.write(s.as_bytes());
            match self.file.write_all(s.as_bytes()) {
                Ok(_) => Ok(()),
                Err(_) => Err(std::fmt::Error::default()),
            }
        }
    }
    let mut my_file = MyFile {
        file,
        hash: rustc_hash::FxHasher::with_seed(0),
    };
    let config = ron::ser::PrettyConfig::default()
        .indentor(" ")
        .separator(" ")
        .struct_names(false)
        .escape_strings(true);
    // write the serialized type
    ron::ser::to_writer_pretty(&mut my_file, data, config).unwrap();
    // goes back and write the calculated hash
    my_file
        .file
        .seek(SeekFrom::Start(HASH_PREV.len().try_into().unwrap()))
        .unwrap();
    let hash = my_file.hash.finish();
    let hash_str = format!("{hash:0width$X}", width = HASH_SIZE * 2);
    assert!(
        hash_str.len() <= HASH_SIZE * 2,
        "Hash len is too big: {}",
        hash_str.len()
    );
    my_file.file.write_all(hash_str.as_bytes()).unwrap();
    // return the hash
    hash
}

#[rstest]
fn parse_til(#[files("resources/tils/**/*.til")] file: PathBuf) {
    parse_til_inner(file)
}

#[rstest]
fn parse_idb(
    #[files("resources/idbs/**/*.i64")]
    #[files("resources/idbs/**/*.idb")]
    filename: PathBuf,
) {
    parse_idb_inner(filename)
}

fn remove_base_dir<'a>(
    file: &'a Path,
    resource: &'static str,
) -> impl Iterator<Item = std::path::Component<'a>> {
    let root_env = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(root_env).join("resources").join(resource);
    if !file.starts_with(&root) {
        panic!("Invalid Path {root_env:?}: {:?}", file.to_str());
    }
    let len = root.components().count();
    file.components().skip(len)
}

fn parse_til_inner(file: PathBuf) {
    let file_suffix: PathBuf = remove_base_dir(&file, "tils").collect();
    let file_suffix_str = file_suffix.to_str().unwrap();
    println!("{file_suffix_str}");
    // makes sure it don't read out-of-bounds
    let mut input = BufReader::new(File::open(file).unwrap());
    // TODO make a SmartReader
    let til = TILSection::read(&mut input).unwrap();
    assert_dyn!("parse_til", file_suffix_str, til);

    assert_eq!(
        input.peek_u8().unwrap(),
        None,
        "unable to consume the entire TIL file"
    );
}

fn parse_idb_inner(file: PathBuf) {
    let filename: PathBuf = remove_base_dir(&file, "idbs").collect();
    let filename_str = filename.to_str().unwrap();
    println!("{filename_str}");
    let mut input = BufReader::new(File::open(&file).unwrap());
    let format = identify_idb_file(&mut input).unwrap();
    match format {
        IDBFormats::Separated(IDAVariants::IDA32(sections)) => {
            parse_idb_format(filename_str, &mut input, &sections)
        }
        IDBFormats::Separated(IDAVariants::IDA64(sections)) => {
            parse_idb_format(filename_str, &mut input, &sections)
        }
        IDBFormats::InlineUncompressed(sections) => {
            parse_idb_format(filename_str, &mut input, &sections)
        }
        IDBFormats::InlineCompressed(compressed) => {
            let mut decompressed = Vec::new();
            let sections = compressed
                .decompress_into_memory(input, &mut decompressed)
                .unwrap();
            parse_idb_format(
                filename_str,
                &mut Cursor::new(decompressed),
                &sections,
            );
        }
    }
}

fn parse_idb_format<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
    filename: &str,
    input: &mut I,
    sections: &F,
) {
    // parse sectors
    let id0 = sections
        .read_id0(&mut *input, sections.id0_location().unwrap())
        .unwrap();
    let id1 = sections
        .read_id1(&mut *input, sections.id1_location().unwrap())
        .unwrap();
    let id2 = sections
        .id2_location()
        .map(|id2| sections.read_id2(&mut *input, id2))
        .transpose()
        .unwrap();
    let til = sections
        .til_location()
        .map(|til| sections.read_til(&mut *input, til).unwrap());
    assert_dyn!("parse_idb", filename, til);
    let nam = sections
        .nam_location()
        .map(|idx| sections.read_nam(&mut *input, idx).unwrap());
    assert_dyn!("parse_idb", filename, nam);
    parse_idb_data(filename, &id0, &id1, id2.as_ref(), til.as_ref())
}

fn parse_idb_data<K>(
    filename: &str,
    id0: &ID0Section<K>,
    id1: &ID1Section<K>,
    id2: Option<&ID2Section<K>>,
    til: Option<&TILSection>,
) where
    K: IDAKind,
{
    // parse all id0 information
    let root_netnode = id0.root_node().unwrap();
    let ida_info = id0.ida_info(root_netnode.into()).unwrap();
    let netdelta = ida_info.netdelta();
    let proc = crate::processors::get_processor(
        ida_info.version,
        &ida_info.target.processor,
    )
    .unwrap();
    assert_dyn!("parse_idb", filename, ida_info);

    let seg_idx = id0.segments_idx().unwrap().unwrap();
    let mut segments: Vec<Segment<K>> =
        id0.segments(seg_idx).map(Result::unwrap).collect();
    segments.sort_unstable_by_key(|seg| {
        (seg.address.start, seg.address.end, seg.selector)
    });
    assert_dyn!("parse_idb", filename, segments);

    // TODO default into `$ regs`?
    if let Some((info, srareas_idx)) =
        proc.registers_info().zip(id0.srareas_idx().unwrap())
    {
        let mut srareas: Vec<(&'static str, Vec<Srarea<K>>)> = vec![];
        for (sreg_idx, sreg) in info.segment_register_names().iter().enumerate()
        {
            let mut srareas_reg: Vec<Srarea<K>> = id0
                .srareas(srareas_idx, sreg_idx.try_into().unwrap())
                .map(Result::unwrap)
                .collect();
            srareas_reg.sort_unstable_by_key(|seg| seg.range.start);
            srareas.push((*sreg, srareas_reg));
        }
        srareas.sort_unstable_by_key(|seg| seg.0);
        assert_dyn!("parse_idb", filename, srareas);
    }

    let loader_name: Option<Vec<&str>> = id0
        .loader_name()
        .unwrap()
        .map(|iter| iter.map(Result::unwrap).collect());
    assert_dyn!("parse_idb", filename, loader_name);

    let root_info_idx = id0.root_node().unwrap();
    // I belive the input file should always be present, but maybe I'm wrong,
    // I need know if this unwrap panics
    let input_file = id0.input_file(root_info_idx).unwrap();
    assert_dyn!("parse_idb", filename, input_file);

    let input_file_size = id0.input_file_size(root_info_idx).unwrap();
    assert_dyn!("parse_idb", filename, input_file_size);

    let input_file_crc32 =
        id0.input_file_crc32(root_info_idx).unwrap().unwrap();
    assert_dyn!("parse_idb", filename, input_file_crc32);

    let input_file_sha256 = id0.input_file_sha256(root_info_idx).unwrap();
    assert_dyn!("parse_idb", filename, input_file_sha256);

    let input_file_md5 = id0.input_file_md5(root_info_idx).unwrap();
    assert_dyn!("parse_idb", filename, input_file_md5);

    // TODO I think database information is always available, check that...
    let database_num_opens =
        id0.database_num_opens(root_info_idx).unwrap().unwrap();
    assert_dyn!("parse_idb", filename, database_num_opens);

    let database_secs_opens =
        id0.database_secs_opens(root_info_idx).unwrap().unwrap();
    assert_dyn!("parse_idb", filename, database_secs_opens);

    let database_creation_time =
        id0.database_creation_time(root_info_idx).unwrap().unwrap();
    assert_dyn!("parse_idb", filename, database_creation_time);

    let database_initial_version = id0
        .database_initial_version(root_info_idx)
        .unwrap()
        .unwrap();
    assert_dyn!("parse_idb", filename, database_initial_version);

    let database_creation_version =
        id0.database_creation_version(root_info_idx);
    assert_dyn!("parse_idb", filename, database_creation_version);

    let c_predefined_macros = id0.c_predefined_macros(root_info_idx);
    assert_dyn!("parse_idb", filename, c_predefined_macros);

    let c_header_path = id0.c_header_path(root_info_idx);
    assert_dyn!("parse_idb", filename, c_header_path);

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

    let file_regions_idx = id0.file_regions_idx().unwrap();
    let file_regions: Vec<FileRegions<K>> = id0
        .file_regions(file_regions_idx, ida_info.version)
        .map(Result::unwrap)
        .collect();
    assert_dyn!("parse_idb", filename, file_regions);

    if let Some(funcord_idx) = id0.funcords_idx().unwrap() {
        let funcords: Vec<Address<K>> = id0
            .funcords(funcord_idx)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_dyn!("parse_idb", filename, funcords);
        if let Some(funcs_idx) = id0.funcs_idx().unwrap() {
            let function_comments: Vec<(u64, Option<String>, Option<String>)> =
                funcords
                    .into_iter()
                    .filter_map(|addr| {
                        let cmt = id0
                            .func_cmt(funcs_idx, netdelta, addr)
                            .unwrap()
                            .map(|str| str.to_string());
                        let cmt_repeatable = id0
                            .func_cmt(funcs_idx, netdelta, addr)
                            .unwrap()
                            .map(|str| str.to_string());
                        if cmt.is_none() && cmt_repeatable.is_none() {
                            return None;
                        }
                        Some((addr.0.into_u64(), cmt, cmt_repeatable))
                    })
                    .collect();
            assert_dyn!("parse_idb", filename, function_comments);

            let fchunks: Vec<(
                IDBFunction<K>,
                Option<(Vec<RegisterName<K>>, StackNames)>,
            )> = id0
                .fchunks(funcs_idx)
                .map(|func| {
                    let func = func?;
                    let regs = if let id0::function::IDBFunctionType::NonTail(
                        func_data,
                    ) = &func.extra
                    {
                        let regs = id0
                            .function_defined_registers(
                                netdelta, &func, func_data,
                            )
                            .collect::<Result<_>>()?;
                        let stack = id0.function_defined_variables(
                            &ida_info, &func, func_data,
                        )?;
                        Some((regs, stack))
                    } else {
                        None
                    };
                    Ok((func, regs))
                })
                .collect::<Result<_>>()
                .unwrap();
            assert_dyn!("parse_idb", filename, fchunks);
        }
    }
    let entry_points = id0.entry_points(&ida_info).unwrap();
    assert_dyn!("parse_idb", filename, entry_points);

    let _ = id0.dirtree_bpts().unwrap();
    let _ = id0.dirtree_enums().unwrap();

    if let Some(dirtree_names) = id0.dirtree_names().unwrap() {
        dirtree_names.visit_leafs(|addr| {
            // NOTE it's know that some labels are missing from the byte
            // info but not from the databases, maybe in cases they are
            // created in debug-memory-pages or similar...
            let addr_info = crate::addr_info::AddressInfo::new(
                id0,
                id1,
                id2,
                netdelta,
                Address::from_raw(*addr),
            )
            .or_else(|| {
                // TODO make sure this new_forced is required
                crate::addr_info::AddressInfo::new_forced(
                    id0,
                    netdelta,
                    Address::from_raw(*addr),
                )
            })
            .unwrap();
            let _name = addr_info.label().unwrap();
        });
    }
    if let Some((_dirtree_tinfos, til)) = id0.dirtree_tinfos().unwrap().zip(til)
    {
        _dirtree_tinfos.visit_leafs(|ord| {
            let _til = til.get_ord((*ord).into()).unwrap();
        });
    }
    let _ = id0.dirtree_imports().unwrap();
    let _ = id0.dirtree_structs().unwrap();
    let _ = id0.dirtree_function_address().unwrap();
    let _ = id0.dirtree_bookmarks_tiplace().unwrap();
    let _ = id0.dirtree_bookmarks_idaplace().unwrap();
    let _ = id0.dirtree_bookmarks_structplace().unwrap();
}
