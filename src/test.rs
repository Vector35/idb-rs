use rstest::rstest;

use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::id0::function::FunctionsAndComments;
use crate::id0::{FileRegions, Segment};
use crate::*;

#[test]
fn parse_id0_til() {
    let function = [
        0x0c, // Function Type
        0xaf, 0x81, 0x42, 0x01, 0x53, // TODO
        0x01, // void ret
        0x03, //n args
        0x3d, 0x08, 0x48, 0x4d, 0x4f, 0x44, 0x55, 0x4c, 0x45, 0x3d, 0x06, 0x44,
        0x57, 0x4f, 0x52, 0x44, 0x00,
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_destructor_function() {
    // from ComRAT-Orchestrator.i64 0x180007cf0
    // ```c
    // void __fastcall stringstream__basic_ios__sub_180007CF0_Destructor(
    //   basic_ios *__shifted(stringstream,0x94) a1
    // );
    // ```
    let function = [
        0x0c, // Function Type
        0x70, // TODO
        0x01, // void ret
        0x02, // n args (2 - 1 = 1)
        0x0a, // arg0 type is pointer
        0xfe, 0x80, 0x01, // pointer tah
        0x3d, // pointer type is typedef
        0x04, 0x23, 0x83, 0x69, // typedef ord is 233 -> basic_ios
        // ?????
        0x3d, // second typedef?
        0x04, 0x23, 0x83, 0x66, // typedef ord is 230 => stringstream
        0x82, 0x54, // ???? the 0x94 value?
        0x00, // the final value always present
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_function_ext_att() {
    // ```
    // Function {
    //   ret: Basic(Int { bytes: 4, is_signed: None }),
    //   args: [(
    //     Some("env"),
    //     Pointer(Pointer {
    //       closure: Default,
    //       tah: TAH(TypeAttribute(1)),
    //       typ: Struct(Ref {
    //         ref_type: Typedef("__jmp_buf_tag"),
    //         taudt_bits: SDACL(TypeAttribute(0))
    //       })
    //     }),
    //     None
    //   )],
    //   retloc: None }
    // ```
    let function = [
        0x0c, // func type
        0x13, // TODO
        0x07, // return int
        0x02, // 1 parameter
        0xff, 0x48, // TODO
        0x0a, // arg1 type pointer
        0xfe, 0x10, // TypeAttribute val
        0x02, // dt len 1
        0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64, 0x69,
        0x6d, // TODO some _string: "__org_arrdim"
        0x03, 0xac, 0x01, // TODO _other_thing
        0x0d, // arg1 pointer type struct
        0x01, // struct ref
        0x0e, 0x5f, 0x5f, 0x6a, 0x6d, 0x70, 0x5f, 0x62, 0x75, 0x66, 0x5f, 0x74,
        0x61, 0x67, // "__jmp_buf_tag"
        0x00, // end of type
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_aes_encrypt() {
    // ```c
    // void AES_ctr128_encrypt(
    //   const unsigned __int8 *in,
    //   unsigned __int8 *out,
    //   const unsigned int length,
    //   const AES_KEY *key,
    //   unsigned __int8 ivec[16],
    //   unsigned __int8 ecount_buf[16],
    //   unsigned int *num
    // );
    // ```
    let function = [
        0x0c, // type function
        0x13, 0x01, // ???
        0x08, // 7 args
        // arg1 ...
        0x0a, // pointer
        0x62, // const unsigned __int8
        // arg2 ...
        0x0a, // pointer
        0x22, // unsigned __int8
        // arg3 ...
        0x67, // const unsigned int
        // arg4 ...
        0x0a, // pointer
        0x7d, // const typedef
        0x08, 0x41, 0x45, 0x53, 0x5f, 0x4b, 0x45,
        0x59, // ordinal "AES_KEY"
        // arg5
        0xff, 0x48, // some flag in function arg
        0x0a, // pointer
        0xfe, 0x10, // TypeAttribute val
        0x02, // TypeAttribute loop once
        0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64, 0x69,
        0x6d, // string "__org_arrdim"
        0x03, 0xac, 0x10, // ???? some other TypeAttribute field
        0x22, // type unsigned __int8
        // arg6
        0xff, 0x48, // some flag in function arg
        0x0a, // pointer
        0xfe, 0x10, // TypeAttribute val
        0x02, // TypeAttribute loop once
        0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64, 0x69,
        0x6d, // string "__org_arrdim"
        0x03, 0xac, 0x10, // ???? some other TypeAttribute field
        0x22, // type unsigned __int8
        // arg7 ...
        0x0a, // pointer
        0x27, // unsigned int
        0x00,
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_spoiled_function_kernel_32() {
    // ```
    // TilType(Type { is_const: false, is_volatile: false, type_variant:
    //   Function(Function {
    //     ret: Type { is_const: false, is_volatile: false, type_variant: Basic(Void) },
    //     args: [
    //       (
    //         Some([117, 69, 120, 105, 116, 67, 111, 100, 101]),
    //         Type {
    //           is_const: false,
    //           is_volatile: false,
    //           type_variant: Typedef(Name([85, 73, 78, 84])) }, None)],
    //           retloc: None
    //         }
    //       )
    // })
    // ```
    let function = [
        0x0c, // function type
        0xaf, 0x81, // function cc extended...
        0x42, // flag
        0x01, // 0 regs nspoiled
        0x53, // cc
        0x01, // return type void
        0x02, // 1 param
        0x3d, // param 1 typedef
        0x05, 0x55, 0x49, 0x4e, 0x54, // typedef name
        0x00, //end
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_spoiled_function_invalid_reg() {
    // ```
    // 0x180001030:
    // TilType(Type { is_const: false, is_volatile: false, type_variant:
    //   Function(Function {
    //     ret: Type { is_const: false, is_volatile: false, type_variant: Basic(Void) },
    //     args: [], retloc: None
    //   })
    // })
    // ```
    let function = [
        0x0c, // function type
        0xaa, // extended function cc, 10 nspoiled
        0x71, // spoiled reg 0
        0x72, // spoiled reg 1
        0x73, // spoiled reg 2
        0x79, // spoiled reg 3
        0x7a, // spoiled reg 4
        0x7b, // spoiled reg 5
        0x7c, // spoiled reg 6
        0xc0, 0x08, // spoiled reg 7
        0xc4, 0x08, // spoiled reg 8
        0xc5, 0x08, // spoiled reg 9
        0x30, // cc
        0x01, // return type void
        0x01, // no params
        0x00, // end
    ];
    let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
}

#[test]
fn parse_struct_with_fixed() {
    let function = [
        0x0d, // stuct type
        0x31, // n = 0x30, mem_cnt = 6, packalig = 0
        0xf1, 0x80, 0x08, // struct att
        0x32, // member 0 => char
        0x01, // member 0 fixed_ext_att
        0x03, // member 1 => int16
        0x02, 0x10, // member 1 fixed_ext_att
        0x07, // member 2 => int
        0x02, 0x10, // member 2 fixed_ext_att
        0x3d, 0x03, 0x23, 0x48, // member 3 => typeref(8)
        0x02, 0x20, // member 3 fixed_ext_att
        0x08, // member 4 => bool
        0x02, 0x40, // member 4 fixed_ext_att
        0x1b, // member 5 array
        0x01, // member 5 nelem = 0
        0x32, // member 5 inner_type = char
        0x02, 0x08, // member 5 fixed_ext_att
        0x02, 0x13, // struct stuff
        0x00, //end
    ];
    let til = til::Type::new_from_id0(&function, vec![]).unwrap();
    let til::TypeVariant::Struct(til_struct) = til.type_variant else {
        unreachable!()
    };
    assert!(til_struct.extra_padding == Some(19));
}

#[rstest]
fn parse_til(
    #[files("resources/tils/**/*.til")]
    #[exclude("resources/tils/local/.*")]
    file: PathBuf,
) {
    parse_til_inner(file)
}

#[rstest]
fn parse_local_til(#[files("resources/tils/local/**/*.til")] file: PathBuf) {
    parse_til_inner(file)
}

#[rstest]
fn parse_idb(
    #[files("resources/idbs/**/*.i64")]
    #[files("resources/idbs/**/*.idb")]
    #[exclude("resources/idbs/local/.*")]
    filename: PathBuf,
) {
    parse_idb_inner(filename)
}

#[rstest]
fn parse_local_idb(
    #[files("resources/idbs/local/**/*.i64")]
    #[files("resources/idbs/local/**/*.idb")]
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
    insta::with_settings!({snapshot_suffix => file_suffix_str, sort_maps => true}, {
        insta::assert_yaml_snapshot!(til);
    });

    assert_eq!(
        input.peek_u8().unwrap(),
        None,
        "unable to consume the entire TIL file"
    );
}

fn parse_idb_inner(file: PathBuf) {
    let file_suffix: PathBuf = remove_base_dir(&file, "idbs").collect();
    println!("{}", file_suffix.to_str().unwrap());
    let mut input = BufReader::new(File::open(&file).unwrap());
    let format = identify_idb_file(&mut input).unwrap();
    insta::with_settings!({sort_maps => true}, {
        match format {
            IDBFormats::Separated(IDAVariants::IDA32(sections)) => {
                parse_idb_separated(file_suffix, &mut input, &sections)
            }
            IDBFormats::Separated(IDAVariants::IDA64(sections)) => {
                parse_idb_separated(file_suffix, &mut input, &sections)
            }
            IDBFormats::InlineUncompressed(sections) => {
                parse_idb_inlined(file_suffix, &mut input, &sections)
            }
            IDBFormats::InlineCompressed(compressed) => {
                let mut decompressed = Vec::new();
                let sections = compressed
                    .decompress_into_memory(input, &mut decompressed)
                    .unwrap();
                parse_idb_inlined(
                    file_suffix,
                    &mut Cursor::new(decompressed),
                    &sections,
                );
            }
        }
    });
}

fn parse_idb_separated<K: IDAKind, I: BufRead + Seek>(
    file_suffix: PathBuf,
    input: &mut I,
    sections: &SeparatedSections<K>,
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
    insta::with_settings!({snapshot_suffix => file_suffix.join("til").to_str().unwrap()}, {
        insta::assert_yaml_snapshot!(til);
    });
    let _nam = sections
        .nam_location()
        .map(|idx| sections.read_nam(&mut *input, idx));
    parse_idb_data(file_suffix, &id0, &id1, id2.as_ref(), til.as_ref())
}

fn parse_idb_inlined<I: BufRead + Seek>(
    file_suffix: PathBuf,
    input: &mut I,
    sections: &InlineUnCompressedSections,
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
    let _nam = sections
        .nam_location()
        .map(|idx| sections.read_nam(&mut *input, idx));
    parse_idb_data(file_suffix, &id0, &id1, id2.as_ref(), til.as_ref())
}

fn parse_idb_data<K>(
    file_suffix: PathBuf,
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
    insta::with_settings!({snapshot_suffix => file_suffix.join("ida_info").to_str().unwrap()}, {
        insta::assert_yaml_snapshot!(ida_info);
    });

    insta::with_settings!({snapshot_suffix => file_suffix.join("segments").to_str().unwrap()}, {
        let seg_idx = id0.segments_idx().unwrap().unwrap();
        let mut segments: Vec<Segment<K>> =
            id0.segments(seg_idx).map(Result::unwrap).collect();
        segments.sort_unstable_by_key(|seg| (seg.address.start, seg.address.end, seg.selector));
        insta::assert_yaml_snapshot!(segments);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("loader_name").to_str().unwrap()}, {
        let loader_name: Option<Vec<&str>> = id0
            .loader_name()
            .unwrap()
            .map(|iter| iter.map(Result::unwrap).collect());
        insta::assert_yaml_snapshot!(loader_name);
    });
    let root_info_idx = id0.root_node().unwrap();
    // I belive the input file should always be present, but maybe I'm wrong,
    // I need know if this unwrap panics
    insta::with_settings!({snapshot_suffix => file_suffix.join("input_file").to_str().unwrap()}, {
        let input_file = id0.input_file(root_info_idx).unwrap();
        insta::assert_yaml_snapshot!(input_file);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("input_file_size").to_str().unwrap()}, {
        let input_file_size = id0.input_file_size(root_info_idx).unwrap();
        insta::assert_yaml_snapshot!(input_file_size);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("input_file_crc32").to_str().unwrap()}, {
        let input_file_crc32 =
            id0.input_file_crc32(root_info_idx).unwrap().unwrap();
        insta::assert_yaml_snapshot!(input_file_crc32);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("input_file_sha256").to_str().unwrap()}, {
        let input_file_sha256 = id0.input_file_sha256(root_info_idx).unwrap();
        insta::assert_yaml_snapshot!(input_file_sha256);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("input_file_md5").to_str().unwrap()}, {
        let input_file_md5 = id0.input_file_md5(root_info_idx).unwrap();
        insta::assert_yaml_snapshot!(input_file_md5);
    });
    // TODO I think database information is always available, check that...
    insta::with_settings!({snapshot_suffix => file_suffix.join("database_num_opens").to_str().unwrap()}, {
        let database_num_opens =
            id0.database_num_opens(root_info_idx).unwrap().unwrap();
        insta::assert_yaml_snapshot!(database_num_opens);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("database_secs_opens").to_str().unwrap()}, {
        let database_secs_opens =
            id0.database_secs_opens(root_info_idx).unwrap().unwrap();
        insta::assert_yaml_snapshot!(database_secs_opens);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("database_creation_time").to_str().unwrap()}, {
        let database_creation_time =
            id0.database_creation_time(root_info_idx).unwrap().unwrap();
        insta::assert_yaml_snapshot!(database_creation_time);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("database_initial_version").to_str().unwrap()}, {
        let database_initial_version = id0
            .database_initial_version(root_info_idx)
            .unwrap()
            .unwrap();
        insta::assert_yaml_snapshot!(database_initial_version);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("database_creation_version").to_str().unwrap()}, {
        let database_creation_version =
            id0.database_creation_version(root_info_idx);
        insta::assert_yaml_snapshot!(database_creation_version);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("c_predefined_macros").to_str().unwrap()}, {
        let c_predefined_macros = id0.c_predefined_macros(root_info_idx);
        insta::assert_yaml_snapshot!(c_predefined_macros);
    });
    insta::with_settings!({snapshot_suffix => file_suffix.join("c_header_path").to_str().unwrap()}, {
        let c_header_path = id0.c_header_path(root_info_idx);
        insta::assert_yaml_snapshot!(c_header_path);
    });
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

    insta::with_settings!({snapshot_suffix => file_suffix.join("file_regions").to_str().unwrap()}, {
        let file_regions_idx = id0.file_regions_idx().unwrap();
        let file_regions: Vec<FileRegions<K>> = id0
            .file_regions(file_regions_idx, ida_info.version)
            .map(Result::unwrap)
            .collect();
        insta::assert_yaml_snapshot!(file_regions);
    });
    if let Some(func_idx) = id0.funcs_idx().unwrap() {
        let _functions_and_comments: Vec<FunctionsAndComments<'_, K>> = id0
            .functions_and_comments(func_idx)
            .map(Result::unwrap)
            .collect();
    }
    insta::with_settings!({snapshot_suffix => file_suffix.join("entry_points").to_str().unwrap()}, {
        let entry_points = id0.entry_points().unwrap();
        insta::assert_yaml_snapshot!(entry_points);
    });
    let _ = id0.dirtree_bpts().unwrap();
    let _ = id0.dirtree_enums().unwrap();

    if let Some(dirtree_names) = id0.dirtree_names().unwrap() {
        let image_base = ida_info.netdelta();
        dirtree_names.visit_leafs(|addr| {
            // NOTE it's know that some labels are missing from the byte
            // info but not from the databases, maybe in cases they are
            // created in debug-memory-pages or similar...
            let addr_info = crate::addr_info::AddressInfo::new(
                id0,
                id1,
                id2,
                image_base,
                Address::from_raw(*addr),
            )
            .or_else(|| {
                // TODO make sure this new_forced is required
                crate::addr_info::AddressInfo::new_forced(
                    id0,
                    image_base,
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
