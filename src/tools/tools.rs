mod dump_dirtree;
mod dump_til;
use dump_til::dump_til;
mod dump_id0;
use dump_id0::dump_id0;
mod dump_id1;
use dump_id1::dump_id1;
//mod split_idb;
//use split_idb::split_idb;
mod decompress_til;
use decompress_til::decompress_til;
mod dump_functions;
use dump_functions::dump_functions;
mod dump_segments;
use dump_segments::dump_segments;
mod dump_segstrings;
use dump_segstrings::dump_segstrings;
mod dump_loader_name;
use dump_loader_name::dump_loader_name;
mod dump_root_info;
use dump_root_info::dump_root_info;
mod dump_addr_info;
use dump_addr_info::dump_addr_info;
mod dump_dirtree_types;
use dump_dirtree_types::dump_dirtree_types;
mod dump_dirtree_structs;
use dump_dirtree_structs::dump_dirtree_structs;
mod dump_dirtree_enums;
use dump_dirtree_enums::dump_dirtree_enums;
mod dump_dirtree_funcs;
use dump_dirtree_funcs::dump_dirtree_funcs;
mod dump_dirtree_names;
use dump_dirtree_names::dump_dirtree_names;
mod dump_dirtree_imports;
use dump_dirtree_imports::dump_dirtree_imports;
mod dump_dirtree_bpts;
use dump_dirtree_bpts::dump_dirtree_bpts;
mod dump_dirtree_bookmarks_idaplace;
use dump_dirtree_bookmarks_idaplace::dump_dirtree_bookmarks_idaplace;
mod dump_dirtree_bookmarks_structplace;
use dump_dirtree_bookmarks_structplace::dump_dirtree_bookmarks_structplace;
mod dump_dirtree_bookmarks_tiplace;
use dump_dirtree_bookmarks_tiplace::dump_dirtree_bookmarks_tiplace;
mod tilib;
use idb_rs::id0::ID0SectionVariants;
use idb_rs::til::section::TILSection;
use idb_rs::IDBFormat;
use tilib::tilib_print;
mod produce_idc;
use produce_idc::produce_idc;

use idb_rs::id1::ID1Section;

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// Parse IDA files and output it's data
#[derive(Clone, Debug, Parser)]
struct Args {
    /// input filename to parse
    #[arg(short, long)]
    input: PathBuf,
    /// parse the filename using this format, if not specified use the input file ext, otherwise default to idb 32bits
    #[arg(short, long, value_enum)]
    force_type: Option<FileType>,
    // operation to execute
    #[command(subcommand)]
    operation: Operation,
}

/// File type to parse
#[derive(Clone, Copy, Debug, ValueEnum)]
enum FileType {
    /// IDB file
    Idb,
    // TODO verify if is necessary to parse standalone id0 files
    ///// ID0 database file
    //ID0,
    /// TIL lib types file
    Til,
}

/// File type to parse
#[derive(Clone, Debug, Subcommand)]
enum Operation {
    /// Dump all the TIL type
    DumpTil,
    /// Dump all entries of the ID0 database
    DumpID0,
    /// Dump all entries of the ID1 database
    DumpID1,
    //SplitIDB(SplitIDBArgs),
    /// Decompress the TIL Section and buckets
    DecompressTil(DecompressTilArgs),
    /// Dump all the function information
    DumpFunctions,
    /// Dump all the segments
    DumpSegments,
    /// Dump all the segments strings
    DumpSegStrings,
    /// Dump the loader names
    DumpLoaderNames,
    /// Dump the RootInfo
    DumpRootInfo,
    /// Dump all the address info
    DumpAddressInfo,
    /// Dump all the type from the diretory tree
    DumpDirtreeTypes,
    DumpDirtreeStructs,
    DumpDirtreeEnums,
    /// Dump all the functions from the diretory tree
    DumpDirtreeFuncs,
    /// Dump all the Names from the diretory tree
    DumpDirtreeNames,
    DumpDirtreeImports,
    DumpDirtreeBpts,
    DumpDirtreeBookmarksIdaplace,
    DumpDirtreeBookmarksStructplace,
    DumpDirtreeBookmarksTiplace,
    /// Print all til types from file and it's information
    PrintTilib(PrintTilibArgs),
    /// Print a IDC file from the IDB database
    ProduceIdc(ProduceIdcArgs),
}

///// Split the IDB file into it's decompressed sectors. Allow IDB and I64 files.
//#[derive(Clone, Debug, Parser)]
//struct SplitIDBArgs {
//    /// output path, defaults to the input file path
//    output_path: Option<PathBuf>,
//    /// output filename, defatuls to the input filename (without the extension)
//    output_filename: Option<OsString>,
//}

/// Decompress the TIL into a uncompressed version of the TIL. Allow IDB, I64 and TIL files.
#[derive(Clone, Debug, Parser)]
struct DecompressTilArgs {
    /// output filename
    output: PathBuf,
}

/// Decompress the TIL into a uncompressed version of the TIL. Allow IDB, I64 and TIL files.
#[derive(Clone, Debug, Parser)]
struct PrintTilibArgs {
    dump_struct_layout: Option<bool>,
}

/// Produce idc from an IDB database
#[derive(Clone, Debug, Parser)]
struct ProduceIdcArgs {
    banner: Vec<String>,
}

impl Args {
    pub fn input_type(&self) -> FileType {
        if let Some(input_type) = self.force_type {
            return input_type;
        }
        match self.input.extension().and_then(std::ffi::OsStr::to_str) {
            Some("idb") | Some("i64") => FileType::Idb,
            Some("til") => FileType::Til,
            //Some("id0") => FileType::ID0,
            _ => FileType::Idb,
        }
    }
}

fn get_id0_section(args: &Args) -> Result<ID0SectionVariants> {
    match args.input_type() {
        FileType::Til => Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    get_id0_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    get_id0_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)?;
                    get_id0_section_fmt(sections, Cursor::new(decompressed))
                }
            }
        }
    }
}

fn get_id0_section_fmt<F: IDBFormat, I: BufRead + Seek>(
    idb: F,
    input: I,
) -> Result<ID0SectionVariants> {
    let id0 = idb
        .id0_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a ID0 sector"))?;
    idb.read_id0(input, id0)
}

fn get_id1_section(args: &Args) -> Result<ID1Section> {
    match args.input_type() {
        FileType::Til => Err(anyhow!("TIL don't contains any ID1 data")),
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    get_id1_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    get_id1_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)?;
                    get_id1_section_fmt(sections, Cursor::new(decompressed))
                }
            }
        }
    }
}

fn get_id1_section_fmt<F: IDBFormat, I: BufRead + Seek>(
    idb: F,
    input: I,
) -> Result<ID1Section> {
    let id1 = idb
        .id1_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a ID1 sector"))?;
    idb.read_id1(input, id1)
}

fn get_til_section(args: &Args) -> Result<TILSection> {
    match args.input_type() {
        FileType::Til => {
            let mut input = BufReader::new(File::open(&args.input)?);
            TILSection::read(&mut input)
        }
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    get_til_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    get_til_section_fmt(sections, input)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)?;
                    get_til_section_fmt(sections, Cursor::new(decompressed))
                }
            }
        }
    }
}

fn get_til_section_fmt<F: IDBFormat, I: BufRead + Seek>(
    idb: F,
    input: I,
) -> Result<TILSection> {
    let location = idb
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    idb.read_til(input, location)
}

fn main() -> Result<()> {
    let args = Args::parse();

    match &args.operation {
        Operation::DumpTil => dump_til(&args),
        Operation::DumpID0 => dump_id0(&args),
        Operation::DumpID1 => dump_id1(&args),
        //Operation::SplitIDB(split_idbargs) => split_idb(&args, split_idbargs),
        Operation::DecompressTil(decompress_til_args) => {
            decompress_til(&args, decompress_til_args)
        }
        Operation::DumpFunctions => dump_functions(&args),
        Operation::DumpSegments => dump_segments(&args),
        Operation::DumpSegStrings => dump_segstrings(&args),
        Operation::DumpLoaderNames => dump_loader_name(&args),
        Operation::DumpRootInfo => dump_root_info(&args),
        Operation::DumpAddressInfo => dump_addr_info(&args),
        Operation::DumpDirtreeTypes => dump_dirtree_types(&args),
        Operation::DumpDirtreeStructs => dump_dirtree_structs(&args),
        Operation::DumpDirtreeEnums => dump_dirtree_enums(&args),
        Operation::DumpDirtreeFuncs => dump_dirtree_funcs(&args),
        Operation::DumpDirtreeNames => dump_dirtree_names(&args),
        Operation::DumpDirtreeImports => dump_dirtree_imports(&args),
        Operation::DumpDirtreeBpts => dump_dirtree_bpts(&args),
        Operation::DumpDirtreeBookmarksIdaplace => {
            dump_dirtree_bookmarks_idaplace(&args)
        }
        Operation::DumpDirtreeBookmarksStructplace => {
            dump_dirtree_bookmarks_structplace(&args)
        }
        Operation::DumpDirtreeBookmarksTiplace => {
            dump_dirtree_bookmarks_tiplace(&args)
        }
        Operation::PrintTilib(tilib_args) => tilib_print(&args, tilib_args),
        Operation::ProduceIdc(idc_args) => produce_idc(&args, idc_args),
    }
}
