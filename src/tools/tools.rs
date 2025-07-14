mod dump_dirtree;
mod dump_til;
use dump_til::dump_til;
mod dump_id0;
use dump_id0::dump_id0;
mod dump_id1;
use dump_id1::dump_id1;
mod dump_id2;
use dump_id2::dump_id2;
mod dump_nam;
use dump_nam::dump_nam;
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
use idb_rs::id0::ID0Section;
use idb_rs::id2::ID2Section;
use idb_rs::nam::NamSection;
use idb_rs::til::section::TILSection;
use idb_rs::{
    identify_idb_file, IDAKind, IDAVariants, IDBFormat, IDBFormats, IDA32,
    IDA64,
};
use tilib::tilib_print;
mod produce_idc;
use produce_idc::produce_idc;

use idb_rs::id1::ID1Section;

use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
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
    /// Dump all entries of the ID2 database
    DumpID2,
    /// Dump all entries of the Nam database
    DumpNam,
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

trait ParseSection {
    type Section<K: IDAKind>;
    fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
        idb: F,
        input: I,
    ) -> Result<Self::Section<K>>;
}

fn get_sections<P: ParseSection>(
    args: &Args,
) -> Result<IDAVariants<P::Section<IDA32>, P::Section<IDA64>>> {
    match args.input_type() {
        FileType::Til => Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            get_sections_inner::<_, P>(
                identify_idb_file(&mut input)?,
                &mut input,
            )
        }
    }
}

fn get_sections_inner<I: BufRead + Seek, P: ParseSection>(
    format: IDBFormats,
    input: &mut I,
) -> Result<IDAVariants<P::Section<IDA32>, P::Section<IDA64>>> {
    match format {
        idb_rs::IDBFormats::Separated(IDAVariants::IDA32(sections)) => {
            P::parse_section(sections, input).map(IDAVariants::IDA32)
        }
        idb_rs::IDBFormats::Separated(IDAVariants::IDA64(sections)) => {
            P::parse_section(sections, input).map(IDAVariants::IDA64)
        }
        idb_rs::IDBFormats::InlineUncompressed(sections) => {
            P::parse_section(sections, input).map(IDAVariants::IDA64)
        }
        idb_rs::IDBFormats::InlineCompressed(compressed) => {
            let mut decompressed = Vec::new();
            let sections = compressed
                .decompress_into_memory(&mut *input, &mut decompressed)?;
            P::parse_section(sections, input).map(IDAVariants::IDA64)
        }
    }
}

fn get_id0_section(
    args: &Args,
) -> Result<IDAVariants<ID0Section<IDA32>, ID0Section<IDA64>>> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = ID0Section<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            input: I,
        ) -> Result<Self::Section<K>> {
            let location = idb.id0_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID0 sector")
            })?;
            idb.read_id0(input, location)
        }
    }
    get_sections::<Parse>(args)
}

fn get_id1_section(
    args: &Args,
) -> Result<IDAVariants<ID1Section<IDA32>, ID1Section<IDA64>>> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = ID1Section<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            input: I,
        ) -> Result<Self::Section<K>> {
            let location = idb.id1_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID1 sector")
            })?;
            idb.read_id1(input, location)
        }
    }
    get_sections::<Parse>(args)
}

fn get_id2_section(
    args: &Args,
) -> Result<IDAVariants<ID2Section<IDA32>, ID2Section<IDA64>>> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = ID2Section<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            input: I,
        ) -> Result<Self::Section<K>> {
            let location = idb.id2_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID2 sector")
            })?;
            idb.read_id2(input, location)
        }
    }
    get_sections::<Parse>(args)
}

fn get_nam_section(
    args: &Args,
) -> Result<IDAVariants<NamSection<IDA32>, NamSection<IDA64>>> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = NamSection<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            input: I,
        ) -> Result<Self::Section<K>> {
            let location = idb.nam_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a Nam sector")
            })?;
            idb.read_nam(input, location)
        }
    }
    get_sections::<Parse>(args)
}

fn get_til_section(args: &Args) -> Result<TILSection> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = TILSection;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            input: I,
        ) -> Result<Self::Section<K>> {
            let location = idb.til_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a Nam sector")
            })?;
            idb.read_til(input, location)
        }
    }
    match get_sections::<Parse>(args)? {
        IDAVariants::IDA32(x) | IDAVariants::IDA64(x) => Ok(x),
    }
}

#[allow(type_alias_bounds)]
type Id0Id1Id2Variant<K: IDAKind> =
    (ID0Section<K>, ID1Section<K>, Option<ID2Section<K>>);
type Id0Id1Id2Variants =
    IDAVariants<Id0Id1Id2Variant<IDA32>, Id0Id1Id2Variant<IDA64>>;

fn get_id0_id1_id2_sections(args: &Args) -> Result<Id0Id1Id2Variants> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = Id0Id1Id2Variant<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            mut input: I,
        ) -> Result<Self::Section<K>> {
            let id0_location = idb.id0_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID0 sector")
            })?;
            let id1_location = idb.id1_location().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID1 sector")
            })?;
            let id2_location = idb.id2_location();
            let id0 = idb.read_id0(&mut input, id0_location)?;
            let id1 = idb.read_id1(&mut input, id1_location)?;
            let id2 = id2_location
                .map(|id2| idb.read_id2(&mut input, id2))
                .transpose()?;
            Ok((id0, id1, id2))
        }
    }
    get_sections::<Parse>(args)
}

fn main() -> Result<()> {
    let args = Args::parse();

    match &args.operation {
        Operation::DumpTil => dump_til(&args),
        Operation::DumpID0 => dump_id0(&args),
        Operation::DumpID1 => dump_id1(&args),
        Operation::DumpID2 => dump_id2(&args),
        Operation::DumpNam => dump_nam(&args),
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
