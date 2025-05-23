pub mod netnode {
    /// Maximum length of a netnode name. WILL BE REMOVED IN THE FUTURE
    pub const MAXNAMESIZE: u32 = 512;

    /// Maximum length of a name. We permit names up to 32KB-1 bytes.
    pub const MAX_NODENAME_SIZE: u32 = 32 * 1024;

    /// Maximum length of strings or objects stored in a supval array element
    pub const MAXSPECSIZE: u32 = 1024;

    /// A number to represent a bad netnode reference
    pub const BADNODE: u64 = u64::MAX;

    /// Reserved netnode tags
    /// Tags internally used in netnodes. You should not use them
    /// for your tagged alt/sup/char/hash arrays.
    pub mod nn_res {
        /// Array of altvals
        pub const ARRAY_ALT_TAG: u8 = b'A';
        /// Array of supvals
        pub const ARRAY_SUP_TAG: u8 = b'S';
        /// Array of hashvals
        pub const HASH_TAG: u8 = b'H';
        /// Value of netnode
        pub const VALUE_TAG: u8 = b'V';
        /// Name of netnode
        pub const NAME_TAG: u8 = b'N';
        /// Links between netnodes
        pub const LINK_TAG: u8 = b'L';
    }

    // Internal bit used to request ea2node() mapping of alt and sup indexes
    pub const NETMAP_IDX: u32 = 0x100;
    // Internal bit used to request ea2node() mapping of alt values.
    // Such values are stored after being incremented by one.
    pub const NETMAP_VAL: u32 = 0x200;
    // Internal bit used to make sure a string obtained with getblob() is
    // null-terminated.
    pub const NETMAP_STR: u32 = 0x400;
    // Internal bit: use 8-bit indexes.
    pub const NETMAP_X8: u32 = 0x800;
    // Internal bit: use 8-bit values.
    pub const NETMAP_V8: u32 = 0x1000;
    // Internal bit: value is a netnode index
    pub const NETMAP_VAL_NDX: u32 = 0x2000;
}

/// Structure of altvals array
/// Structure of altvals array of netnode(ea).
/// altvals is a virtual array of 32-bit longs attached to a netnode.
/// the size of this array is unlimited. Unused indexes are not kept in the
/// database. We use only first several indexes to this array.
pub mod nalt {
    ///// reserved for enums
    //const NALT_ENUM: i32 = -2;
    ///// 16-bit byte value
    //const NALT_WIDE: i32 = -1;

    /// switch idiom address (used at jump targets)
    pub const NALT_SWITCH: u8 = 1;
    ///// offset base 2
    //const NALT_OBASE1: u8 = 2;
    /// struct id
    pub const NALT_STRUCT: u8 = 3;
    ///// 'seen' flag (used in structures)
    //const NALT_SEENF: u8 = 4;
    ///// outer offset base 1
    //const NALT_OOBASE0: u8 = 5;
    ///// outer offset base 2
    //const NALT_OOBASE1: u8 = 6;
    ///// saved xref address in the xrefs window
    //const NALT_XREFPOS: u8 = 7;
    /// additional flags for an item
    pub const NALT_AFLAGS: u8 = 8;
    /// source line number
    pub const NALT_LINNUM: u8 = 9;
    /// absolute segment location
    pub const NALT_ABSBASE: u8 = 10;
    /// enum id for the first operand
    pub const NALT_ENUM0: u8 = 11;
    /// enum id for the second operand
    pub const NALT_ENUM1: u8 = 12;
    ///// struct offset, struct id for the first operand
    //const NALT_STROFF0: u8 = 13;
    ///// struct offset, struct id for the second operand
    //const NALT_STROFF1: u8 = 14;
    /// number of bytes purged from the stack when a function is called indirectly
    pub const NALT_PURGE: u8 = 15;
    /// type of string item
    pub const NALT_STRTYPE: u8 = 16;
    /// alignment value if the item is #FF_ALIGN
    /// (should by equal to power of 2)
    pub const NALT_ALIGN: u8 = 17;

    ///// linear address of byte referenced by
    ///// high 16 bits of an offset (FF_0HIGH)
    //const NALT_HIGH0: u8 = 18;
    ///// linear address of byte referenced by
    ///// high 16 bits of an offset (FF_1HIGH)
    //const NALT_HIGH1: u8 = 19;
    /// instruction/data background color
    pub const NALT_COLOR: u8 = 20;

    /// Netnode xref tags
    /// Tag values to store xrefs
    pub mod x {
        /// code xref to, idx: target address
        pub const NALT_CREF_TO: u8 = b'X';
        /// code xref from, idx: source address
        pub const NALT_CREF_FROM: u8 = b'x';
        /// data xref to, idx: target address
        pub const NALT_DREF_TO: u8 = b'D';
        /// data xref from, idx: source address
        pub const NALT_DREF_FROM: u8 = b'd';
    }
}

/// Structure of supvals array
/// Structure of supvals array of netnode(ea).
/// Supvals is a virtual array of objects of arbitrary length attached
/// to a netnode (length of one element is limited by #MAXSPECSIZE, though)
/// We use first several indexes to this array:
pub mod nsup {
    /// regular comment
    pub const NSUP_CMT: u8 = 0;
    /// repeatable comment
    pub const NSUP_REPCMT: u8 = 1;
    /// forced operand 1
    pub const NSUP_FOP1: u8 = 2;
    /// forced operand 2
    pub const NSUP_FOP2: u8 = 3;
    /// jump table info
    pub const NSUP_JINFO: u8 = 4;
    /// array parameters
    pub const NSUP_ARRAY: u8 = 5;
    /// OMF: group of segments (not used anymore)
    pub const NSUP_OMFGRP: u8 = 6;
    /// forced operand 3
    pub const NSUP_FOP3: u8 = 7;
    /// switch information
    pub const NSUP_SWITCH: u8 = 8;
    /// complex reference information for operand 1
    pub const NSUP_REF0: u8 = 9;
    /// complex reference information for operand 2
    pub const NSUP_REF1: u8 = 10;
    /// complex reference information for operand 3
    pub const NSUP_REF2: u8 = 11;
    /// outer complex reference information for operand 1
    pub const NSUP_OREF0: u8 = 12;
    /// outer complex reference information for operand 2
    pub const NSUP_OREF1: u8 = 13;
    /// outer complex reference information for operand 3
    pub const NSUP_OREF2: u8 = 14;
    /// stroff: struct path for the first operand
    pub const NSUP_STROFF0: u8 = 15;
    /// stroff: struct path for the second operand
    pub const NSUP_STROFF1: u8 = 16;
    /// segment translations
    pub const NSUP_SEGTRANS: u8 = 17;
    /// forced operand 4
    pub const NSUP_FOP4: u8 = 18;
    /// forced operand 5
    pub const NSUP_FOP5: u8 = 19;
    /// forced operand 6
    pub const NSUP_FOP6: u8 = 20;
    /// complex reference information for operand 4
    pub const NSUP_REF3: u8 = 21;
    /// complex reference information for operand 5
    pub const NSUP_REF4: u8 = 22;
    /// complex reference information for operand 6
    pub const NSUP_REF5: u8 = 23;
    /// outer complex reference information for operand 4
    pub const NSUP_OREF3: u8 = 24;
    /// outer complex reference information for operand 5
    pub const NSUP_OREF4: u8 = 25;
    /// outer complex reference information for operand 6
    pub const NSUP_OREF5: u8 = 26;
    /// saved xref address and type in the xrefs window
    pub const NSUP_XREFPOS: u8 = 27;
    /// custom data type id
    pub const NSUP_CUSTDT: u8 = 28;
    /// SEG_GRP: pack_dd encoded list of selectors
    pub const NSUP_GROUPS: u8 = 29;
    /// instructions that initialize call arguments
    pub const NSUP_ARGEAS: u8 = 30;
    /// forced operand 7
    pub const NSUP_FOP7: u8 = 31;
    /// forced operand 8
    pub const NSUP_FOP8: u8 = 32;
    /// complex reference information for operand 7
    pub const NSUP_REF6: u8 = 33;
    /// complex reference information for operand 8
    pub const NSUP_REF7: u8 = 34;
    /// outer complex reference information for operand 7
    pub const NSUP_OREF6: u8 = 35;
    /// outer complex reference information for operand 8
    pub const NSUP_OREF7: u8 = 36;
    /// Extended flags
    pub const NSUP_EX_FLAGS: u8 = 37;

    // values E_PREV..E_NEXT+1000 are reserved (1000..2000..3000 decimal)

    /// SP change points blob (see funcs.cpp).
    /// values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved
    pub const NSUP_POINTS: u32 = 0x1000;

    /// manual instruction.
    /// values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
    pub const NSUP_MANUAL: u32 = 0x2000;

    /// type information.
    /// values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
    pub const NSUP_TYPEINFO: u32 = 0x3000;

    /// register variables.
    /// values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
    pub const NSUP_REGVAR: u32 = 0x4000;

    /// local labels.
    /// values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
    pub const NSUP_LLABEL: u32 = 0x5000;

    /// register argument type/name descriptions
    /// values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved
    pub const NSUP_REGARG: u32 = 0x6000;

    /// function tails or tail referers
    /// values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved
    pub const NSUP_FTAILS: u32 = 0x7000;

    /// graph group information
    /// values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
    pub const NSUP_GROUP: u32 = 0x8000;

    /// operand type information.
    /// values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved
    pub const NSUP_OPTYPES: u32 = 0x9000;

    /// function metadata before lumina information was applied
    /// values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved
    pub const NSUP_ORIGFMD: u32 = 0x109000;

    /// function frame type
    /// values NSUP_FRAME..NSUP_FRAME+0x10000 are reserved
    pub const NSUP_FRAME: u32 = 0x10A000;

    /// Netnode graph tags
    /// Tag values to store graph info
    pub mod gt {
        /// group node info: color, ea, text
        pub const NSUP_GR_INFO: u8 = b'g';
        /// group layout ptrs, hash: md5 of 'belongs'
        pub const NALT_GR_LAYX: u8 = b'p';
        /// group layouts, idx: layout pointer
        pub const NSUP_GR_LAYT: u8 = b'l';
    }
}

/// Patch netnode tag
pub const PATCH_TAG: u8 = b'P';

pub mod indxs {
    // UI desktops
    /// hash indexed by desktop name with dekstop netnode
    pub const IDB_DESKTOPS_NODE_NAME: &str = "$ desktops";
    /// tag to store desktop blob & timestamp
    pub const IDB_DESKTOPS_TAG: u8 = b'S';
    /// desktop timestamp index
    pub const IDB_DESKTOPS_TIMESTAMP: i32 = -1;

    /// node containing address of .got section
    pub const GOTEA_NODE_NAME: &str = "$ got";
    pub const GOTEA_NODE_IDX: u8 = 0;
}

/// Additional flags for the location
/// All 32-bits of the main flags are used up.
/// Additional flags keep more information about addresses.
/// AFLNOTE: DO NOT use these flags directly unless there is absolutely no way.
/// They are too low level and may corrupt the database.
pub mod afl {
    /// has line number info
    pub const AFL_LINNUM: u32 = 0x00000001;
    /// user-defined SP value
    pub const AFL_USERSP: u32 = 0x00000002;
    /// name is public (inter-file linkage)
    pub const AFL_PUBNAM: u32 = 0x00000004;
    /// name is weak
    pub const AFL_WEAKNAM: u32 = 0x00000008;
    /// the item is hidden completely
    pub const AFL_HIDDEN: u32 = 0x00000010;
    /// the instruction/data is specified by the user
    pub const AFL_MANUAL: u32 = 0x00000020;
    /// the code/data border is hidden
    pub const AFL_NOBRD: u32 = 0x00000040;
    /// display struct field name at 0 offset when displaying an offset.
    /// example:
    ///   \v{offset somestruct.field_0}
    /// if this flag is clear, then
    ///   \v{offset somestruct}
    pub const AFL_ZSTROFF: u32 = 0x00000080;
    /// the 1st operand is bitwise negated
    pub const AFL_BNOT0: u32 = 0x00000100;
    /// the 2nd operand is bitwise negated
    pub const AFL_BNOT1: u32 = 0x00000200;
    /// item from the standard library.
    /// low level flag, is used to set
    /// #FUNC_LIB of ::func_t
    pub const AFL_LIB: u32 = 0x00000400;
    /// has typeinfo? (#NSUP_TYPEINFO); used only for addresses, not for member_t
    pub const AFL_TI: u32 = 0x00000800;
    /// has typeinfo for operand 0? (#NSUP_OPTYPES)
    pub const AFL_TI0: u32 = 0x00001000;
    /// has typeinfo for operand 1? (#NSUP_OPTYPES+1)
    pub const AFL_TI1: u32 = 0x00002000;
    /// has local name too (#FF_NAME should be set)
    pub const AFL_LNAME: u32 = 0x00004000;
    /// has type comment? (such a comment may be changed by IDA)
    pub const AFL_TILCMT: u32 = 0x00008000;
    /// toggle leading zeroes for the 1st operand
    pub const AFL_LZERO0: u32 = 0x00010000;
    /// toggle leading zeroes for the 2nd operand
    pub const AFL_LZERO1: u32 = 0x00020000;
    /// has user defined instruction color?
    pub const AFL_COLORED: u32 = 0x00040000;
    /// terse structure variable display?
    pub const AFL_TERSESTR: u32 = 0x00080000;
    /// code: toggle sign of the 1st operand
    pub const AFL_SIGN0: u32 = 0x00100000;
    /// code: toggle sign of the 2nd operand
    pub const AFL_SIGN1: u32 = 0x00200000;
    /// for imported function pointers: doesn't return.
    /// this flag can also be used for any instruction
    /// which halts or finishes the program execution
    pub const AFL_NORET: u32 = 0x00400000;
    /// sp delta value is fixed by analysis.
    /// should not be modified by modules
    pub const AFL_FIXEDSPD: u32 = 0x00800000;
    /// the previous insn was created for alignment purposes only
    pub const AFL_ALIGNFLOW: u32 = 0x01000000;
    /// the type information is definitive.
    /// (comes from the user or type library)
    /// if not set see #AFL_TYPE_GUESSED
    pub const AFL_USERTI: u32 = 0x02000000;
    /// function returns a floating point value
    pub const AFL_RETFP: u32 = 0x04000000;
    /// insn modifes SP and uses the modified value;
    /// example: pop [rsp+N]
    pub const AFL_USEMODSP: u32 = 0x08000000;
    /// autoanalysis should not create code here
    pub const AFL_NOTCODE: u32 = 0x10000000;
    /// autoanalysis should not create proc here
    pub const AFL_NOTPROC: u32 = 0x20000000;
    /// who guessed the type information?
    pub const AFL_TYPE_GUESSED: u32 = 0xC2000000;
    /// the type is guessed by IDA
    pub const AFL_IDA_GUESSED: u32 = 0x00000000;
    /// the function type is guessed by the decompiler
    pub const AFL_HR_GUESSED_FUNC: u32 = 0x40000000;
    /// the data type is guessed by the decompiler
    pub const AFL_HR_GUESSED_DATA: u32 = 0x80000000;
    /// the type is definitely guessed by the decompiler
    pub const AFL_HR_DETERMINED: u32 = 0xC0000000;
}

pub mod array {
    /// use 'dup' construct
    pub const AP_ALLOWDUPS: u32 = 0x00000001;
    /// treats numbers as signed
    pub const AP_SIGNED: u32 = 0x00000002;
    /// display array element indexes as comments
    pub const AP_INDEX: u32 = 0x00000004;
    /// create as array (this flag is not stored in database)
    pub const AP_ARRAY: u32 = 0x00000008;
    /// mask for number base of the indexes
    pub const AP_IDXBASEMASK: u32 = 0x000000F0;
    /// display indexes in decimal
    pub const AP_IDXDEC: u32 = 0x00000000;
    /// display indexes in hex
    pub const AP_IDXHEX: u32 = 0x00000010;
    /// display indexes in octal
    pub const AP_IDXOCT: u32 = 0x00000020;
    /// display indexes in binary
    pub const AP_IDXBIN: u32 = 0x00000030;
}

/// Switch info flags
pub mod swi {
    /// sparse switch (value table present),
    /// otherwise lowcase present
    pub const SWI_SPARSE: u32 = 0x00000001;
    /// 32-bit values in table
    pub const SWI_V32: u32 = 0x00000002;
    /// 32-bit jump offsets
    pub const SWI_J32: u32 = 0x00000004;
    /// value table is split (only for 32-bit values)
    pub const SWI_VSPLIT: u32 = 0x00000008;
    /// user specified switch (starting from version 2)
    pub const SWI_USER: u32 = 0x00000010;
    /// default case is an entry in the jump table.
    /// This flag is applicable in 2 cases:
    ///
    /// * The sparse indirect switch (i.e. a switch with a values table)
    ///
    /// {jump table size} == {value table size} + 1.
    /// The default case entry is the last one in the table
    /// (or the first one in the case of an inversed jump table).
    ///
    /// * The switch with insns in the jump table.
    ///
    /// The default case entry is before the first entry of the table.
    /// See also the find_defjump_from_table() helper function.
    pub const SWI_DEF_IN_TBL: u32 = 0x00000020;
    /// jumptable is inversed. (last entry is for first entry in values table)
    pub const SWI_JMP_INV: u32 = 0x00000040;
    /// use formula (element<<shift) + elbase to find jump targets
    pub const SWI_SHIFT_MASK: u32 = 0x00000180;
    /// elbase is present (otherwise the base of the switch
    /// segment will be used)
    pub const SWI_ELBASE: u32 = 0x00000200;
    /// jump offset expansion bit
    pub const SWI_JSIZE: u32 = 0x00000400;
    /// value table element size expansion bit
    pub const SWI_VSIZE: u32 = 0x00000800;
    /// create an array of individual elements (otherwise separate items)
    pub const SWI_SEPARATE: u32 = 0x00001000;
    /// jump table entries are signed
    pub const SWI_SIGNED: u32 = 0x00002000;
    /// custom jump table.
    pub const SWI_CUSTOM: u32 = 0x00004000;
    /// reserved
    pub const SWI_EXTENDED: u32 = 0x00008000;
    /// value table elements are used as indexes into the jump table
    /// (for sparse switches)
    pub const SWI_INDIRECT: u32 = 0x00010000;
    /// table values are subtracted from the elbase instead of being added
    pub const SWI_SUBTRACT: u32 = 0x00020000;
    /// lowcase value should not be used by the decompiler (internal flag)
    pub const SWI_HXNOLOWCASE: u32 = 0x00040000;
    /// custom jump table with standard table formatting.
    /// ATM IDA doesn't use SWI_CUSTOM for switches with standard
    /// table formatting. So this flag can be considered as obsolete.
    pub const SWI_STDTBL: u32 = 0x00080000;
    /// return in the default case (defjump==BADADDR)
    pub const SWI_DEFRET: u32 = 0x00100000;
    /// jump address is relative to the element not to ELBASE
    pub const SWI_SELFREL: u32 = 0x00200000;
    /// jump table entries are insns. For such entries SHIFT has a
    /// different meaning. It denotes the number of insns in the
    /// entry. For example, 0 - the entry contains the jump to the
    /// case, 1 - the entry contains one insn like a 'mov' and jump
    /// to the end of case, and so on.
    pub const SWI_JMPINSN: u32 = 0x00400000;
    /// the structure contains the VERSION member
    pub const SWI_VERSION: u32 = 0x00800000;
}

/// Reference info flags
pub mod ref_info {
    /// reference type (reftype_t), or custom
    /// reference ID if REFINFO_CUSTOM set
    pub const REFINFO_TYPE: u32 = 0x000F;
    /// based reference (rva);
    /// refinfo_t::base will be forced to get_imagebase();
    /// such a reference is displayed with the \ash{a_rva} keyword
    pub const REFINFO_RVAOFF: u32 = 0x0010;
    /// reference past an item;
    /// it may point to an nonexistent address;
    /// do not destroy alignment dirs
    pub const REFINFO_PASTEND: u32 = 0x0020;
    /// a custom reference.
    /// see custom_refinfo_handler_t.
    /// the id of the custom refinfo is
    /// stored under the REFINFO_TYPE mask.
    pub const REFINFO_CUSTOM: u32 = 0x0040;
    /// don't create the base xref;
    /// implies that the base can be any value.
    /// nb: base xrefs are created only if the offset base
    /// points to the middle of a segment
    pub const REFINFO_NOBASE: u32 = 0x0080;
    /// the reference value is subtracted from the base value instead of (as usual) being added to it
    pub const REFINFO_SUBTRACT: u32 = 0x0100;
    /// the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
    pub const REFINFO_SIGNEDOP: u32 = 0x0200;
    /// an opval of 0 will be considered invalid
    pub const REFINFO_NO_ZEROS: u32 = 0x0400;
    /// an opval of ~0 will be considered invalid
    pub const REFINFO_NO_ONES: u32 = 0x0800;
    /// the self-based reference;
    /// refinfo_t::base will be forced to the reference address
    pub const REFINFO_SELFREF: u32 = 0x1000;
}

/// Rootnode indexes:
pub mod ridx {
    /// file format name for loader modules
    pub const RIDX_FILE_FORMAT_NAME: u32 = 1;
    /// 2..63 are for selector_t blob (see init_selectors())
    pub const RIDX_SELECTORS: u32 = 2;
    /// segment group information (see init_groups())
    pub const RIDX_GROUPS: u32 = 64;
    /// C header path
    pub const RIDX_H_PATH: u32 = 65;
    /// C predefined macros
    pub const RIDX_C_MACROS: u32 = 66;
    /// Instant IDC statements (obsolete)
    pub const RIDX_SMALL_IDC_OLD: u32 = 67;
    /// notepad blob, occupies 1000 indexes (1MB of text)
    pub const RIDX_NOTEPAD: u32 = 68;
    /// assembler include file name
    pub const RIDX_INCLUDE: u32 = 1100;
    /// Instant IDC statements, blob
    pub const RIDX_SMALL_IDC: u32 = 1200;
    /// Graph text representation options
    pub const RIDX_DUALOP_GRAPH: u32 = 1300;
    /// Text text representation options
    pub const RIDX_DUALOP_TEXT: u32 = 1301;
    /// MD5 of the input file
    pub const RIDX_MD5: u32 = 1302;
    /// version of ida which created the database
    pub const RIDX_IDA_VERSION: u32 = 1303;

    /// a list of encodings for the program strings
    pub const RIDX_STR_ENCODINGS: u32 = 1305;
    /// source debug paths, occupies 20 indexes
    pub const RIDX_SRCDBG_PATHS: u32 = 1306;
    /// unused (20 indexes)
    pub const RIDX_DBG_BINPATHS: u32 = 1328;
    /// SHA256 of the input file
    pub const RIDX_SHA256: u32 = 1349;
    /// ABI name (processor specific)
    pub const RIDX_ABINAME: u32 = 1350;
    /// archive file path
    pub const RIDX_ARCHIVE_PATH: u32 = 1351;
    /// problem lists
    pub const RIDX_PROBLEMS: u32 = 1352;
    /// user-closed source files, occupies 20 indexes
    pub const RIDX_SRCDBG_UNDESIRED: u32 = 1353;

    // altvals
    /// initial version of database
    pub const RIDX_ALT_VERSION: i32 = -1;
    /// database creation timestamp
    pub const RIDX_ALT_CTIME: i32 = -2;
    /// seconds database stayed open
    pub const RIDX_ALT_ELAPSED: i32 = -3;
    /// how many times the database is opened
    pub const RIDX_ALT_NOPENS: i32 = -4;
    /// input file crc32
    pub const RIDX_ALT_CRC32: i32 = -5;
    /// image base
    pub const RIDX_ALT_IMAGEBASE: i32 = -6;
    /// ids modnode id (for import_module)
    pub const RIDX_ALT_IDSNODE: i32 = -7;
    /// input file size
    pub const RIDX_ALT_FSIZE: i32 = -8;
    /// output file encoding index
    pub const RIDX_ALT_OUTFILEENC: i32 = -9;
}

pub mod segs {

    pub mod sfl {
        /// IDP dependent field (IBM PC: if set, ORG directive is not commented out)
        pub const SFL_COMORG: u8 = 0x01;
        /// Orgbase is present? (IDP dependent field)
        pub const SFL_OBOK: u8 = 0x02;

        /// \name Segment flag: orgbase
        /// Is the segment hidden?
        pub const SFL_HIDDEN: u8 = 0x04;
        /// Is the segment created for the debugger?.
        /// Such segments are temporary and do not have permanent flags.
        pub const SFL_DEBUG: u8 = 0x08;
        /// Is the segment created by the loader?
        pub const SFL_LOADER: u8 = 0x10;
        /// Hide segment type (do not print it in the listing)
        pub const SFL_HIDETYPE: u8 = 0x20;
        /// Header segment (do not create offsets to it in the disassembly)
        pub const SFL_HEADER: u8 = 0x40;
    }

    /// Segment alignment codes
    pub mod sa {
        /// Absolute segment.
        pub const SA_ABS: u8 = 0;
        /// Relocatable, byte aligned.
        pub const SA_REL_BYTE: u8 = 1;
        /// Relocatable, word (2-byte) aligned.
        pub const SA_REL_WORD: u8 = 2;
        /// Relocatable, paragraph (16-byte) aligned.
        pub const SA_REL_PARA: u8 = 3;
        /// Relocatable, aligned on 256-byte boundary
        pub const SA_REL_PAGE: u8 = 4;
        /// Relocatable, aligned on a double word (4-byte)
        pub const SA_REL_DBLE: u8 = 5;
        /// boundary.
        /// This value is used by the PharLap OMF for page (4K)
        pub const SA_REL4_K: u8 = 6;
        /// alignment. It is not supported by LINK.
        /// Segment group
        pub const SA_GROUP: u8 = 7;
        /// 32 bytes
        pub const SA_REL32_BYTES: u8 = 8;
        /// 64 bytes
        pub const SA_REL64_BYTES: u8 = 9;
        /// 8 bytes
        pub const SA_REL_QWORD: u8 = 10;
        /// 128 bytes
        pub const SA_REL128_BYTES: u8 = 11;
        /// 512 bytes
        pub const SA_REL512_BYTES: u8 = 12;
        /// 1024 bytes
        pub const SA_REL1024_BYTES: u8 = 13;
        /// 2048 bytes
        pub const SA_REL2048_BYTES: u8 = 14;
        pub const SA_REL_MAX_ALIGN_CODE: u8 = SA_REL2048_BYTES;
    }

    /// Segment combination codes
    pub mod sc {
        /// Private. Do not combine with any other program
        /// segment.
        pub const SC_PRIV: u8 = 0;
        /// Segment group
        pub const SC_GROUP: u8 = 1;
        /// Public. Combine by appending at an offset that meets
        /// the alignment requirement.
        pub const SC_PUB: u8 = 2;
        /// As defined by Microsoft, same as C=2 (public).
        pub const SC_PUB2: u8 = 4;
        /// Stack. Combine as for C=2. This combine type forces
        /// byte alignment.
        pub const SC_STACK: u8 = 5;
        /// Common. Combine by overlay using maximum size.
        pub const SC_COMMON: u8 = 6;
        /// As defined by Microsoft, same as C=2 (public).
        pub const SC_PUB3: u8 = 7;
        pub const SC_MAX_COMB_CODE: u8 = SC_PUB3;
    }

    /// Segment types
    pub mod ty {
        /// unknown type, no assumptions
        pub const SEG_NORM: u8 = 0;
        /// * segment with 'extern' definitions.
        ///   no instructions are allowed
        pub const SEG_XTRN: u8 = 1;
        /// code segment
        pub const SEG_CODE: u8 = 2;
        /// data segment
        pub const SEG_DATA: u8 = 3;
        /// java: implementation segment
        pub const SEG_IMP: u8 = 4;
        /// * group of segments
        pub const SEG_GRP: u8 = 6;
        /// zero-length segment
        pub const SEG_NULL: u8 = 7;
        /// undefined segment type (not used)
        pub const SEG_UNDF: u8 = 8;
        /// uninitialized segment
        pub const SEG_BSS: u8 = 9;
        /// * segment with definitions of absolute symbols
        pub const SEG_ABSSYM: u8 = 10;
        /// * segment with communal definitions
        pub const SEG_COMM: u8 = 11;
        /// internal processor memory & sfr (8051)
        pub const SEG_IMEM: u8 = 12;
        /// maximum value segment type can take
        pub const SEG_MAX_SEGTYPE_CODE: u8 = SEG_IMEM;
    }
}

pub mod func {
    /// Function doesn't return
    pub const FUNC_NORET: u16 = 1;
    /// Far function
    pub const FUNC_FAR: u16 = 2;
    /// Library function
    pub const FUNC_LIB: u16 = 4;
    /// Static function
    pub const FUNC_STATICDEF: u16 = 8;
    /// Function uses frame pointer (BP)
    pub const FUNC_FRAME: u16 = 16;
    /// User has specified far-ness of the function
    pub const FUNC_USERFAR: u16 = 32;
    /// A hidden function chunk
    pub const FUNC_HIDDEN: u16 = 64;
    /// Thunk (jump) function
    pub const FUNC_THUNK: u16 = 128;
    /// BP points to the bottom of the stack frame
    pub const FUNC_BOTTOMBP: u16 = 256;
    /// Function 'non-return' analysis must be performed. This flag is verified
    /// upon func_does_return()
    pub const FUNC_NORET_PENDING: u16 = 512;
    /// SP-analysis has been performed.
    pub const FUNC_SP_READY: u16 = 1024;
    /// Function changes SP in untraceable way, eg: `and esp, 0FFFFFFF0h`
    pub const FUNC_FUZZY_SP: u16 = 2048;
    /// Prolog analysis has been performed by last SP-analysis
    pub const FUNC_PROLOG_OK: u16 = 4096;
    /// 'argsize' field has been validated. If this bit is clear and 'argsize'
    /// is 0, then we do not known the real number of bytes removed from
    /// the stack. This bit is handled by the processor module.
    pub const FUNC_PURGED_OK: u16 = 16384;
    /// This is a function tail. Other bits must be clear (except #FUNC_HIDDEN).
    pub const FUNC_TAIL: u16 = 32768;
    /// Function info is provided by Lumina.
    pub const FUNC_LUMINA: u32 = 65536;
    /// Outlined code, not a real function.
    pub const FUNC_OUTLINE: u32 = 131072;
    /// Function frame changed, request to reanalyze the function after the last
    /// insn is analyzed.
    pub const FUNC_REANALYZE: u32 = 262144;
    /// function is an exception unwind handler
    pub const FUNC_UNWIND: u32 = 524288;
    /// function is an exception catch handler
    pub const FUNC_CATCH: u32 = 1048576;
}
