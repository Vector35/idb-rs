/// Flags structure
/// Here we define the organization of ::flags64_t values.
/// Low 8 bits contain value of corresponding byte of the program.
/// The next bit is set if the byte is initialized.
pub mod byte {
    /// Mask for byte value
    pub const MS_VAL: u32 = 0x000000FF;
    /// Byte has value ?
    pub const FF_IVL: u32 = 0x00000100;
}

pub mod flags {
    pub mod byte_type {
        /// Mask for typing
        pub const MS_CLS: u32 = 0x00000600;
        /// Code ?
        pub const FF_CODE: u32 = 0x00000600;
        /// Data ?
        pub const FF_DATA: u32 = 0x00000400;
        /// Tail ?
        pub const FF_TAIL: u32 = 0x00000200;
        /// Unknown ?
        pub const FF_UNK: u32 = 0x00000000;
    }

    /// specific state information
    /// Flags keep information common to all four states of bytes.
    /// This information will not be automatically discarded during
    /// transitions between different states.
    pub mod byte_info {
        /// Mask of common bits
        pub const MS_COMM: u32 = 0x000FF800;
        /// Has comment ?
        pub const FF_COMM: u32 = 0x00000800;
        /// has references
        pub const FF_REF: u32 = 0x00001000;
        /// Has next or prev lines ?
        pub const FF_LINE: u32 = 0x00002000;
        /// Has name ?
        pub const FF_NAME: u32 = 0x00004000;
        /// Has dummy name?
        pub const FF_LABL: u32 = 0x00008000;
        /// Exec flow from prev instruction
        pub const FF_FLOW: u32 = 0x00010000;
        /// Inverted sign of operands
        pub const FF_SIGN: u32 = 0x00020000;
        /// Bitwise negation of operands
        pub const FF_BNOT: u32 = 0x00040000;
        /// unused bit (was used for variable bytes)
        pub const FF_UNUSED: u32 = 0x00080000;
    }

    /// Instruction/Data operands
    /// Represent instruction/data operands.
    ///
    /// IDA keeps bitmask representations for a maximum of 8 operands:
    ///
    /// For data bytes, only the first bitmask is used (i.e. all elements of
    /// an array have the same type).
    pub mod inst_info {
        /// Mask for nth arg (a 64-bit constant)
        pub const MS_N_TYPE: u8 = 0xf;
        /// Void (unknown)?
        pub const FF_N_VOID: u8 = 0x0;
        /// Hexadecimal number?
        pub const FF_N_NUMH: u8 = 0x1;
        /// Decimal number?
        pub const FF_N_NUMD: u8 = 0x2;
        /// Char ('x')?
        pub const FF_N_CHAR: u8 = 0x3;
        /// Segment?
        pub const FF_N_SEG: u8 = 0x4;
        /// Offset?
        pub const FF_N_OFF: u8 = 0x5;
        /// Binary number?
        pub const FF_N_NUMB: u8 = 0x6;
        /// Octal number?
        pub const FF_N_NUMO: u8 = 0x7;
        /// Enumeration?
        pub const FF_N_ENUM: u8 = 0x8;
        /// Forced operand?
        pub const FF_N_FOP: u8 = 0x9;
        /// Struct offset?
        pub const FF_N_STRO: u8 = 0xA;
        /// Stack variable?
        pub const FF_N_STK: u8 = 0xB;
        /// Floating point number?
        pub const FF_N_FLT: u8 = 0xC;
        /// Custom representation?
        pub const FF_N_CUST: u8 = 0xD;
    }

    /// data bytes
    pub mod data_info {
        /// Mask for DATA typing
        pub const DT_TYPE: u32 = 0xF0000000;

        /// byte
        pub const FF_BYTE: u32 = 0x00000000;
        /// word
        pub const FF_WORD: u32 = 0x10000000;
        /// double word
        pub const FF_DWORD: u32 = 0x20000000;
        /// quadro word
        pub const FF_QWORD: u32 = 0x30000000;
        /// tbyte
        pub const FF_TBYTE: u32 = 0x40000000;
        /// string literal
        pub const FF_STRLIT: u32 = 0x50000000;
        /// struct variable
        pub const FF_STRUCT: u32 = 0x60000000;
        /// octaword/xmm word (16 bytes/128 bits)
        pub const FF_OWORD: u32 = 0x70000000;
        /// float
        pub const FF_FLOAT: u32 = 0x80000000;
        /// double
        pub const FF_DOUBLE: u32 = 0x90000000;
        /// packed decimal real
        pub const FF_PACKREAL: u32 = 0xA0000000;
        /// alignment directive
        pub const FF_ALIGN: u32 = 0xB0000000;
        /// reserved
        pub const FF_RESERVED: u32 = 0xC0000000;
        /// custom data type
        pub const FF_CUSTOM: u32 = 0xD0000000;
        /// ymm word (32 bytes/256 bits)
        pub const FF_YWORD: u32 = 0xE0000000;
        /// zmm word (64 bytes/512 bits)
        pub const FF_ZWORD: u32 = 0xF0000000;
    }

    /// code bytes
    pub mod code_info {
        /// Mask for code bits
        pub const MS_CODE: u32 = 0xF0000000;
        /// function start?
        pub const FF_FUNC: u32 = 0x10000000;
        /// not used
        pub const FF_RESERVED: u32 = 0x20000000;
        /// Has Immediate value ?
        pub const FF_IMMD: u32 = 0x40000000;
        /// Has jump table or switch_info?
        pub const FF_JUMP: u32 = 0x80000000;
    }
}
