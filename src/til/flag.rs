/// byte sequence used to describe a type in IDA
type TypeT = u8;
/// Enum type flags
type BteT = u8;
/// Til Type flags
type TilT = u16;
/// TypeAtt Type flags
type TattrT = u16;
type CmT = u16;

/// multi-use
pub const RESERVED_BYTE: TypeT = 0xFF;

/// Masks
pub mod tf_mask {
    use super::TypeT;
    /// the low 4 bits define the basic type
    pub const TYPE_BASE_MASK: TypeT = 0x0F;
    /// type flags - they have different meaning depending on the basic type
    pub const TYPE_FLAGS_MASK: TypeT = 0x30;
    /// modifiers.
    /// for [super::tf_array::BT_ARRAY] see [super::tf_array]
    /// ::BT_VOID can have them ONLY in 'void *'
    pub const TYPE_MODIF_MASK: TypeT = 0xC0;
    /// basic type with type flags
    pub const TYPE_FULL_MASK: TypeT = TYPE_BASE_MASK | TYPE_FLAGS_MASK;
}

/// Basic type: unknown & void
///  [tf_unk::BT_UNK] and [tf_unk::BT_VOID] with non-zero type flags can be used in function
///  (and struct) declarations to describe the function arguments or structure
///  fields if only their size is known. They may be used in ida to describe
///  the user input.
///
///  In general BT_... bits should not be used alone to describe types.
///  Use BTF_... constants instead.
///
///  For struct used also as 'single-field-alignment-suffix'
///  [__declspec(align(x))] with [tf_mask::TYPE_MODIF_MASK] == [tf_mask::TYPE_FULL_MASK]
pub mod tf_unk {
    use super::TypeT;
    /// unknown
    pub const BT_UNK: TypeT = 0x00;
    /// void
    pub const BT_VOID: TypeT = 0x01;
    /// [BT_VOID] - normal void; [BT_UNK] - don't use
    pub const BTMT_SIZE0: TypeT = 0x00;
    /// size = 1 byte  if [BT_VOID]; 2 if [BT_UNK]
    pub const BTMT_SIZE12: TypeT = 0x10;
    /// size = 4 bytes if [BT_VOID]; 8 if [BT_UNK]
    pub const BTMT_SIZE48: TypeT = 0x20;
    /// size = 16 bytes if [BT_VOID]; unknown if [BT_UNK] (IN struct alignment - see below)
    pub const BTMT_SIZE128: TypeT = 0x30;
}

/// Basic type: integer
pub mod tf_int {
    use super::TypeT;
    /// __int8
    pub const BT_INT8: TypeT = 0x02;
    /// __int16
    pub const BT_INT16: TypeT = 0x03;
    /// __int32
    pub const BT_INT32: TypeT = 0x04;
    /// __int64
    pub const BT_INT64: TypeT = 0x05;
    /// __int128 (for alpha & future use)
    pub const BT_INT128: TypeT = 0x06;
    /// natural int. (size provided by idp module)
    pub const BT_INT: TypeT = 0x07;
    /// unknown signedness
    pub const BTMT_UNKSIGN: TypeT = 0x00;
    /// signed
    pub const BTMT_SIGNED: TypeT = 0x10;
    /// unsigned
    pub const BTMT_UNSIGNED: TypeT = 0x20;
    /// specify char or segment register
    /// - [BT_INT8]         - char
    /// - [BT_INT]          - segment register
    /// - other [BT_INT]...   - don't use
    pub const BTMT_CHAR: TypeT = 0x30;
}

/// Basic type: bool
pub mod tf_bool {
    use super::TypeT;
    /// bool
    pub const BT_BOOL: TypeT = 0x08;
    /// bool size is model specific or unknown(?)
    pub const BTMT_DEFBOOL: TypeT = 0x00;
    /// bool sized 1byte
    pub const BTMT_BOOL1: TypeT = 0x10;
    /// bool sized 2bytes - !inf_is_64bit()
    pub const BTMT_BOOL2: TypeT = 0x20;
    /// bool sized 8bytes - inf_is_64bit()
    pub const BTMT_BOOL8: TypeT = 0x20;
    /// bool sized 4bytes
    pub const BTMT_BOOL4: TypeT = 0x30;
}

/// Basic type: float
pub mod tf_float {
    use super::TypeT;
    /// float
    pub const BT_FLOAT: TypeT = 0x09;
    /// float (4 bytes)
    pub const BTMT_FLOAT: TypeT = 0x00;
    /// double (8 bytes)
    pub const BTMT_DOUBLE: TypeT = 0x10;
    /// long double (compiler specific)
    pub const BTMT_LNGDBL: TypeT = 0x20;
    /// float (variable size). `if { use_tbyte } then { tbyte_size } else { 2 }`,
    pub const BTMT_SPECFLT: TypeT = 0x30;
}

/// Basic type: last
pub mod tf_last_basic {
    /// the last basic type, all basic types may be followed by `tah-typeattrs`
    pub const BT_LAST_BASIC: super::TypeT = super::tf_float::BT_FLOAT;
}

/// Derived type: pointer
/// Pointers to undeclared yet [tf_complex::BT_COMPLEX] types are prohibited
pub mod tf_ptr {
    use super::TypeT;
    /// pointer
    /// has the following format:
    /// `[db sizeof(ptr)]; [tah-typeattrs]; type_t...`
    pub const BT_PTR: TypeT = 0x0A;
    /// default for model
    pub const BTMT_DEFPTR: TypeT = 0x00;
    /// near
    pub const BTMT_NEAR: TypeT = 0x10;
    /// far
    pub const BTMT_FAR: TypeT = 0x20;
    /// closure
    /// - if ptr to [super::tf_func::BT_FUNC] - __closure.
    ///   in this case next byte MUST be
    ///   [super::RESERVED_BYTE], and after it [super::tf_func::BT_FUNC]
    /// - else the next byte contains `size_of::<ptr>()`
    ///   allowed values are 1 - `ph,processor_t,max_ptr_size`
    /// - if value is bigger than `ph,processor_t,max_ptr_size`,
    ///   `based_ptr_name_and_size()` is called to find out the typeinfo
    pub const BTMT_CLOSURE: TypeT = 0x30;
}

/// Derived type: array
/// For [tf_array::BT_ARRAY], the BTMT_... flags must be equivalent to the BTMT_... flags of its elements
pub mod tf_array {
    use super::TypeT;
    /// array
    pub const BT_ARRAY: TypeT = 0x0B;

    /// code
    /// ```custom,text
    /// if set
    ///    array base==0
    ///    format: dt num_elem; [tah-typeattrs]; type_t...
    ///    if num_elem==0 then the array size is unknown
    /// else
    ///    format: da num_elem, base; [tah-typeattrs]; type_t... \endcode
    /// ```
    /// used only for serialization
    pub const BTMT_NONBASED: TypeT = 0x10;
    /// reserved bit
    pub const BTMT_ARRESERV: TypeT = 0x20;
}

/// Function attribute byte
/// Zero attribute byte is forbidden.
///
/// Ellipsis is not taken into account in the number of parameters//
/// The return type cannot be ::BT_ARRAY or ::BT_FUNC.
pub mod tf_func {
    use super::{CmT, TypeT};
    /// function.
    /// format:
    ///  optional:
    /// ```custom,text
    ///   ::CM_CC_SPOILED | num_of_spoiled_regs
    ///   if num_of_spoiled_reg == BFA_FUNC_MARKER:
    ///     ::bfa_byte
    ///     if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0
    ///      ::fti_bits (only low bits: FTI_SPOILED,...,FTI_VIRTUAL)
    ///      num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
    ///     else
    ///       bfa_byte is function attribute byte (see \ref BFA_...)
    ///   else:
    ///     num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
    /// ```
    ///  ::cm_t ... calling convention and memory model
    ///  [tah-typeattrs];
    ///  ::type_t ... return type;
    ///  [serialized argloc_t of returned value (if ::CM_CC_SPECIAL{PE} && !return void);
    /// ```custom,text
    ///  if !::CM_CC_VOIDARG:
    ///    dt N (N=number of parameters)
    ///    if ( N == 0 )
    ///    if ::CM_CC_ELLIPSIS or ::CM_CC_SPECIALE
    ///        func(...)
    ///      else
    ///        parameters are unknown
    ///    else
    ///      N records:
    ///        ::type_t ... (i.e. type of each parameter)
    ///        [serialized argloc_t (if ::CM_CC_SPECIAL{PE})] (i.e. place of each parameter)
    ///        [#FAH_BYTE + de( \ref funcarg_t::flags )] </pre>
    /// ```
    pub const BT_FUNC: TypeT = 0x0C;

    ///< call method - default for model or unknown
    pub const BTMT_DEFCALL: TypeT = 0x00;
    ///< function returns by retn
    pub const BTMT_NEARCALL: TypeT = 0x10;
    ///< function returns by retf
    pub const BTMT_FARCALL: TypeT = 0x20;
    ///< function returns by iret
    ///< in this case cc MUST be 'unknown'
    pub const BTMT_INTCALL: TypeT = 0x30;
    /// __noreturn
    pub const BFA_NORET: TypeT = 0x01;

    /// __pure
    pub const BFA_PURE: TypeT = 0x02;

    /// high level prototype (with possibly hidden args)
    pub const BFA_HIGH: TypeT = 0x04;
    /// static
    pub const BFA_STATIC: TypeT = 0x08;

    /// virtual
    pub const BFA_VIRTUAL: TypeT = 0x10;

    /// This is NOT a cc! (used internally as a marker)
    pub const BFA_FUNC_MARKER: CmT = 0x0F;
    /// This is NOT a real attribute (used internally as marker for extended format)
    pub const BFA_FUNC_EXT_FORMAT: TypeT = 0x80;

    /// Argument location types
    pub mod argloc {
        use super::TypeT;
        /// None
        pub const ALOC_NONE: TypeT = 0;
        /// stack offset
        pub const ALOC_STACK: TypeT = 1;
        /// distributed (scattered)
        pub const ALOC_DIST: TypeT = 2;
        /// one register (and offset within it)
        pub const ALOC_REG1: TypeT = 3;
        /// register pair
        pub const ALOC_REG2: TypeT = 4;
        /// register relative
        pub const ALOC_RREL: TypeT = 5;
        /// global address
        pub const ALOC_STATIC: TypeT = 6;
        /// custom argloc (7 or higher)
        pub const ALOC_CUSTOM: TypeT = 7;
    }
}

/// Derived type: complex
pub mod tf_complex {
    use super::TypeT;
    /// struct/union/enum/typedef.
    /// format:
    /// ```custom,text
    ///   [dt N (N=field count) if !::BTMT_TYPEDEF]
    ///   if N == 0:
    ///     p_string name (unnamed types have names "anon_...")
    ///     [sdacl-typeattrs];
    ///   else, for struct & union:
    ///     if N == 0x7FFE   // Support for high (i.e., > 4095) members count
    ///       N = deserialize_de()
    ///     ALPOW = N & 0x7
    ///     MCNT = N >> 3
    ///     if MCNT == 0
    ///       empty struct
    ///     if ALPOW == 0
    ///       ALIGN = get_default_align()
    ///     else
    ///       ALIGN = (1 << (ALPOW - 1))
    ///     [sdacl-typeattrs];
    ///   else, for enums:
    ///     if N == 0x7FFE   // Support for high enum entries count.
    ///       N = deserialize_de()
    ///     [tah-typeattrs]; </pre>
    /// ```
    pub const BT_COMPLEX: TypeT = 0x0D;
    /// struct
    /// `MCNT records: type_t; [sdacl-typeattrs];`
    pub const BTMT_STRUCT: TypeT = 0x00;
    /// union
    /// `MCNT records: type_t...`
    pub const BTMT_UNION: TypeT = 0x10;
    /// enum
    /// ```custom,text
    ///   next byte bte_t (see below)
    ///   N records: de delta(s)
    ///              OR
    ///              blocks (see below)
    /// ```
    pub const BTMT_ENUM: TypeT = 0x20;
    /// named reference
    /// `always p_string name`
    pub const BTMT_TYPEDEF: TypeT = 0x30;
    /// bitfield (only in struct)
    /// ```custom,text
    /// ['bitmasked' enum see below]
    /// next byte is dt
    ///  ((size in bits << 1) | (unsigned ? 1 : 0))
    /// ```
    pub const BT_BITFIELD: TypeT = 0x0E;
    /// __int8
    pub const BTMT_BFLDI8: TypeT = 0x00;
    /// __int16
    pub const BTMT_BFLDI16: TypeT = 0x10;
    /// __int32
    pub const BTMT_BFLDI32: TypeT = 0x20;
    /// __int64
    pub const BTMT_BFLDI64: TypeT = 0x30;
}

/// RESERVED
pub const BT_RESERVED: TypeT = 0x0F;

/// Type modifiers
/// "pub const volatile" types are forbidden
pub mod tf_modifiers {
    use super::TypeT;
    /// const
    pub const BTM_CONST: TypeT = 0x40;
    /// volatile
    pub const BTM_VOLATILE: TypeT = 0x80;
}

/// Special enum definitions
pub mod tf_enum {
    use super::BteT;
    /// storage size.
    ///   - if == 0 then inf_get_cc_size_e()
    ///   - else 1 << (n -1) = 1,2,4...64
    pub const BTE_SIZE_MASK: BteT = 0x07;
    /// must be 0, in order to distinguish from a tah-byte
    pub const BTE_RESERVED: BteT = 0x08;
    /// 'subarrays'. In this case ANY record
    /// has the following format:
    ///   - 'de' mask (has name)
    ///   - 'dt' cnt
    ///   - cnt records of 'de' values
    ///      (cnt CAN be 0)
    ///
    /// NOTE: delta for ALL subsegment is ONE
    pub const BTE_BITFIELD: BteT = 0x10;
    /// output style mask
    pub const BTE_OUT_MASK: BteT = 0x60;
    /// hex
    pub const BTE_HEX: BteT = 0x00;
    /// char or hex
    pub const BTE_CHAR: BteT = 0x20;
    /// signed decimal
    pub const BTE_SDEC: BteT = 0x40;
    /// unsigned decimal
    pub const BTE_UDEC: BteT = 0x60;
    /// this bit MUST be present
    pub const BTE_ALWAYS: BteT = 0x80;
}

/// Convenience definitions: segment register
pub mod tf_conv_segreg {
    use super::{tf_int, TypeT};
    /// segment register
    pub const BT_SEGREG: TypeT = tf_int::BT_INT | tf_int::BTMT_CHAR;
}

/// Convenience definitions: unknown types
pub mod tf_conv_unk {
    use super::{tf_unk, TypeT};
    /// 1 byte
    pub const BT_UNK_BYTE: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE12;
    /// 2 bytes
    pub const BT_UNK_WORD: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE12;
    /// 4 bytes
    pub const BT_UNK_DWORD: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE48;
    /// 8 bytes
    pub const BT_UNK_QWORD: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE48;
    /// 16 bytes
    pub const BT_UNK_OWORD: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE128;
    /// unknown size - for parameters
    pub const BT_UNKNOWN: TypeT = tf_unk::BT_UNK | tf_unk::BTMT_SIZE128;
}

/// Convenience definitions: shortcuts
pub mod tf_shortcuts {
    use super::{tf_bool, tf_complex, tf_conv_unk, tf_float, tf_int, tf_unk, TypeT};
    /// byte
    pub const BTF_BYTE: TypeT = tf_conv_unk::BT_UNK_BYTE;
    /// unknown
    pub const BTF_UNK: TypeT = tf_conv_unk::BT_UNKNOWN;
    /// void
    pub const BTF_VOID: TypeT = tf_unk::BT_VOID | tf_unk::BTMT_SIZE0;

    /// signed byte
    pub const BTF_INT8: TypeT = tf_int::BT_INT8 | tf_int::BTMT_SIGNED;
    /// signed char
    pub const BTF_CHAR: TypeT = tf_int::BT_INT8 | tf_int::BTMT_CHAR;
    /// unsigned char
    pub const BTF_UCHAR: TypeT = tf_int::BT_INT8 | tf_int::BTMT_UNSIGNED;
    /// unsigned byte
    pub const BTF_UINT8: TypeT = tf_int::BT_INT8 | tf_int::BTMT_UNSIGNED;

    /// signed short
    pub const BTF_INT16: TypeT = tf_int::BT_INT16 | tf_int::BTMT_SIGNED;
    /// unsigned short
    pub const BTF_UINT16: TypeT = tf_int::BT_INT16 | tf_int::BTMT_UNSIGNED;

    /// signed int
    pub const BTF_INT32: TypeT = tf_int::BT_INT32 | tf_int::BTMT_SIGNED;
    /// unsigned int
    pub const BTF_UINT32: TypeT = tf_int::BT_INT32 | tf_int::BTMT_UNSIGNED;

    /// signed long
    pub const BTF_INT64: TypeT = tf_int::BT_INT64 | tf_int::BTMT_SIGNED;
    /// unsigned long
    pub const BTF_UINT64: TypeT = tf_int::BT_INT64 | tf_int::BTMT_UNSIGNED;

    /// signed 128-bit value
    pub const BTF_INT128: TypeT = tf_int::BT_INT128 | tf_int::BTMT_SIGNED;
    /// unsigned 128-bit value
    pub const BTF_UINT128: TypeT = tf_int::BT_INT128 | tf_int::BTMT_UNSIGNED;

    /// int, unknown signedness
    pub const BTF_INT: TypeT = tf_int::BT_INT | tf_int::BTMT_UNKSIGN;
    /// unsigned int
    pub const BTF_UINT: TypeT = tf_int::BT_INT | tf_int::BTMT_UNSIGNED;
    /// singed int
    pub const BTF_SINT: TypeT = tf_int::BT_INT | tf_int::BTMT_SIGNED;

    /// boolean
    pub const BTF_BOOL: TypeT = tf_bool::BT_BOOL;

    /// float
    pub const BTF_FLOAT: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_FLOAT;
    /// double
    pub const BTF_DOUBLE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_DOUBLE;
    /// long double
    pub const BTF_LDOUBLE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_LNGDBL;
    /// see [tf_float::BTMT_SPECFLT]
    pub const BTF_TBYTE: TypeT = tf_float::BT_FLOAT | tf_float::BTMT_SPECFLT;

    /// struct
    pub const BTF_STRUCT: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_STRUCT;
    /// union
    pub const BTF_UNION: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_UNION;
    /// enum
    pub const BTF_ENUM: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_ENUM;
    /// typedef
    pub const BTF_TYPEDEF: TypeT = tf_complex::BT_COMPLEX | tf_complex::BTMT_TYPEDEF;
}

/// Type attributes
///
/// The type attributes start with the type attribute header byte (::TAH_BYTE),
/// followed by attribute bytes
pub mod tattr {
    use super::TattrT;
    /// type attribute header byte
    pub const TAH_BYTE: TattrT = 0xFE;
    /// function argument attribute header byte
    pub const FAH_BYTE: TattrT = 0xFF;

    pub const MAX_DECL_ALIGN: TattrT = 0x000F;

    /// all defined bits
    pub const TAH_ALL: TattrT = 0x03F0;
}

/// Extended type attributes
pub mod tattr_ext {
    use super::TattrT;
    /// has extended attributes
    pub const TAH_HASATTRS: TattrT = 0x0010;
}

/// Type attributes for udts
pub mod tattr_udt {
    use super::TattrT;
    /// struct: unaligned struct
    pub const TAUDT_UNALIGNED: TattrT = 0x0040;
    /// struct: gcc msstruct attribute
    pub const TAUDT_MSSTRUCT: TattrT = 0x0020;
    /// struct: a c++ object, not simple pod type
    pub const TAUDT_CPPOBJ: TattrT = 0x0080;
    /// struct: is virtual function table
    pub const TAUDT_VFTABLE: TattrT = 0x0100;
}

/// Type attributes for udt fields
pub mod tattr_field {
    use super::TattrT;
    /// field: do not include but inherit from the current field
    pub const TAFLD_BASECLASS: TattrT = 0x0020;
    /// field: unaligned field
    pub const TAFLD_UNALIGNED: TattrT = 0x0040;
    /// field: virtual base (not supported yet)
    pub const TAFLD_VIRTBASE: TattrT = 0x0080;
    /// field: ptr to virtual function table
    pub const TAFLD_VFTABLE: TattrT = 0x0100;
    /// denotes a udt member function
    pub const TAFLD_METHOD: TattrT = 0x0200;
}

/// Type attributes for pointers
pub mod tattr_ptr {
    use super::TattrT;
    /// ptr: __ptr32
    pub const TAPTR_PTR32: TattrT = 0x0020;
    /// ptr: __ptr64
    pub const TAPTR_PTR64: TattrT = 0x0040;
    /// ptr: __restrict
    pub const TAPTR_RESTRICT: TattrT = 0x0060;
    /// ptr: __shifted(parent_struct, delta)
    pub const TAPTR_SHIFTED: TattrT = 0x0080;
}

/// Type attributes for enums
pub mod tattr_enum {
    use super::TattrT;
    /// enum: store 64-bit values
    pub const TAENUM_64BIT: TattrT = 0x0020;
    /// enum: unsigned
    pub const TAENUM_UNSIGNED: TattrT = 0x0040;
    /// enum: signed
    pub const TAENUM_SIGNED: TattrT = 0x0080;
}

/// Type info library property bits
pub mod til {
    use super::TilT;
    /// pack buckets using zip
    pub const TIL_ZIP: TilT = 0x0001;
    /// til has macro table
    pub const TIL_MAC: TilT = 0x0002;
    /// extended sizeof info (short, long, longlong)
    pub const TIL_ESI: TilT = 0x0004;
    /// universal til for any compiler
    pub const TIL_UNI: TilT = 0x0008;
    /// type ordinal numbers are present
    pub const TIL_ORD: TilT = 0x0010;
    /// type aliases are present (this bit is used only on the disk)
    pub const TIL_ALI: TilT = 0x0020;
    /// til has been modified, should be saved
    pub const TIL_MOD: TilT = 0x0040;
    /// til has extra streams
    pub const TIL_STM: TilT = 0x0080;
    /// sizeof(long double)
    pub const TIL_SLD: TilT = 0x0100;
}

/// Calling convention & Model
pub mod cm {
    use super::CmT;
    /// Default pointer size
    pub mod cm_ptr {
        use super::CmT;
        pub const CM_MASK: CmT = 0x03;
        /// unknown
        pub const CM_UNKNOWN: CmT = 0x00;

        /// if sizeof(int)<=2: near 1 byte, far 2 bytes
        pub const CM_N8_F16: CmT = 0x01;

        /// if sizeof(int)>2: near 8 bytes, far 8 bytes
        pub const CM_N64: CmT = 0x01;

        /// near 2 bytes, far 4 bytes
        pub const CM_N16_F32: CmT = 0x02;

        /// near 4 bytes, far 6 bytes
        pub const CM_N32_F48: CmT = 0x03;
    }
    /// Model
    pub mod m {
        use super::CmT;
        pub const CM_M_MASK: CmT = 0x0C;
        /// small:   code=near, data=near (or unknown if CM_UNKNOWN)
        pub const CM_M_NN: CmT = 0x00;
        /// large:   code=far, data=far
        pub const CM_M_FF: CmT = 0x04;

        /// compact: code=near, data=far
        pub const CM_M_NF: CmT = 0x08;

        /// medium:  code=far, data=near
        pub const CM_M_FN: CmT = 0x0C;
    }

    /// Calling convention
    pub mod cc {
        use super::CmT;
        pub const CM_CC_MASK: CmT = 0xF0;
        /// this value is invalid
        pub const CM_CC_INVALID: CmT = 0x00;

        /// unknown calling convention
        pub const CM_CC_UNKNOWN: CmT = 0x10;

        /// function without arguments
        /// if has other cc and argnum == 0,
        /// represent as f() - unknown list
        pub const CM_CC_VOIDARG: CmT = 0x20;

        /// stack
        pub const CM_CC_CDECL: CmT = 0x30;

        /// cdecl + ellipsis
        pub const CM_CC_ELLIPSIS: CmT = 0x40;

        /// stack, purged
        pub const CM_CC_STDCALL: CmT = 0x50;

        /// stack, purged, reverse order of args
        pub const CM_CC_PASCAL: CmT = 0x60;

        /// stack, purged (x86), first args are in regs (compiler-dependent)
        pub const CM_CC_FASTCALL: CmT = 0x70;
        /// stack, purged (x86), first arg is in reg (compiler-dependent)
        pub const CM_CC_THISCALL: CmT = 0x80;
        /// (Swift) arguments and return values in registers (compiler-dependent)
        pub const CM_CC_SWIFT: CmT = 0x90;
        /// This is NOT a cc! Mark of __spoil record
        /// the low nibble is count and after n {spoilreg_t}
        /// present real cm_t byte. if n == BFA_FUNC_MARKER,
        /// the next byte is the function attribute byte.
        pub const CM_CC_SPOILED: CmT = 0xA0;

        /// (Go) arguments and return value in stack
        pub const CM_CC_GOLANG: CmT = 0xB0;

        pub const CM_CC_RESERVE3: CmT = 0xC0;
        /// ::CM_CC_SPECIAL with ellipsis
        pub const CM_CC_SPECIALE: CmT = 0xD0;

        /// Equal to ::CM_CC_SPECIAL, but with purged stack
        pub const CM_CC_SPECIALP: CmT = 0xE0;

        /// usercall: locations of all arguments
        /// and the return value are explicitly specified
        pub const CM_CC_SPECIAL: CmT = 0xF0;
    }

    /// Standard C-language models for x86
    pub mod pc {
        use super::cm_ptr::*;
        use super::m::*;
        use crate::til::flag::CmT;

        pub const C_PC_TINY: CmT = CM_N16_F32 | CM_M_NN;
        pub const C_PC_SMALL: CmT = CM_N16_F32 | CM_M_NN;
        pub const C_PC_COMPACT: CmT = CM_N16_F32 | CM_M_NF;
        pub const C_PC_MEDIUM: CmT = CM_N16_F32 | CM_M_FN;
        pub const C_PC_LARGE: CmT = CM_N16_F32 | CM_M_FF;
        pub const C_PC_HUGE: CmT = CM_N16_F32 | CM_M_FF;
        pub const C_PC_FLAT: CmT = CM_N32_F48 | CM_M_NN;
    }
}
