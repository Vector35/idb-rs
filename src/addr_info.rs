use crate::bytes_info::BytesInfo;
use crate::id0::entry_iter::EntryTagContinuousSubkeys;
use crate::id0::flag::nalt::x::NALT_DREF_FROM;
use crate::id0::flag::nalt::{NALT_ENUM0, NALT_ENUM1, NALT_STRTYPE};
use crate::id0::flag::netnode::nn_res::{ARRAY_ALT_TAG, ARRAY_SUP_TAG};
use crate::id0::flag::nsup::NSUP_TYPEINFO;
use crate::id0::{
    get_sup_from_key, parse_maybe_cstr, ID0CStr, ID0Section, Netdelta,
    NetnodeIdx, RootInfo,
};
use crate::id1::{ByteDataType, ByteInfo, ByteType, ID1Section};
use crate::id2::ID2Section;
use crate::til::r#enum::EnumMembers;
use crate::til::section::TILSection;
use crate::til::{TILTypeInfo, Type, TypeVariant};
use crate::{Address, IDAKind, IDAUsize, IDBStr, IDBString};

use anyhow::{anyhow, Result};

pub struct AddressInfo<'a, K: IDAKind> {
    id0: &'a ID0Section<K>,
    address: Address<K>,
    netdelta: Netdelta<K>,
    byte_info: ByteInfo,
}

impl<'a, K: IDAKind> AddressInfo<'a, K> {
    pub fn new(
        id0: &'a ID0Section<K>,
        id1: &ID1Section<K>,
        id2: Option<&ID2Section<K>>,
        netdelta: Netdelta<K>,
        address: Address<K>,
    ) -> Option<Self> {
        let byte_info =
            BytesInfo::new(Some(id1), id2).byte_by_address(address)?;
        Some(Self {
            id0,
            address,
            netdelta,
            byte_info,
        })
    }

    /// this ignores the byte mapping from id1/id2, some entries, specialy for
    /// labels, need this because they are outside the mapped address.
    pub fn new_forced(
        id0: &'a ID0Section<K>,
        netdelta: Netdelta<K>,
        address: Address<K>,
    ) -> Option<Self> {
        Some(Self {
            id0,
            netdelta,
            address,
            // TODO how to handle flags?
            byte_info: ByteInfo::from_raw(
                crate::id1::flag::flags::byte_info::FF_NAME,
            ),
        })
    }

    pub fn netnode(&self) -> NetnodeIdx<K> {
        self.netdelta.ea2node(self.address)
    }

    pub fn address(&self) -> Address<K> {
        self.address
    }

    pub fn byte_info(&self) -> ByteInfo {
        self.byte_info
    }

    // TODO what happens if a comment is created, then a multi-byte type is
    // created in such a way that the comment is in the middle of the type?
    // the function `get_cmt` search for the next non-tail entry in id1,
    // maybe that's for compatibility reasons, but maybe the `has_comment`
    // flag should be ignored in tail id1 entries
    pub fn comment(&self) -> Option<IDBStr<'a>> {
        self.id0.comment_at(self.netnode())
    }

    pub fn comment_repeatable(&self) -> Option<IDBStr<'a>> {
        if !self.byte_info.has_comment() {
            return None;
        }
        self.id0.comment_repeatable_at(self.netnode())
    }

    pub fn comment_pre(&self) -> Option<impl Iterator<Item = IDBStr<'a>>> {
        if !self.byte_info.has_comment_ext() {
            return None;
        }
        Some(self.id0.comment_pre_at(self.netnode()))
    }

    pub fn comment_post(&self) -> Option<impl Iterator<Item = IDBStr<'a>>> {
        if !self.byte_info.has_comment_ext() {
            return None;
        }
        Some(self.id0.comment_post_at(self.netnode()))
    }

    pub fn label(&self) -> Result<Option<IDBString>> {
        if !self.byte_info.has_name() {
            if !self.byte_info.has_dummy_name() {
                return Ok(None);
            }
            // TODO a dummy name is returned here depending on the context
            // eg sub_XXXXX
            // known formats: "sub" "loc" "unk" "off" "seg" "xmmword" "algn"
            // "ymmword" "zmmword" "custdata" "dbl" "packreal" "flt" "qword"
            // "asc" "stru" "tbyte" "word" "dword" "byte"
            Ok(None)
        } else {
            let Some(name_raw) = self.id0.netnode_name(self.netnode()) else {
                return Ok(None);
            };
            let value = ID0CStr::<'_, K>::parse_cstr_or_subkey(name_raw)
                .ok_or_else(|| {
                    anyhow!("Label is not a valid CStr or ID0 Ref")
                })?;
            match value {
                ID0CStr::CStr(label) => Ok(Some(label.to_idb_string())),
                ID0CStr::Ref(label_ref) => {
                    let entries = self.id0.address_info_value(label_ref)?;
                    let label: Vec<u8> = entries
                        .iter()
                        .flat_map(|x| &x.value[..])
                        .copied()
                        .collect();
                    Ok(Some(IDBString::new(label)))
                }
            }
        }
    }

    /// The enumeration referenced by an operand displayed as an enum, if any.
    ///
    /// Reads the `NALT_ENUM0`/`NALT_ENUM1` altval (see `get_enum_id` / `op_enum` in `bytes.hpp`)
    /// for operand 0 or 1, returning the referenced enumeration's id. Returns `None` when the
    /// operand is not displayed as an enum (or for operands other than 0/1).
    pub fn op_enum(&self, operand: u8) -> Option<u64> {
        self.op_enum_netnode(operand)
            .map(|node| node.into_raw().into_u64())
    }

    /// The enumeration referenced by an operand, as the netnode (tid) it points at.
    fn op_enum_netnode(&self, operand: u8) -> Option<NetnodeIdx<K>> {
        let index = match operand {
            0 => NALT_ENUM0,
            1 => NALT_ENUM1,
            _ => return None,
        };
        self.id0
            .altval(self.netnode(), index.into(), ARRAY_ALT_TAG)
            .ok()
            .flatten()
    }

    /// The symbolic name an enum operand resolves to (an enumeration member, or the enumeration
    /// itself), recovered from the referenced tid's netnode name.
    ///
    /// The tid is itself a netnode; its `N` name holds the symbolic constant / type name. This
    /// works whether the enumeration lives in a type library or the local types.
    pub fn op_enum_name(&self, operand: u8) -> Option<IDBString> {
        let node = self.op_enum_netnode(operand)?;
        self.id0
            .netnode_type_name(node)
            .map(|name| IDBString::new(name.to_vec()))
    }

    /// The enumeration type an operand is displayed against.
    ///
    /// An enum operand's tid identifies a specific enumeration member, whose netnode sits right
    /// after the enumeration's own netnode (members are allocated at `enum_tid + 1 ..=
    /// enum_tid + member_count`). This resolves the member tid back to the enumeration in `til`
    /// by that tid range, so it returns the exact enumeration regardless of any member-name
    /// collisions, working for enumerations in a type library or the local types.
    pub fn op_enum_type<'t>(
        &self,
        operand: u8,
        til: &'t TILSection,
    ) -> Option<&'t TILTypeInfo> {
        let member_tid = self.op_enum(operand)?;
        for ty in &til.types {
            let TypeVariant::Enum(en) = &ty.tinfo.type_variant else {
                continue;
            };
            let member_count = match &en.members {
                EnumMembers::Regular(members) => members.len(),
                EnumMembers::Groups(groups) => {
                    groups.iter().map(|g| g.sub_fields.len()).sum()
                }
            } as u64;
            // The enumeration's netnode is named with IDA's `$$ ` type-name prefix.
            let enum_name = format!("$$ {}", ty.name.as_utf8_lossy());
            let Some(enum_tid) = self
                .id0
                .netnode_idx_by_name(&enum_name)
                .ok()
                .flatten()
                .map(|node| node.into_raw().into_u64())
            else {
                continue;
            };
            if member_tid > enum_tid && member_tid <= enum_tid + member_count {
                return Some(ty);
            }
        }
        None
    }

    /// The string literal type IDA assigned to this address, if any.
    ///
    /// Decodes the `NALT_STRTYPE` altval (see `get_str_type` in `nalt.hpp`). Returns `None` for
    /// addresses that are not string literals.
    pub fn str_type(&self) -> Option<StrType> {
        let raw = self.id0.sup_value(
            self.netnode(),
            NALT_STRTYPE.into(),
            ARRAY_ALT_TAG,
        )?;
        Some(StrType::from_code(*raw.first()?))
    }

    pub fn tinfo(&self, info: &RootInfo<K>) -> Result<Option<Type>> {
        // allow if it's a struct type or a function definition
        match self.byte_info.byte_type() {
            ByteType::Data(byte_data) => {
                if byte_data.data_type() != ByteDataType::Struct {
                    return Ok(None);
                }
            }
            ByteType::Code(byte_code) => {
                if !byte_code.is_func_start() {
                    return Ok(None);
                }
            }
            ByteType::Tail(_) => return Ok(None),
            ByteType::Unknown => return Ok(None),
        }

        // take the field names and the continuation (optional!)
        let mut iter = EntryTagContinuousSubkeys::new(
            self.id0,
            self.netnode(),
            ARRAY_SUP_TAG,
            NSUP_TYPEINFO.into(),
        )
        .take(0x1000);
        let Some(first_entry) = iter.next() else {
            return Ok(None);
        };
        let mut til_raw: Vec<u8> = first_entry.value.to_vec();

        // convert the value into fields
        // usually this string ends with \x00, but maybe there is no garanty for that.
        // TODO what if there is more fields that can fit a id0 entry
        let field_names = if let Some(fields_entry) = iter.next() {
            let value = parse_maybe_cstr(&fields_entry.value);
            crate::ida_reader::split_strings_from_array(value)
                .ok_or_else(|| anyhow!("Invalid Fields for TIL Type"))?
        } else {
            // no fields
            // TODO what if the type requires a continuation but it have no
            // fields, does it just skip 0x3001? If so can't use
            // EntryTagContinuousSubkeys above
            vec![vec![]]
        };

        // condensate the data continuation into a single buffer
        til_raw.extend(iter.flat_map(|e| &e.value[..]));

        // create the raw type
        let til = Type::new_from_id0(info, &til_raw, field_names)?;
        Ok(Some(til))
    }

    // TODO make a index type
    // Used to defined what struct is apply at the address
    pub fn tinfo_ref(
        &self,
    ) -> impl Iterator<Item = Result<SubtypeId<K>>> + use<'_, K> {
        let range = self
            .id0
            .netnode_tag_range_idx(self.netnode(), NALT_DREF_FROM);
        self.id0.entries[range]
            .iter()
            .filter(|e| e.value[..] == [0x03])
            .map(|e| {
                get_sup_from_key::<K>(&e.key)
                    .map(SubtypeId)
                    .ok_or_else(|| anyhow!("Invalid tinfo_ref index value"))
            })
    }
}

pub fn all_address_info<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    id1: &ID1Section<K>,
    id2: Option<&ID2Section<K>>,
    netdelta: Netdelta<K>,
) -> Vec<(AddressInfo<'a, K>, usize)> {
    BytesInfo::new(Some(id1), id2)
        .all_bytes_no_tails()
        .into_iter()
        .filter(|(_a, b, _len)| {
            // InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4b3370
            b.has_name()
                || b.has_comment()
                || b.has_comment_ext()
                || !matches!(
                    b.byte_type(),
                    ByteType::Tail(_) | ByteType::Unknown
                )
        })
        .map(move |(address, byte_info, len)| {
            let addr_info = AddressInfo {
                id0,
                address,
                netdelta,
                byte_info,
            };
            (addr_info, len)
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct SubtypeId<K: IDAKind>(pub(crate) K::Usize);

/// The character width of a string literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrWidth {
    /// One byte per character (C / ASCII / UTF-8).
    Byte,
    /// Two bytes per character (UTF-16).
    Word,
    /// Four bytes per character (UTF-32).
    Dword,
}

/// The in-memory layout of a string literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrLayout {
    /// Terminated by a zero character (C string).
    TerminatedChar,
    /// Length prefixed by a single byte (Pascal).
    Pascal1,
    /// Length prefixed by two bytes.
    Pascal2,
    /// Length prefixed by four bytes.
    Pascal4,
}

/// The type of a string literal IDA defined at an address, decoded from `strtype`.
///
/// See `get_str_type` / `NALT_STRTYPE` in the IDA SDK (`nalt.hpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrType {
    pub width: StrWidth,
    pub layout: StrLayout,
}

impl StrType {
    /// Decode the low (type code) byte of an IDA `strtype` value.
    pub fn from_code(code: u8) -> Self {
        // InnerRef: nalt.hpp STRWIDTH_MASK / STRLYT_MASK / STRLYT_SHIFT.
        let width = match code & 0x03 {
            1 => StrWidth::Word,
            2 => StrWidth::Dword,
            // 0, and the reserved 3, are treated as single byte.
            _ => StrWidth::Byte,
        };
        let layout = match (code & 0xFC) >> 2 {
            1 => StrLayout::Pascal1,
            2 => StrLayout::Pascal2,
            3 => StrLayout::Pascal4,
            // 0 (and any unexpected value) is a zero-terminated string.
            _ => StrLayout::TerminatedChar,
        };
        Self { width, layout }
    }
}
