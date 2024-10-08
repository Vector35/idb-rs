use anyhow::{anyhow, Result};

use crate::til;

use super::parse_maybe_cstr;

#[derive(Clone, Debug)]
pub enum AddressInfo<'a> {
    Comment(Comments<'a>),
    Label(&'a str),
    TilType(til::Type),
    Other { key: &'a [u8], value: &'a [u8] },
}

impl<'a> AddressInfo<'a> {
    pub(crate) fn parse(key: &'a [u8], value: &'a [u8], is_64: bool) -> Result<Self> {
        let [sub_type, id @ ..] = key else {
            return Err(anyhow!("Missing SubType"));
        };
        let id_value = if is_64 {
            <[u8; 8]>::try_from(id).ok().map(u64::from_be_bytes)
        } else {
            <[u8; 4]>::try_from(id)
                .ok()
                .map(u32::from_be_bytes)
                .map(u64::from)
        };
        // Non UTF-8 comment: "C:\\Documents and Settings\\Administrator\\\xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9\ls"
        // \xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9 = "바탕 화면" = "Desktop" in Korean encoded using Extended Unix Code
        #[allow(clippy::wildcard_in_or_patterns)]
        match (sub_type, id_value) {
            // Comments
            // NOTE
            // pre comments start at index 1000
            // post comments start at index 2000
            // if you create more then a 1000 pre/post comments ida start acting strange, BUG?
            (b'S', Some(1000..=1999)) => Ok(Self::Comment(Comments::PreComment(parse_maybe_cstr(
                value,
            ).ok_or_else(|| anyhow!("Pre-Comment is not valid CStr"))?))),
            (b'S', Some(2000..=2999)) => Ok(Self::Comment(Comments::PostComment(parse_maybe_cstr(
                value,
            ).ok_or_else(|| anyhow!("Post-Comment is not valid CStr"))?))),
            (b'S', Some(0x0)) => Ok(Self::Comment(Comments::Comment(parse_maybe_cstr(
                value,
            ).ok_or_else(|| anyhow!("Comment is not valid CStr"))?))),
            // Repeatable comment
            (b'S', Some(0x1)) => Ok(Self::Comment(Comments::RepeatableComment(parse_maybe_cstr(
                value,
            ).ok_or_else(|| anyhow!("Repeatable Comment is not valid CStr"))?))),

            // Type at this address
            (b'S', Some(0x3000)) => Ok(Self::TilType(til::Type::new_from_id0(value)?)),
            // TODO followed by (b'S', Some(0x3001)) data with unknown meaning

            // Name, aka a label to this memory address
            (b'N', None) => {
                let label_raw = parse_maybe_cstr(value).ok_or_else(|| anyhow!("Label is not a valid CStr"))?;
                let label = core::str::from_utf8(label_raw).map_err(|_| anyhow!("Label is not valid UTF-8"))?;
                Ok(Self::Label(label))
            },

            // Seems related to datatype, maybe cstr, align and stuff like that
            (b'A', Some(_)) |
            // Know to happen to data that represent an memory location
            (b'S', Some(0x09)) |
            // Seem defined on procedures
            (b'S', Some(0x1000)) |
            // seems to be a code reference to memory, key is the destination memory
            (b'x', Some(_)) |
            // The oposite of 'x', memory being referenced by an instruction
            (b'X', Some(_)) |
            // Seems to represent a XREF, key being the location that points to this address
            (b'D', Some(_)) |
            // The oposite of 'D", is a memory location that points to other
            (b'd', Some(_)) |
            // other unknown values
            _ => Ok(Self::Other { key, value }),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Comments<'a> {
    Comment(&'a [u8]),
    RepeatableComment(&'a [u8]),
    PreComment(&'a [u8]),
    PostComment(&'a [u8]),
}

impl<'a> Comments<'a> {
    /// The message on the comment, NOTE that IDA don't have a default character encoding
    pub fn message(&self) -> &'a [u8] {
        match self {
            Comments::Comment(x)
            | Comments::RepeatableComment(x)
            | Comments::PreComment(x)
            | Comments::PostComment(x) => x,
        }
    }
}
