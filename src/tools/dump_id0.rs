use std::borrow::Cow;

use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::{ID0Section, Id0Section};
use idb_rs::IdbKind;

pub fn dump_id0(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        Id0Section::U32(id0) => dump(id0),
        Id0Section::U64(id0) => dump(id0),
    }
}

fn dump<K: IdbKind>(id0: ID0Section<K>) -> Result<()> {
    for entry in id0.all_entries() {
        let key = id0_to_str(&entry.key);
        let value = id0_to_str(&entry.value);
        println!("\"{key}\":\"{value}\"");
    }
    Ok(())
}

fn id0_to_str(input: &[u8]) -> Cow<str> {
    // ignore any \x00 at the end
    let striped = input.strip_suffix(b"\x00").unwrap_or(input);
    let is_string = striped.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    if is_string {
        let result = String::from_utf8_lossy(striped);
        // we will print this around `"`, so scape that
        result.replace('\\', "\\\\").replace('"', "\\\"").into()
    } else {
        use std::fmt::Write;
        let mut output = String::with_capacity(input.len() * 4);
        for c in input {
            write!(&mut output, "\\x{:02x}", *c).unwrap();
        }
        output.into()
    }
}
