use crate::{get_id0_id1_id2_sections, Args, Id0Id1Id2Variant};

use anyhow::Result;

use idb_rs::addr_info::all_address_info;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_addr_info(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_id1_id2_sections(args)? {
        IDAVariants::IDA32(kind) => dump_inner(kind),
        IDAVariants::IDA64(kind) => dump_inner(kind),
    }
}

fn dump_inner<K: IDAKind>((id0, id1, id2): Id0Id1Id2Variant<K>) -> Result<()> {
    // TODO create a function for that in ida_info
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let image_base = root_info.netdelta();
    let mut buf = String::new();
    for (addr_info, _len) in
        all_address_info(&id0, &id1, id2.as_ref(), image_base)
    {
        use std::fmt::Write;
        buf.clear();
        let addr = addr_info.address();
        if let Some(label) = addr_info.label()? {
            write!(&mut buf, " Label: {label:?}")?;
        }
        if let Some(comment) = addr_info.comment() {
            write!(&mut buf, " Comment: {comment:?}")?;
        }
        if let Some(comment) = addr_info.comment_repeatable() {
            write!(&mut buf, " Comment Repeatable: {comment:?}")?;
        }
        if let Some(comments) = addr_info.comment_pre() {
            comments.enumerate().try_for_each(|(i, comment)| {
                write!(&mut buf, " Comment Pre + {i}: {comment:?}")
            })?;
        }
        if let Some(comments) = addr_info.comment_post() {
            comments.enumerate().try_for_each(|(i, comment)| {
                write!(&mut buf, " Comment Post + {i}: {comment:?}")
            })?;
        }
        if let Some(tinfo) = addr_info.tinfo()? {
            write!(&mut buf, " Tinfo: {tinfo:?}",)?;
        }
        if !buf.is_empty() {
            println!("{:#010x?}:{buf}", addr.into_raw());
        }
    }

    Ok(())
}
