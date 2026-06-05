use crate::{get_id0_id1_id2_sections, get_til_section, Args, Id0Id1Id2Variant};

use anyhow::Result;

use idb_rs::addr_info::all_address_info;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_addr_info(args: &Args) -> Result<()> {
    let til = get_til_section(args).ok();
    // parse the id0 sector/file
    match get_id0_id1_id2_sections(args)? {
        IDAVariants::IDA32(kind) => dump_inner(kind, til.as_ref()),
        IDAVariants::IDA64(kind) => dump_inner(kind, til.as_ref()),
    }
}

fn dump_inner<K: IDAKind>(
    (id0, id1, id2): Id0Id1Id2Variant<K>,
    til: Option<&idb_rs::til::section::TILSection>,
) -> Result<()> {
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
        if let Some(tinfo) = addr_info.tinfo(&root_info)? {
            write!(&mut buf, " Tinfo: {tinfo:?}",)?;
        }
        for operand in 0u8..2 {
            if let Some(id) = addr_info.op_enum(operand) {
                let name = addr_info.op_enum_name(operand);
                let enum_ty = til.and_then(|t| addr_info.op_enum_type(operand, t));
                write!(
                    &mut buf,
                    " OpEnum[{operand}]: tid={id:#x} member={:?} enum_type={:?}",
                    name.as_ref().map(|n| n.as_utf8_lossy()),
                    enum_ty.map(|t| t.name.as_utf8_lossy())
                )?;
            }
        }
        if !buf.is_empty() {
            println!("{:#010x?}:{buf}", addr.into_raw());
        }
    }

    Ok(())
}
