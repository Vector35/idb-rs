use crate::{get_id1_section, Args};

use idb_rs::id1::ByteInfo;
use idb_rs::id1::ByteType;

use anyhow::Result;

macro_rules! print_char_if_bool {
    ($cond:expr, $value:literal) => {
        print!("{} ", if $cond { $value } else { ' ' });
    };
}

pub fn dump_id1(args: &Args) -> Result<()> {
    // parse the id1 sector/file
    let id1 = get_id1_section(args)?;

    for (address, byte_info) in id1.all_bytes() {
        print!("{address:08X}: {:#010X} ", byte_info.as_raw());

        let ByteInfo {
            byte_value: _,
            has_comment,
            has_reference,
            has_comment_ext,
            has_name,
            has_dummy_name,
            exec_flow_from_prev_inst,
            op_invert_sig,
            op_bitwise_negation,
            is_unused_set,
            byte_type,
        } = byte_info.decode().unwrap();
        print_char_if_bool!(has_comment, 'C');
        print_char_if_bool!(has_comment_ext, 'Ĉ');
        print_char_if_bool!(has_reference, 'R');
        print_char_if_bool!(has_name, 'N');
        print_char_if_bool!(has_dummy_name, 'Ñ');
        print_char_if_bool!(exec_flow_from_prev_inst, 'X');
        print_char_if_bool!(op_invert_sig, 'S');
        print_char_if_bool!(op_bitwise_negation, 'B');
        print_char_if_bool!(is_unused_set, 'U');

        print!("| ");
        match byte_type {
            ByteType::Data(data) => {
                print!("D ");
                print!("{data:?} ");
            }
            ByteType::Code(_code) => print!("C "),
            ByteType::Tail => print!("T "),
            ByteType::Unknown => print!("U "),
        }

        println!();
    }
    Ok(())
}
