use crate::{get_id1_section, Args};

use idb_rs::id1::{ByteOp, ByteType};

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

        print_char_if_bool!(byte_info.has_comment(), 'C');
        print_char_if_bool!(byte_info.has_comment_ext(), 'Ĉ');
        print_char_if_bool!(byte_info.has_reference(), 'R');
        print_char_if_bool!(byte_info.has_name(), 'N');
        print_char_if_bool!(byte_info.has_dummy_name(), 'Ñ');
        print_char_if_bool!(byte_info.exec_flow_from_prev_inst(), 'X');
        print_char_if_bool!(byte_info.op_invert_sig(), 'S');
        print_char_if_bool!(byte_info.op_bitwise_negation(), 'B');
        print_char_if_bool!(byte_info.is_unused_set(), 'U');

        print!("| ");
        let byte_type = byte_info.byte_type();
        fn print_op(op: Option<ByteOp>, n: u8) {
            if let Some(op) = op {
                print!("OP{n}({op:?}) ");
            }
        }
        match byte_type {
            ByteType::Data(data) => {
                print!("D ");
                print_op(data.operand0()?, 0);
            }
            ByteType::Code(code) => {
                print!("C ");
                print_char_if_bool!(code.is_func_start(), 'F');
                print_char_if_bool!(code.has_func_reserved_set(), 'R');
                print_char_if_bool!(code.has_immediate_value(), 'I');
                print_char_if_bool!(code.has_jump_table(), 'J');
                print_op(code.operand0()?, 0);
                print_op(code.operand0()?, 1);
            }
            ByteType::Tail(_) => print!("T "),
            ByteType::Unknown => print!("U "),
        }

        println!();
    }
    Ok(())
}
