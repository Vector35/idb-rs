use crate::{get_id0_section, Args};

use anyhow::{anyhow, Result};

use idb_rs::id0::segment_register::SrareasIdx;
use idb_rs::id0::{ID0Section, RootInfo, SegmentIdx};
use idb_rs::{Address, IDAKind, IDAUsize, IDAVariants};

pub fn dump_cpu_arch(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let srarea_idx = id0.srareas_idx()?;
    let segment_idx = id0.segments_idx()?;

    let funcs_idx = id0.funcs_idx()?;
    if let Some(funcs_idx) = funcs_idx {
        for idbfunction in id0.fchunks(funcs_idx) {
            let idbfunction = idbfunction?;
            let cpu = architecture_from_ida(
                &id0,
                srarea_idx,
                segment_idx,
                &root_info,
                idbfunction.address.start,
            )?;
            println!(
                "{:08x}..{:08x}: {cpu}",
                idbfunction.address.start.into_raw(),
                idbfunction.address.end.into_raw(),
            );
        }
    }

    Ok(())
}

fn read_true_false_regs<K: IDAKind>(
    id0: &ID0Section<K>,
    addr: Address<K>,
    srarea_idx: Option<SrareasIdx<K>>,
    segment_idx: Option<SegmentIdx<K>>,
    segreg_idx: usize,
) -> Result<bool> {
    // default into false for the thumb value?
    let segreg_raw = srarea_idx
        .zip(segment_idx)
        .map(|(srarea_idx, segment_idx)| {
            id0.segment_register_value(
                addr,
                srarea_idx,
                segment_idx,
                segreg_idx,
            )
        })
        .transpose()?
        .flatten();
    match segreg_raw.map(<K::Usize as IDAUsize>::into_u64) {
        None | Some(0) => Ok(false),
        Some(1) => Ok(true),
        Some(2..) => Err(anyhow!("Invalid segment register value")),
    }
}

fn architecture_from_ida<K: IDAKind>(
    id0: &ID0Section<K>,
    srarea_idx: Option<SrareasIdx<K>>,
    segment_idx: Option<SegmentIdx<K>>,
    root_info: &RootInfo<K>,
    addr: Address<K>,
) -> Result<String> {
    let Some(proc) = id0.processor(root_info) else {
        return Ok("NOCPU".into());
    };
    use idb_rs::processors::*;

    let is_big_endian = root_info.lflags.is_big_endian();
    let lflags_32 = root_info.lflags.is_program_32b_or_bigger();
    let lflags_64 = root_info.lflags.is_program_64b();
    let bits = match (lflags_32, lflags_64) {
        (true, true) => 64,
        (true, false) => 32,
        (false, false) => 16,
        (false, true) => {
            panic!("The lflags have the 32b_or_greater unset and 64 set")
        }
    };
    let mut output = format!(
        "{proc:?} {bits} {}",
        if is_big_endian { "Be" } else { "Le" }
    );

    // aarch64
    match proc {
        Processor::Arm(_arm) => {
            let is_thumb = read_true_false_regs(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(ArmReg::T) - ArmReg::SEGMENT_REGISTERS_START,
            )?;
            if is_thumb {
                output.push_str(" Thumb2");
            }
            Ok(output)
        }
        Processor::Mips(_mips) => {
            // the mips16 pseudoregister is used to switch between standard MIPS and MIPS16 or microMIPS
            let is_mips16 = read_true_false_regs(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(MipsReg::Mips16) - MipsReg::SEGMENT_REGISTERS_START,
            )?;
            if is_mips16 {
                output.push_str(" Mips16");
            }
            Ok(output)
        }
        Processor::Ppc(_ppc) => {
            // PPC, vle is used to enable decoding of VLE instructions
            let is_vle = read_true_false_regs(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(PpcReg::Vle) - PpcReg::SEGMENT_REGISTERS_START,
            )?;
            if is_vle {
                output.push_str(" VLE");
            }
            Ok(output)
        }
        Processor::Msp430(_)
        | Processor::Riscv(_)
        | Processor::Pc(_)
        | Processor::Tricore(_)
        | Processor::Script(_)
        | Processor::M740(_)
        | Processor::Ia(_)
        | Processor::M7900(_)
        | Processor::Avr(_)
        | Processor::Alpha(_)
        | Processor::Nec850(_)
        | Processor::Sparc(_)
        | Processor::Arc(_)
        | Processor::Fr(_)
        | Processor::Tms320C3(_)
        | Processor::M65816(_)
        | Processor::F2Mc(_)
        | Processor::Rl78(_)
        | Processor::Proc78K0(_)
        | Processor::Dsp56K(_)
        | Processor::M65(_)
        | Processor::Kr1878(_)
        | Processor::S390(_)
        | Processor::Sam8(_)
        | Processor::C166(_)
        | Processor::Dalvik(_)
        | Processor::Mc68K(_)
        | Processor::Tms320C1(_)
        | Processor::Spc700(_)
        | Processor::I196(_)
        | Processor::Mc6812(_)
        | Processor::I960(_)
        | Processor::M16C(_)
        | Processor::Pdp11(_)
        | Processor::Tms320C6(_)
        | Processor::M32R(_)
        | Processor::Java(_)
        | Processor::Mc6816(_)
        | Processor::Z80(_)
        | Processor::Cli(_)
        | Processor::Hppa(_)
        | Processor::H8(_)
        | Processor::Oakdsp(_)
        | Processor::Xtensa(_)
        | Processor::Pic16(_)
        | Processor::H8500(_)
        | Processor::Tms32028(_)
        | Processor::Proc78K0S(_)
        | Processor::Tms320C5(_)
        | Processor::Z8(_)
        | Processor::Mc8(_)
        | Processor::M7700(_)
        | Processor::Tms32054(_)
        | Processor::Unsp(_)
        | Processor::Rx(_)
        | Processor::Wasm(_)
        | Processor::Sh3(_)
        | Processor::St7(_)
        | Processor::Ad218X(_)
        | Processor::St9(_)
        | Processor::Tms32055(_)
        | Processor::Pic(_)
        | Processor::I860(_)
        | Processor::St20(_)
        | Processor::I51(_)
        | Processor::Xa(_)
        | Processor::Ebc(_)
        | Processor::Spu(_) => Ok(output),
    }
}
