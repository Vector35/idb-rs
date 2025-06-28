use anyhow::{anyhow, Result};
use num_traits::AsPrimitive;
use serde::{Deserialize, Serialize};

use crate::ida_reader::IdbReadKind;
use crate::{id0::*, Address};
use crate::{IDAKind, IDAUsize};
impl<K: IDAKind> RootInfo<K> {
    pub fn read_v2(
        input: &mut impl IdbReadKind<K>,
        _input_len: usize,
        _upgrade_700: u64,
        version: u16,
    ) -> Result<RootInfo<K>> {
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x6f2d40
        let default_root_info = RootInfoV2Raw::<K>::default();
        let mut data = bincode::serialize(&default_root_info)?;
        debug_assert_eq!(data.len(), size_of::<RootInfoV2Raw<K>>());
        // TODO check the data is read and no interrupt happen?
        let mut read_data =
            vec![b'I', b'D', b'A', version as u8, (version >> 8) as u8];
        input.read_to_end(&mut read_data)?;
        if read_data.len() > data.len() {
            return Err(anyhow!("Invalid size of RootInfo V2"));
        }
        data[..read_data.len()].copy_from_slice(&read_data[..]);
        if read_data.len() <= size_of::<RootInfoV2Raw<K>>() - 8 {
            data.copy_within(
                5 + 8..5 + 8 + (size_of::<RootInfoV2Raw<K>>() - 29),
                0x15,
            );
            data[5 + 8..5 + 8 + 8].iter_mut().for_each(|b| *b = 0);
        } else {
            data[5 + 15] = 0;
        }

        let mut data: RootInfoV2Raw<K> = bincode::deserialize(&data[..])?;
        migrate_version(&mut data, version)?;

        let genflags = migrate_genflags(&data);
        let lflags = migrate_lflags(&data, genflags);
        let af1 = migrate_af1(&data);
        let outflag = migrate_outflag(&data);

        let mut processor = data.cpu_name.to_vec();
        // remove any \x00 that marks the end of the str
        let cpu_str_part = parse_maybe_cstr(&processor[..])
            .ok_or_else(|| anyhow!("Invalid RootInfo CStr cpu name"))?;
        processor.truncate(cpu_str_part.len());

        let mut strlit_name_prefix = data.strlit_name_prefix.to_vec();
        // remove any \x00 that marks the end of the str
        let strlit_name_prefix_part = parse_maybe_cstr(&processor[..])
            .ok_or_else(|| anyhow!("Invalid RootInfo CStr cpu name"))?;
        strlit_name_prefix.truncate(strlit_name_prefix_part.len());

        let is_cc_guessed = data.cc_id_raw & 0x80 != 0;
        let cc_id = Compiler::try_from(data.cc_id_raw & 0x7F)
            .unwrap_or(Compiler::Unknown);

        Ok(RootInfo {
            version,
            target: RootInfoTarget {
                processor,
                assembler: data.target_assembler,
            },
            genflags: Inffl::new(genflags).unwrap(),
            lflags: Lflg::new(lflags).unwrap(),
            database_change_count: data.database_change_count,
            input: RootInfoInput {
                file_format: FileType::from_value(data.input_file_format)?,
                operating_system: data.input_operating_system,
                application_type: data.input_application_type,
            },
            special_segment_entry_size: data.special_segment_entry_size,
            af: Af::new(af1, 3).unwrap(),
            addresses: RootInfoAddressed {
                loading_base: data.addresses_loading_base,
                initial_ss: data.addresses_initial_ss,
                initial_cs: data.addresses_initial_cs,
                initial_ip: data.addresses_initial_ip,
                initial_ea: Address::from_raw(data.addresses_initial_ea),
                initial_sp: data.addresses_initial_sp,
                main_ea: Address::from_raw(data.addresses_main_ea),
                min_ea: Address::from_raw(data.addresses_min_ea),
                max_ea: Address::from_raw(data.addresses_max_ea),
                original_min_ea: Address::from_raw(
                    data.addresses_original_min_ea,
                ),
                original_max_ea: Address::from_raw(
                    data.addresses_original_max_ea,
                ),
                privrange: Address::from_raw(data.addresses_privrange_start_ea)
                    ..Address::from_raw(data.addresses_privrange_end_ea),
                netdelta: data.addresses_netdelta,
            },
            suspiciousness_limits: RootInfoSuspiciousnessLimits {
                low: (!data.suspiciousness_limits_low.is_max())
                    .then(|| Address::from_raw(data.suspiciousness_limits_low)),
                high: (!data.suspiciousness_limits_high.is_max()).then(|| {
                    Address::from_raw(data.suspiciousness_limits_high)
                }),
            },
            xrefs: RootInfoXrefs {
                max_depth: data.xrefs_max_depth,
                max_displayed_xrefs: data.xrefs_max_displayed_xrefs,
                max_displayed_type_xrefs: data.xrefs_max_displayed_type_xrefs,
                max_displayed_strlit_xrefs: data
                    .xrefs_max_displayed_strlit_xrefs,
                xrefflag: XRef::new(data.xrefs_xrefflag).unwrap(),
            },
            names: RootInfoNames {
                max_autogenerated_name_length: data
                    .names_max_autogenerated_name_length,
                dummy_names: NameType::new(data.names_dummy_names).ok_or_else(
                    || anyhow!("Invalid RootInfo V2 Dummy Names"),
                )?,
            },
            demangler: RootInfoDemangler {
                short_form: data.demangler_short_demnames,
                long_form: data.demangler_long_demnames,
                name: DemName::new(data.demangler_name).unwrap(),
            },
            listname: ListName::new(data.listnames).unwrap(),
            indent: data.indent,
            cmt_ident: data.cmt_ident,
            margin: data.margin,
            listing: RootInfoListing {
                xref_margin: data.listing_xref_margin,
            },
            outflag: OutputFlags::new(outflag).unwrap(),
            cmtflg: CommentOptions::new(data.cmtflg),
            limiter: DelimiterOptions::new(data.limiter).unwrap(),
            bin_prefix_size: data.bin_prefix_size,
            prefflag: LinePrefixOptions::new(data.prefflag).unwrap(),
            strlits: RootInfoStrlits {
                flags: StrLiteralFlags::new(data.strlit_flags).unwrap(),
                break_: data.strlit_break,
                leading_zeroes: data.strlit_leading_zeroes,
                name_prefix: strlit_name_prefix,
                serial_number: data.strlit_serial_number,
            },
            strtype: data.strtype,
            data_carousel: data.data_carousel,
            compiler: RootInfoCompiler {
                is_guessed: is_cc_guessed,
                compiler: cc_id,
                sizeof: RootInfoCompilerSizeof {
                    cm: data.cc_cm,
                    int: data.cc_size_i,
                    bool: data.cc_size_b,
                    enum_: data.cc_size_e,
                    short: data.cc_size_s,
                    long: data.cc_size_l,
                    longlong: data.cc_size_ll,
                    long_double: data.cc_size_ldbl,
                },
                alignment: data.cc_defalign,
            },
            abibits: AbiOptions::new(data.abibits).unwrap(),
            appcall_options: data.appcall_options,
        })
    }
}

fn migrate_version<K: IDAKind>(
    data: &mut RootInfoV2Raw<K>,
    version: u16,
) -> Result<()> {
    match version {
        #[cfg(not(feature = "restrictive"))]
        0..16 => version_16(data),
        16 => version_16(data),

        17 => version_17(data),
        18 => version_18(data),
        19 => version_19(data),
        20 => version_20(data),
        21 => version_21(data),
        22 => version_22(data),
        23 => version_23(data),
        24 => version_24(data),
        25 => version_25(data),
        26 => version_26(data),
        27 => version_27(data),
        28 => version_28(data),
        29 => version_29(data),
        30 => version_30(data),
        31 => version_31(data),
        32 => version_32(data),
        33 => version_33(data),
        34 => version_34(data),
        35 => version_35(data),
        36 => version_36(data),
        37 => version_37(data),
        38 => version_38(data),
        39 => version_39(data),
        40 => version_40(data),
        41 => version_41(data),
        42 => version_42(data),
        43 => version_43(data),
        44 => version_44(data),

        #[cfg(not(feature = "restrictive"))]
        45..470 => version_470(data),
        470 => version_470(data),
        471 => version_471(data),

        #[cfg(not(feature = "restrictive"))]
        472..480 => version_480(data),
        480 => version_480(data),

        #[cfg(not(feature = "restrictive"))]
        481..502 => version_502(data),
        502 => version_502(data),

        #[cfg(not(feature = "restrictive"))]
        503..505 => version_505(data),
        505 => version_505(data),

        #[cfg(not(feature = "restrictive"))]
        505..550 => version_550(data),
        550 => version_550(data),

        #[cfg(not(feature = "restrictive"))]
        551..560 => version_560(data),
        560 => version_560(data),

        #[cfg(not(feature = "restrictive"))]
        561..600 => version_600(data),
        600 => version_600(data),

        #[cfg(not(feature = "restrictive"))]
        601..610 => version_610(data),
        610 => version_610(data),

        #[cfg(not(feature = "restrictive"))]
        611..640 => version_640(data),
        640 => version_640(data),

        #[cfg(not(feature = "restrictive"))]
        641..650 => version_650(data),
        650 => version_650(data),

        #[cfg(not(feature = "restrictive"))]
        651..670 => version_670(data),
        670 => version_670(data),

        #[cfg(not(feature = "restrictive"))]
        671..680 => version_680(data),
        680 => version_680(data),

        #[cfg(not(feature = "restrictive"))]
        681..695 => version_695(data),
        695 => version_695(data),

        #[cfg(not(feature = "restrictive"))]
        696.. => Ok(()),

        #[cfg(feature = "restrictive")]
        _ => Err(anyhow!("Invalid RootInfo V2: {version}")),
    }
}

fn version_16<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.target_assembler = 0;
    version_17(data)
}

fn version_17<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.cmtflg = 1;
    data.xrefs_xrefflag = data.prefflag;
    data.bin_prefix_size = 8;
    version_18(data)
}

fn version_18<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.names_dummy_names = if data.demangler_name == 0 { 6 } else { 0 };
    version_19(data)
}

fn version_19<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.lflags = 1;
    version_20(data)
}

fn version_20<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.strlit_flags = 1;
    data.listnames = 0;
    data.strlit_name_prefix = 0x61u128.to_le_bytes();
    data.field_bb = 0xff;
    version_21(data)
}

fn version_21<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    data.field_bc = 0x84;
    data.field_bd = 0x84;
    data.field_be = 0;
    data.field_bf = 1;
    data.field_c0 = 1;
    data.field_c1 = 0;
    version_22(data)
}

fn version_22<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_23(data)
}

fn version_23<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_24(data)
}

fn version_24<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // rax_14 = zx.q(zx.d([rbx + 0x29].w))
    // [rbx + 0x90].q = rax_14
    data.addresses_loading_base = data.input_operating_system.into();
    // rax_15 = zx.q(zx.d([rbx + 0x2b].w))
    // [rbx + 0x29].d = 0
    let input_application_type = data.input_application_type;
    data.input_operating_system = 0;
    data.input_application_type = 0;
    // rbx + 0xc2].q = rax_15
    data.addresses_initial_ss = input_application_type.into();
    // rax_16 = zx.q(zx.d([rbx + 0x35].w))
    // [rbx + 0xca].q = rax_16
    data.addresses_initial_cs = data.af1.into();
    version_25(data)
}

fn version_25<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // [rbx + 0x16].b = 0
    data.demangler_name = 0;
    // [rbx + 0xda].d = 0xea3be67
    data.demangler_short_demnames = K::Usize::from(0xea3be67u32);
    // [rbx + 0xe2].d = 0x6400007
    data.demangler_long_demnames = K::Usize::from(0x6400007u32);
    version_26(data)
}

fn version_26<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_27(data)
}

fn version_27<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // [rbx + 0xea].q = 7
    data.data_carousel = 7u8.into();
    version_28(data)
}

fn version_28<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_29(data)
}

fn version_29<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    //  99 @ cond:1_1 = [rbx + 0xa1].b == 0
    // 100 @ [rbx + 0x85].b = 0
    data.special_segment_entry_size = 0;
    // 101 @ [rbx + 3].w = 30
    // 102 @ if (cond:1_1) then 107 else 110
    if data.listnames == 0 {
        // 107 @ [rbx + 0xa1].b = 0xf
        data.listnames = 0xf;
        // 108 @ [rbx + 0x35].w = 0xffff
        data.af1 = 0xffff;
        // 109 @ goto 119
    } else {
        // 110 @ [rbx + 0xa0].b = [rbx + 0xa0].b | 4
        data.strlit_flags |= 4;
        // 111 @ goto 119
    }
    // 119 @ cond:0_1 = [rbx + 0x8c].b == 0
    // 120 @ [rbx + 3].w = 31
    // 121 @ if (cond:0_1) then 132 else 135 @ 0x6f1fe4
    // 132 @ [rbx + 0xf2].d = 0
    // 133 @ [rbx + 0xfa].w = 1
    // 134 @ goto 138 @ 0x6f1ffa
    // 135 @ [rbx + 0xf2].d = 4
    // 136 @ [rbx + 0xfa].w = 1
    // 137 @ goto 138 @ 0x6f1ffa
    data.strtype = K::Usize::from(if data.field_8c != 0 { 0u8 } else { 4u8 });
    data.field_fa = 1;

    version_30(data)
}

const fn version_30<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // rax_7 = zx.w([rbx + 0xbb].b)
    // [rbx + 0xfc].w = rax_7
    data.names_max_autogenerated_name_length = data.field_bb as u16;
    version_31(data)
}

const fn version_31<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_32(data)
}

const fn version_32<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // rax_8 = zx.w([rbx + 0xbd].b)
    // [rbx + 0xfe].w = rax_8
    data.margin = data.field_bd as u16;
    // rax_9 = zx.w([rbx + 0xbc].b)
    // [rbx + 0xbb].w = 0
    let field_bc = data.field_bc;
    data.field_bb = 0;
    data.field_bc = 0;
    // [rbx + 0x100].w = rax_9
    data.listing_xref_margin = field_bc as u16;
    version_33(data)
}

const fn version_33<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // 153 rax_10 = [rbx + 0x17].w
    // 154 if (rax_10 == 0) then 169 else 172
    if data.input_file_format == 0 {
        // 169 [rbx + 0x17].w = 0x16
        data.input_file_format = 0x16;
    } else if data.input_file_format == 1 {
        // 172 if (rax_10 != 1) then 186 else 188
        // 188 [rbx + 0x17].w = 0x17
        data.input_file_format = 0x17;
    }
    version_34(data)
}

const fn version_34<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_35(data)
}

const fn version_35<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_36(data)
}

const fn version_36<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // rax_11 = [rbx + 0xbb].b
    // [rbx + 0x113].b = rax_11
    data.cc_id_raw = data.field_bb;
    version_37(data)
}

const fn version_37<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_38(data)
}

const fn version_38<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // [rbx + 0x8a].b = [rbx + 0x8a].b | 2
    data.limiter |= 2;
    version_39(data)
}

const fn version_39<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_40(data)
}

const fn version_40<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_41(data)
}

const fn version_41<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // [rbx + 0x8c].b = 0
    data.field_8c = 0;
    version_42(data)
}

const fn version_42<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    if data.xrefs_max_displayed_type_xrefs != 0 {
        data.xrefs_max_displayed_type_xrefs = data.xrefs_max_displayed_xrefs;
    }
    version_43(data)
}

const fn version_43<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_44(data)
}

const fn version_44<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_470(data)
}

const fn version_470<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_471(data)
}

const fn version_471<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_480(data)
}

const fn version_480<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_502(data)
}

const fn version_502<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    // [rbx + 0x121].d = 0
    data.appcall_options = 0;
    // [rbx + 0x158].o = 0
    data.field_158 = 0;
    version_505(data)
}

const fn version_505<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_550(data)
}

const fn version_550<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_560(data)
}

const fn version_560<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_600(data)
}

const fn version_600<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_610(data)
}

const fn version_610<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_640(data)
}

const fn version_640<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_650(data)
}

const fn version_650<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_670(data)
}

const fn version_670<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_680(data)
}

const fn version_680<K: IDAKind>(data: &mut RootInfoV2Raw<K>) -> Result<()> {
    version_695(data)
}

const fn version_695<K: IDAKind>(_data: &mut RootInfoV2Raw<K>) -> Result<()> {
    Ok(())
}

const fn migrate_genflags<K: IDAKind>(data: &RootInfoV2Raw<K>) -> u16 {
    data.genflags as u16
        | if data.field_89 != 0 { 1 } else { 0 }
        | if data.field_bb != 0 { 0x80 } else { 0 }
        | (data.field_8c & 0x1E) as u16
        | if data.field_c1 & 1 != 0 { 0x20 } else { 0 }
        | if data.field_c1 & 2 != 0 { 0x40 } else { 0 }
}

const fn migrate_lflags<K: IDAKind>(
    data: &RootInfoV2Raw<K>,
    genflags: u16,
) -> u32 {
    data.lflags as u32
        | if genflags & 0x01 != 0 { 0x01 } else { 0 }
        | if genflags & 0x02 != 0 { 0x02 } else { 0 }
        | if genflags & 0x03 != 0 { 0x03 } else { 0 }
        | if genflags & 0x20 != 0 { 0x08 } else { 0 }
        | if genflags & 0x80 != 0 { 0x10 } else { 0 }
        | if genflags & 0x08 != 0 { 0x80 } else { 0 }
        | if genflags & 0x10 != 0 { 0x01 } else { 0 }
        | if data.field_be != 0 { 0x20 } else { 0 }
        | if data.field_80 != 0 { 0x40 } else { 0 }
    // TODO set the flags if the database is
    // is_database_pack: 0x200
    // is_database_compress: 0x200
}

const fn migrate_af1<K: IDAKind>(data: &RootInfoV2Raw<K>) -> u32 {
    let af1 = data.af1;
    let fa = data.field_fa;
    (if af1 & 1 != 0 { 0x80000 } else { 0 }
        | if af1 & 2 != 0 { 0x2 } else { 0 }
        | if af1 & 4 != 0 { 0x20 } else { 0 }
        | if af1 & 8 != 0 { 0x1 } else { 0 }
        | if af1 & 0x10 != 0 { 0x80 } else { 0 }
        | if af1 & 0x20 != 0 { 0x10 } else { 0 }
        | if af1 & 0x40 != 0 { 0x800000 } else { 0 }
        | if af1 & 0x80 != 0 { 0x40 } else { 0 }
        | if af1 & 0x100 != 0 { 0x8000000 } else { 0 }
        | if af1 & 0x200 != 0 { 0x10000000 } else { 0 }
        | if af1 & 0x400 != 0 { 0x2 } else { 0 }
        | if af1 & 0x800 != 0 { 0x10 } else { 0 }
        | if af1 & 0x1000 != 0 { 0x20000 } else { 0 }
        | if af1 & 0x2000 != 0 { 0x200000 } else { 0 }
        | if af1 & 0x4000 != 0 { 0x100000 } else { 0 }
        | if af1 & 0x8000 != 0 { 0x80000000 } else { 0 }
        | if fa & 1 != 0 { 0x4 } else { 0 }
        | if fa & 2 != 0 { 0x20000000 } else { 0 }
        | if fa & 4 != 0 { 0x4000000 } else { 0 }
        | if fa & 8 != 0 { 0x400 } else { 0 }
        | if fa & 0x10 != 0 { 0x800 } else { 0 }
        | if fa & 0x20 != 0 { 0x40000 } else { 0 }
        | if fa & 0x40 != 0 { 0x1000000 } else { 0 }
        | if fa & 0x80 != 0 { 0x2000000 } else { 0 }
        | if fa & 0x100 != 0 { 0x100 } else { 0 }
        | if fa & 0x200 != 0 { 0x400000 } else { 0 }
        | if fa & 0x400 != 0 { 0x4000 } else { 0 }
        | if fa & 0x800 != 0 { 0x2000 } else { 0 }
        | if fa & 0x1000 != 0 { 0x40000000 } else { 0 }
        | if fa & 0x2000 != 0 { 0x10000 } else { 0 }
        | if fa & 0x4000 != 0 { 0x8 } else { 0 }
        | if fa & 0x8000 != 0 { 0x8000 } else { 0 })
}

const fn migrate_outflag<K: IDAKind>(data: &RootInfoV2Raw<K>) -> u32 {
    (if data.field_8c & 1 != 0 { 0x80 } else { 0 }
        | if data.field_bf != 0 { 0x100 } else { 0 }
        | if data.field_c0 != 0 { 0x200 } else { 0 })
}

const _: () = assert!(size_of::<RootInfoV2Raw<crate::IDA32>>() == 0x108);
const _: () = assert!(size_of::<RootInfoV2Raw<crate::IDA64>>() == 0x168);
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C, packed)]
struct RootInfoV2Raw<K: IDAKind> {
    magic: [u8; 0x3],
    version: u16,
    cpu_name: [u8; 0x10],
    genflags: u8,
    demangler_name: u8,
    input_file_format: u16,
    _19: K::Usize,
    _29: K::Usize,
    input_operating_system: u16,
    input_application_type: u16,
    addresses_initial_sp: K::Usize,
    af1: u16,
    addresses_initial_ip: K::Usize,
    addresses_initial_ea: K::Usize,
    addresses_min_ea: K::Usize,
    addresses_max_ea: K::Usize,
    addresses_original_min_ea: K::Usize,
    addresses_original_max_ea: K::Usize,
    suspiciousness_limits_low: K::Usize,
    suspiciousness_limits_high: K::Usize,
    xrefs_max_depth: K::Usize,
    strlit_break: u8,
    field_80: u8,
    indent: u8,
    cmt_ident: u8,
    xrefs_max_displayed_xrefs: u8,
    _84: u8,
    special_segment_entry_size: u8,
    field_86: u8,
    xrefs_max_displayed_type_xrefs: u8,
    field_88: u8,
    field_89: u8,
    limiter: u8,
    field_8b: u8,
    field_8c: u8,
    field_8d: u8,
    field_8e: u8,
    target_assembler: u8,
    addresses_loading_base: K::Usize,
    xrefs_xrefflag: u8,
    bin_prefix_size: u16,
    cmtflg: u8,
    names_dummy_names: u8,
    _9d: u8,
    prefflag: u8,
    lflags: u8,
    strlit_flags: u8,
    listnames: u8,
    strlit_name_prefix: [u8; 0x10],
    strlit_serial_number: K::Usize,
    strlit_leading_zeroes: u8,
    field_bb: u8,
    field_bc: u8,
    field_bd: u8,
    field_be: u8,
    field_bf: u8,
    field_c0: u8,
    field_c1: u8,
    addresses_initial_ss: K::Usize,
    addresses_initial_cs: K::Usize,
    addresses_main_ea: K::Usize,
    demangler_short_demnames: K::Usize,
    demangler_long_demnames: K::Usize,
    data_carousel: K::Usize,
    strtype: K::Usize,
    field_fa: u16,
    names_max_autogenerated_name_length: u16,
    margin: u16,
    listing_xref_margin: u16,
    _102: [u8; 0x11],
    cc_id_raw: u8,
    cc_cm: u8,
    cc_size_i: u8,
    cc_size_b: u8,
    cc_size_e: u8,
    cc_defalign: u8,
    cc_size_s: u8,
    cc_size_l: u8,
    cc_size_ll: u8,
    database_change_count: u32,
    cc_size_ldbl: u8,
    appcall_options: u32,
    field_125: [u8; 0x10],
    abibits: u32,
    xrefs_max_displayed_strlit_xrefs: u8,
    _13a: [u8; 6],
    addresses_netdelta: K::Usize,
    addresses_privrange_start_ea: K::Usize,
    addresses_privrange_end_ea: K::Usize,
    field_158: u128,
}

impl<K: IDAKind> Default for RootInfoV2Raw<K> {
    fn default() -> Self {
        let addresses_privrange_start_ea =
            K::Usize::from(0xFFu8) << ((usize::from(K::BYTES) - 1) * 8);
        let addresses_privrange_end_ea =
            addresses_privrange_start_ea | K::Usize::from(0x100000u32);
        RootInfoV2Raw {
            magic: *b"IDA",
            version: 0,
            cpu_name: [0; 16],
            genflags: 1,
            demangler_name: 0,
            input_file_format: 0,
            _19: K::Usize::from(0u8),
            _29: K::Usize::from(0u8),
            input_operating_system: 0,
            input_application_type: 0,
            addresses_initial_sp: K::Isize::from(-1i8).as_(),
            af1: 0xFFFF,
            addresses_initial_ip: K::Isize::from(-1i8).as_(),
            addresses_initial_ea: K::Isize::from(-1i8).as_(),
            addresses_min_ea: K::Isize::from(-1i8).as_(),
            addresses_max_ea: K::Usize::from(0u8),
            addresses_original_min_ea: K::Usize::from(0u8),
            addresses_original_max_ea: K::Usize::from(0u8),
            suspiciousness_limits_low: K::Isize::from(-1i8).as_(),
            suspiciousness_limits_high: K::Usize::from(0u8),
            xrefs_max_depth: K::Usize::from(16u8),
            strlit_break: 0xA,
            field_80: 0,
            indent: 0,
            cmt_ident: 0,
            xrefs_max_displayed_xrefs: 2,
            _84: 1,
            special_segment_entry_size: 0,
            field_86: 0,
            xrefs_max_displayed_type_xrefs: 2,
            field_88: 1,
            field_89: 1,
            limiter: 0,
            field_8b: 1,
            field_8c: 2,
            field_8d: 0,
            field_8e: 1,
            target_assembler: 0,
            addresses_loading_base: K::Usize::from(0u8),
            xrefs_xrefflag: 0xF,
            bin_prefix_size: 0,
            cmtflg: 1,
            names_dummy_names: 0,
            _9d: 0,
            prefflag: 1,
            lflags: 1,
            strlit_flags: 0x11,
            listnames: 0xF,
            strlit_name_prefix: *b"a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            strlit_serial_number: K::Usize::from(0u8),
            strlit_leading_zeroes: 0,
            field_bb: 0,
            field_bc: 0,
            field_bd: 0,
            field_be: 0,
            field_bf: 1,
            field_c0: 1,
            field_c1: 1,
            addresses_initial_ss: K::Isize::from(-1i8).as_(),
            addresses_initial_cs: K::Isize::from(-1i8).as_(),
            addresses_main_ea: K::Isize::from(-1i8).as_(),
            demangler_short_demnames: K::Usize::from(0xEA3BE67u32),
            demangler_long_demnames: K::Usize::from(0x6400007u32),
            data_carousel: K::Usize::from(0x17u8),
            strtype: K::Usize::from(0u8),
            field_fa: 0x93FD,
            names_max_autogenerated_name_length: 0x1FF,
            margin: 0,
            listing_xref_margin: 0x50,
            _102: [0; 0x11],
            cc_id_raw: 0,
            cc_cm: 13,
            cc_size_i: 4,
            cc_size_b: 4,
            cc_size_e: 4,
            cc_defalign: 0,
            cc_size_s: 2,
            cc_size_l: 4,
            cc_size_ll: 8,
            database_change_count: 0,
            cc_size_ldbl: 0,
            appcall_options: 0,
            field_125: [0u8; 16],
            abibits: 0,
            xrefs_max_displayed_strlit_xrefs: 1,
            _13a: [0; 6],
            addresses_netdelta: K::Usize::from(0u8),
            // 0xFF00000000000000
            addresses_privrange_start_ea,
            // 0xFF00000000100000
            addresses_privrange_end_ea,
            field_158: 0,
        }
    }
}
