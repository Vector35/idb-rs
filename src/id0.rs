use std::ffi::CStr;
use std::io::{BufRead, Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::num::NonZeroU32;

use crate::{read_bytes_len_u16, read_c_string_raw, IDBHeader, IDBSectionCompression};

use anyhow::{anyhow, ensure, Result};

#[derive(Debug, Clone, Copy)]
enum ID0Version {
    V15,
    V16,
    V20,
}

impl ID0Version {
    pub(crate) fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let value = read_c_string_raw(input)?;
        match &value[..] {
            b"B-tree v 1.5 (C) Pol 1990" => Ok(Self::V15),
            b"B-tree v 1.6 (C) Pol 1990" => Ok(Self::V16),
            b"B-tree v2" => Ok(Self::V20),
            name => Err(anyhow!(
                "Unknown B-tree version: {}",
                String::from_utf8_lossy(name)
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ID0Header {
    // TODO handle the next_free_offset being the fist free page
    _next_free_offset: Option<NonZeroU32>,
    page_size: u16,
    // assuming None here means there are no entries in this ID0
    root_page: Option<NonZeroU32>,
    record_count: u32,
    page_count: u32,
    //unk12: u8,
    version: ID0Version,
}

impl ID0Header {
    pub(crate) fn read<I: Read>(input: &mut I, buf: &mut Vec<u8>) -> Result<Self> {
        buf.resize(64, 0);
        input.read_exact(buf)?;
        // TODO handle the 15 version of the header:
        // {
        //    let next_free_offset: u16 = bincode::deserialize_from(&mut *input)?;
        //    let page_size: u16 = bincode::deserialize_from(&mut *input)?;
        //    let root_page: u16 = bincode::deserialize_from(&mut *input)?;
        //    let record_count: u32 = bincode::deserialize_from(&mut *input)?;
        //    let page_count: u16 = bincode::deserialize_from(&mut *input)?;
        //    let unk12: u8 = bincode::deserialize_from(&mut *input)?;
        //    let version = ID0Version::read(input)?;
        // }

        let mut cursor = Cursor::new(&buf);
        let next_free_offset: u32 = bincode::deserialize_from(&mut cursor)?;
        let page_size: u16 = bincode::deserialize_from(&mut cursor)?;
        let root_page: u32 = bincode::deserialize_from(&mut cursor)?;
        let record_count: u32 = bincode::deserialize_from(&mut cursor)?;
        let page_count: u32 = bincode::deserialize_from(&mut cursor)?;
        let _unk12: u8 = bincode::deserialize_from(&mut cursor)?;
        let version = ID0Version::read(&mut cursor)?;
        // TODO move this code out of here and use seek instead
        // read the rest of the page
        ensure!(page_size >= 64);
        buf.resize(page_size.into(), 0);
        input.read_exact(&mut buf[64..])?;
        // the rest of the header should be only zeros
        ensure!(
            buf[64..].iter().all(|b| *b == 0),
            "Extra data on the header was not parsed"
        );
        Ok(ID0Header {
            _next_free_offset: NonZeroU32::new(next_free_offset),
            page_size,
            root_page: NonZeroU32::new(root_page),
            record_count,
            page_count,
            version,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ID0Section {
    is_64: bool,
    pub entries: Vec<ID0Entry>,
}

#[derive(Debug, Clone)]
pub struct ID0Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl ID0Section {
    pub(crate) fn read<I: Read>(
        input: &mut I,
        header: &IDBHeader,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input, header),
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::read_inner(&mut input, header)
            }
        }
    }

    // NOTE this was written this way to validate the data in each file, so it's clear that no
    // data is being parsed incorrectly or is left unparsed. There way too many validations
    // and non-necessary parsing is done on delete data.
    // TODO This is probably much more efficient if written with <I: BufRead + Seek>, this
    // way it's not necessary to read and cache the unused/deleted pages, if you are sure this
    // implementation is correct, you could rewrite this function to do that.
    fn read_inner<I: Read>(input: &mut I, idb_header: &IDBHeader) -> Result<Self> {
        // pages size are usually around that size
        let mut buf = Vec::with_capacity(0x2000);
        let header = ID0Header::read(&mut *input, &mut buf)?;
        buf.resize(header.page_size.into(), 0);
        // NOTE sometimes deleted pages are included here, seems to happen specially if a
        // index is deleted with all it's leafs, leaving the now-empty index and the
        // now-disconnected children
        let mut pages = Vec::with_capacity(header.page_count.try_into().unwrap());
        loop {
            let read = read_exact_or_nothing(&mut *input, &mut buf)?;
            if read == 0 {
                // no more data, hit eof
                break;
            }
            if read != header.page_size.into() {
                // only read part of the page
                return Err(anyhow!("Found EoF in the middle of the page"));
            }
            // read the full page
            let page = ID0TreeEntrRaw::read(&buf, &header)?;
            pages.push(Some(page));
        }

        // verify for duplicated entries
        let pages_tree = Self::create_tree(header.root_page, &mut pages)?;

        // verify that the correct number of pages were consumed and added to the tree
        let in_tree_pages = pages
            .iter()
            .map(Option::as_ref)
            .filter(Option::is_none)
            .count();
        ensure!(in_tree_pages == header.page_count.try_into().unwrap());

        // make sure only empty pages are left out-of-the-tree
        for page in pages.into_iter().flatten() {
            match page {
                ID0TreeEntrRaw::Leaf(leaf) if leaf.is_empty() => {}
                ID0TreeEntrRaw::Index { entries, .. } if entries.is_empty() => {}
                ID0TreeEntrRaw::Index {
                    preceeding,
                    entries,
                } => {
                    return Err(anyhow!(
                        "Extra Index preceeding {}, with {} entries",
                        preceeding.get(),
                        entries.len()
                    ))
                }
                ID0TreeEntrRaw::Leaf(entries) => {
                    let entries_len = entries
                        .iter()
                        .filter(|e| !e.key.is_empty() || !e.value.is_empty())
                        .count();
                    if entries_len != 0 {
                        return Err(anyhow!("Extra Leaf with {} entry", entries_len));
                    }
                }
            }
        }

        // put it all in order on the vector
        let mut entries = Vec::with_capacity(header.record_count.try_into().unwrap());
        Self::tree_to_vec(pages_tree, &mut entries);

        // make sure the vector is sorted
        ensure!(entries.windows(2).all(|win| {
            let [a, b] = win else { unreachable!() };
            a.key < b.key
        }));

        // make sure the right number of entries are in the final vector
        ensure!(entries.len() == header.record_count.try_into().unwrap());

        Ok(ID0Section {
            is_64: idb_header.magic_version.is_64(),
            entries,
        })
    }

    fn create_tree(
        index: Option<NonZeroU32>,
        pages: &mut Vec<Option<ID0TreeEntrRaw>>,
    ) -> Result<ID0TreeEntry> {
        let Some(index) = index else {
            return Ok(ID0TreeEntry::Leaf(vec![]));
        };

        let index = usize::try_from(index.get()).unwrap() - 1;
        let entry = pages
            .get_mut(index)
            .ok_or_else(|| anyhow!("invalid page index: {index}"))?
            .take()
            .ok_or_else(|| anyhow!("page index {index} is referenciated multiple times"))?;
        match entry {
            ID0TreeEntrRaw::Leaf(leaf) => Ok(ID0TreeEntry::Leaf(leaf)),
            ID0TreeEntrRaw::Index {
                preceeding,
                entries,
            } => {
                let preceeding = Self::create_tree(Some(preceeding), &mut *pages)?;
                let index = entries
                    .into_iter()
                    .map(|e| {
                        let page = Self::create_tree(e.page, &mut *pages)?;
                        Ok(ID0TreeIndex {
                            page: Box::new(page),
                            key: e.key,
                            value: e.value,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(ID0TreeEntry::Index {
                    preceeding: Box::new(preceeding),
                    index,
                })
            }
        }
    }

    fn tree_to_vec(entry: ID0TreeEntry, output: &mut Vec<ID0Entry>) {
        match entry {
            ID0TreeEntry::Index { preceeding, index } => {
                Self::tree_to_vec(*preceeding, &mut *output);
                for ID0TreeIndex { page, key, value } in index {
                    output.push(ID0Entry { key, value });
                    Self::tree_to_vec(*page, &mut *output);
                }
            }
            ID0TreeEntry::Leaf(entries) => output.extend(entries),
        }
    }

    fn binary_search(&self, key: impl AsRef<[u8]>) -> Result<usize, usize> {
        let key = key.as_ref();
        self.entries.binary_search_by_key(&key, |b| &b.key[..])
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&ID0Entry> {
        self.binary_search(key).ok().map(|i| &self.entries[i])
    }

    pub fn sub_values<'a>(&'a self, key: Vec<u8>) -> impl Iterator<Item = &ID0Entry> + 'a {
        let start = self.binary_search(&key);
        let start = match start {
            Ok(pos) => pos,
            Err(start) => start,
        };

        self.entries[start..]
            .iter()
            .take_while(move |e| e.key.starts_with(&key))
    }

    pub fn segments<'a>(&'a self) -> Result<impl Iterator<Item = Result<Segment>> + 'a> {
        let entry = self
            .get("N$ segs")
            .ok_or_else(|| anyhow!("Unable to find entry segs"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        Ok(self
            .sub_values(key)
            .map(|e| Segment::read(&e.value, self.is_64)))
    }

    pub fn loader_name<'a>(&'a self) -> Result<impl Iterator<Item = Result<&'a str>> + 'a> {
        let entry = self
            .get("N$ loader name")
            .ok_or_else(|| anyhow!("Unable to find entry loader name"))?;
        // TODO check that keys are 0 => plugin, or 1 => format
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        Ok(self
            .sub_values(key)
            .map(|e| Ok(CStr::from_bytes_with_nul(&e.value)?.to_str()?)))
    }

    pub fn root_info<'a>(&'a self) -> Result<impl Iterator<Item = Result<IDBRootInfo<'a>>> + 'a> {
        let entry = self
            .get("NRoot Node")
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        Ok(self.sub_values(key).map(|entry| {
            let sub_key = entry.key.strip_prefix(&entry.key[..]).unwrap();
            let Some(sub_type) = sub_key.get(0).copied() else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, sub_key.len()) {
                (b'N', 1) => {
                    ensure!(
                        entry.value.as_slice().eq(b"Root Node"),
                        "Invalid Root Node Name"
                    );
                    return Ok(IDBRootInfo::RootNodeName);
                }
                (b'V', 1) => {
                    return parse_maybe_cstr(&entry.value)
                        .map(IDBRootInfo::InputFile)
                        .ok_or_else(|| anyhow!("Unable to parse VersionString string"))
                }
                _ => {}
            }
            let Some(value) = parse_number(&sub_key[1..], true, self.is_64) else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, value as i64) {
                (b'A', -6) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse imagebase value"))
                    .map(IDBRootInfo::ImageBase),
                (b'A', -5) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse crc value"))
                    .map(IDBRootInfo::Crc),
                (b'A', -4) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse open_count value"))
                    .map(IDBRootInfo::OpenCount),
                (b'A', -2) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse CreatedDate value"))
                    .map(IDBRootInfo::CreatedDate),
                (b'A', -1) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse Version value"))
                    .map(IDBRootInfo::Version),
                (b'S', 1302) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Md5)
                    .map_err(|_| anyhow!("Value Md5 with invalid len")),
                (b'S', 1303) => parse_maybe_cstr(&entry.value)
                    .map(IDBRootInfo::VersionString)
                    .ok_or_else(|| anyhow!("Unable to parse VersionString string")),
                (b'S', 1349) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Sha256)
                    .map_err(|_| anyhow!("Value Sha256 with invalid len")),
                (b'S', 0x41b994) => {
                    IDBParam::read(&entry.value, self.is_64).map(IDBRootInfo::IDAInfo)
                }
                _ => Ok(IDBRootInfo::Unknown(entry)),
            }
        }))
    }

    pub fn ida_info(&self) -> Result<IDBParam> {
        // TODO Root Node is always the last one?
        let entry = self
            .get("NRoot Node")
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        let sub_key = if self.is_64 {
            0x41B994u64.to_be_bytes().to_vec()
        } else {
            0x41B994u32.to_be_bytes().to_vec()
        };
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .chain(sub_key.iter())
            .copied()
            .collect();
        let description = self
            .sub_values(key)
            .next()
            .ok_or_else(|| anyhow!("Unable to find id_params inside Root Node"))?;
        IDBParam::read(&description.value, self.is_64)
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    startea: u64,
    size: u64,
    name_id: u64,
    class_id: u64,
    /// This field is IDP dependent.
    /// You may keep your information about the segment here
    orgbase: u64,
    /// See more at [flags](https://hex-rays.com//products/ida/support/sdkdoc/group___s_f_l__.html)
    flags: u32,
    /// [Segment alignment codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sa__.html)
    align: u32,
    /// [Segment combination codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sc__.html)
    comb: u32,
    /// [Segment permissions](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g_p_e_r_m__.html) (0 means no information)
    perm: u32,
    /// Number of bits in the segment addressing.
    /// 0: 16 bits
    /// 1: 32 bits
    /// 2: 64 bits
    bitness: u32,
    /// Segment type (see [Segment types](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g__.html)).
    /// The kernel treats different segment types differently. Segments marked with '*' contain no instructions or data and are not declared as 'segments' in the disassembly.
    seg_type: u32,
    /// Segment selector - should be unique.
    /// You can't change this field after creating the segment.
    /// Exception: 16bit OMF files may have several segments with the same selector,
    /// but this is not good (no way to denote a segment exactly) so it should be fixed in
    /// the future.
    selector: u64,
    /// Default segment register values.
    /// First element of this array keeps information about value of [processor_t::reg_first_sreg](https://hex-rays.com//products/ida/support/sdkdoc/structprocessor__t.html#a4206e35bf99d211c18d53bd1035eb2e3)
    defsr: [u64; 16],
    ///	the segment color
    color: u32,
}

impl Segment {
    fn read(value: &[u8], is_64: bool) -> Result<Self> {
        let mut cursor = Cursor::new(value);
        let startea = parse_word(&mut cursor, is_64)?;
        let size = parse_word(&mut cursor, is_64)?;
        let name_id = parse_word(&mut cursor, is_64)?;
        let class_id = parse_word(&mut cursor, is_64)?;
        let orgbase = parse_word(&mut cursor, is_64)?;
        let flags = parse_u32(&mut cursor)?;
        let align = parse_u32(&mut cursor)?;
        let comb = parse_u32(&mut cursor)?;
        let perm = parse_u32(&mut cursor)?;
        let bitness = parse_u32(&mut cursor)?;
        let seg_type = parse_u32(&mut cursor)?;
        let selector = parse_word(&mut cursor, is_64)?;
        let defsr: Vec<_> = (0..16)
            .map(|_| parse_word(&mut cursor, is_64))
            .collect::<Result<_, _>>()?;
        let color = parse_u32(&mut cursor)?;

        // TODO maybe new versions include extra information and thid check fails
        ensure!(cursor.position() == value.len().try_into().unwrap());
        Ok(Segment {
            startea,
            size,
            name_id,
            class_id,
            orgbase,
            flags,
            align,
            comb,
            perm,
            bitness,
            seg_type,
            selector,
            defsr: defsr.try_into().unwrap(),
            color,
        })
    }
}

#[derive(Clone, Debug)]
pub enum IDBRootInfo<'a> {
    /// it's just the "Root Node" String
    RootNodeName,
    InputFile(&'a str),
    Crc(u64),
    ImageBase(u64),
    OpenCount(u64),
    CreatedDate(u64),
    Version(u64),
    Md5(&'a [u8; 16]),
    VersionString(&'a str),
    Sha256(&'a [u8; 32]),
    IDAInfo(IDBParam),
    Unknown(&'a ID0Entry),
}

#[derive(Clone, Debug)]
pub enum IDBParam {
    V1(IDBParam1),
    V2(IDBParam2),
}

#[derive(Clone, Debug)]
pub struct IDBParam1 {
    pub cpu: String,
    pub lflags: u8,
    pub demnames: u8,
    pub filetype: u16,
    pub fcoresize: u64,
    pub corestart: u64,
    pub ostype: u16,
    pub apptype: u16,
    pub startsp: u64,
    pub af: u16,
    pub startip: u64,
    pub startea: u64,
    pub minea: u64,
    pub maxea: u64,
    pub ominea: u64,
    pub omaxea: u64,
    pub lowoff: u64,
    pub highoff: u64,
    pub maxref: u64,
    pub ascii_break: u8,
    pub wide_high_byte_first: u8,
    pub indent: u8,
    pub comment: u8,
    pub xrefnum: u8,
    pub entab: u8,
    pub specsegs: u8,
    pub voids: u8,
    pub showauto: u8,
    pub auto: u8,
    pub border: u8,
    pub null: u8,
    pub genflags: u8,
    pub showpref: u8,
    pub prefseg: u8,
    pub asmtype: u8,
    pub baseaddr: u64,
    pub xrefs: u8,
    pub binpref: u16,
    pub cmtflag: u8,
    pub nametype: u8,
    pub showbads: u8,
    pub prefflag: u8,
    pub packbase: u8,
    pub asciiflags: u8,
    pub listnames: u8,
    pub asciiprefs: [u8; 16],
    pub asciisernum: u64,
    pub asciizeroes: u8,
    pub tribyte_order: u8,
    pub mf: u8,
    pub org: u8,
    pub assume: u8,
    pub checkarg: u8,
    // offset 131
    pub start_ss: u64,
    pub start_cs: u64,
    pub main: u64,
    pub short_dn: u64,
    pub long_dn: u64,
    pub datatypes: u64,
    pub strtype: u64,
    pub af2: u16,
    pub namelen: u16,
    pub margin: u16,
    pub lenxref: u16,
    pub lprefix: [u8; 16],
    pub lprefixlen: u8,
    pub compiler: u8,
    pub model: u8,
    pub sizeof_int: u8,
    pub sizeof_bool: u8,
    pub sizeof_enum: u8,
    pub sizeof_algn: u8,
    pub sizeof_short: u8,
    pub sizeof_long: u8,
    pub sizeof_llong: u8,
    pub change_counter: u32,
    pub sizeof_ldbl: u8,
    pub abiname: [u8; 16],
    pub abibits: u32,
    pub refcmts: u8,
}

#[derive(Clone, Debug)]
pub struct IDBParam2 {
    pub cpu: String,
    pub genflags: Inffl,
    pub lflags: Lflg,
    pub database_change_count: u32,
    pub filetype: FileType,
    pub ostype: u16,
    pub apptype: u16,
    pub asmtype: u8,
    pub specsegs: u8,
    pub af: Af,
    pub baseaddr: u64,
    pub start_ss: u64,
    pub start_cs: u64,
    pub start_ip: u64,
    pub start_ea: u64,
    pub start_sp: u64,
    pub main: u64,
    pub min_ea: u64,
    pub max_ea: u64,
    pub omin_ea: u64,
    pub omax_ea: u64,
    pub lowoff: u64,
    pub highoff: u64,
    pub maxref: u64,
    pub privrange_start_ea: u64,
    pub privrange_end_ea: u64,
    pub netdelta: u64,
    pub xrefnum: u8,
    pub type_xrefnum: u8,
    pub refcmtnum: u8,
    pub xrefflag: XRef,
    pub max_autoname_len: u16,
    pub nametype: NameType,
    pub short_demnames: u32,
    pub long_demnames: u32,
    pub demnames: DemName,
    pub listnames: ListName,
    pub indent: u8,
    pub cmt_ident: u8,
    pub margin: u16,
    pub lenxref: u16,
    pub outflags: OutputFlags,
    pub cmtflg: CommentOptions,
    pub limiter: DelimiterOptions,
    pub bin_prefix_size: u16,
    pub prefflag: LinePrefixOptions,
    pub strlit_flags: StrLiteralFlags,
    pub strlit_break: u8,
    pub strlit_zeroes: u8,
    pub strtype: u32,
    pub strlit_pref: String,
    pub strlit_sernum: u64,
    pub datatypes: u64,
    pub cc_id: Compiler,
    pub cc_cm: u8,
    pub cc_size_i: u8,
    pub cc_size_b: u8,
    pub cc_size_e: u8,
    pub cc_defalign: u8,
    pub cc_size_s: u8,
    pub cc_size_l: u8,
    pub cc_size_ll: u8,
    pub cc_size_ldbl: u8,
    pub abibits: AbiOptions,
    pub appcall_options: u32,
}

impl IDBParam {
    pub(crate) fn read(data: &[u8], is_64: bool) -> Result<Self> {
        let mut input = Cursor::new(data);
        let magic: [u8; 3] = bincode::deserialize_from(&mut input)?;
        let magic_old = match &magic[..] {
            b"ida" => {
                let zero: u8 = bincode::deserialize_from(&mut input)?;
                ensure!(zero == 0);
                true
            }
            b"IDA" => false,
            _ => return Err(anyhow!("Invalid IDBParam Magic")),
        };
        let version: u16 = bincode::deserialize_from(&mut input)?;

        let cpu_len = match (magic_old, version) {
            (_, ..700) => 8,
            (true, 700..) => 16,
            (false, 700..) => {
                let cpu_len: u8 = bincode::deserialize_from(&mut input)?;
                cpu_len.try_into().unwrap()
            }
        };
        let mut cpu = vec![0; cpu_len];
        input.read_exact(&mut cpu)?;
        // remove any \x00 that marks the end of the str
        if let Some(end_cpu_str) = cpu.iter().position(|b| *b == 0) {
            // make sure there is no data after the \x00 in the string
            ensure!(cpu[end_cpu_str..].iter().all(|b| *b == 0));
            cpu.truncate(end_cpu_str);
        }
        let cpu = String::from_utf8(cpu)?;

        // TODO tight those ranges up
        let param = match version {
            ..700 => Self::read_v1(&mut input, is_64, cpu)?,
            700.. => Self::read_v2(&mut input, is_64, magic_old, cpu)?,
        };
        match version {
            // TODO old version may contain extra data at the end with unknown purpose
            ..700 => {}
            700.. => ensure!(
                input.position() == data.len().try_into().unwrap(),
                "Data left after the IDBParam: {}",
                u64::try_from(data.len()).unwrap() - input.position()
            ),
        }
        Ok(param)
    }

    pub(crate) fn read_v1<I: Read>(mut input: I, is_64: bool, cpu: String) -> Result<Self> {
        let lflags: u8 = bincode::deserialize_from(&mut input)?;
        let demnames: u8 = bincode::deserialize_from(&mut input)?;
        let filetype: u16 = bincode::deserialize_from(&mut input)?;
        let fcoresize: u64 = read_word(&mut input, is_64)?;
        let corestart: u64 = read_word(&mut input, is_64)?;
        let ostype: u16 = bincode::deserialize_from(&mut input)?;
        let apptype: u16 = bincode::deserialize_from(&mut input)?;
        let startsp: u64 = read_word(&mut input, is_64)?;
        let af: u16 = bincode::deserialize_from(&mut input)?;
        let startip: u64 = read_word(&mut input, is_64)?;
        let startea: u64 = read_word(&mut input, is_64)?;
        let minea: u64 = read_word(&mut input, is_64)?;
        let maxea: u64 = read_word(&mut input, is_64)?;
        let ominea: u64 = read_word(&mut input, is_64)?;
        let omaxea: u64 = read_word(&mut input, is_64)?;
        let lowoff: u64 = read_word(&mut input, is_64)?;
        let highoff: u64 = read_word(&mut input, is_64)?;
        let maxref: u64 = read_word(&mut input, is_64)?;
        let ascii_break: u8 = bincode::deserialize_from(&mut input)?;
        let wide_high_byte_first: u8 = bincode::deserialize_from(&mut input)?;
        let indent: u8 = bincode::deserialize_from(&mut input)?;
        let comment: u8 = bincode::deserialize_from(&mut input)?;
        let xrefnum: u8 = bincode::deserialize_from(&mut input)?;
        let entab: u8 = bincode::deserialize_from(&mut input)?;
        let specsegs: u8 = bincode::deserialize_from(&mut input)?;
        let voids: u8 = bincode::deserialize_from(&mut input)?;
        let _unkownw: u8 = bincode::deserialize_from(&mut input)?;
        let showauto: u8 = bincode::deserialize_from(&mut input)?;
        let auto: u8 = bincode::deserialize_from(&mut input)?;
        let border: u8 = bincode::deserialize_from(&mut input)?;
        let null: u8 = bincode::deserialize_from(&mut input)?;
        let genflags: u8 = bincode::deserialize_from(&mut input)?;
        let showpref: u8 = bincode::deserialize_from(&mut input)?;
        let prefseg: u8 = bincode::deserialize_from(&mut input)?;
        let asmtype: u8 = bincode::deserialize_from(&mut input)?;
        let baseaddr: u64 = read_word(&mut input, is_64)?;
        let xrefs: u8 = bincode::deserialize_from(&mut input)?;
        let binpref: u16 = bincode::deserialize_from(&mut input)?;
        let cmtflag: u8 = bincode::deserialize_from(&mut input)?;
        let nametype: u8 = bincode::deserialize_from(&mut input)?;
        let showbads: u8 = bincode::deserialize_from(&mut input)?;
        let prefflag: u8 = bincode::deserialize_from(&mut input)?;
        let packbase: u8 = bincode::deserialize_from(&mut input)?;
        let asciiflags: u8 = bincode::deserialize_from(&mut input)?;
        let listnames: u8 = bincode::deserialize_from(&mut input)?;
        let asciiprefs: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let asciisernum: u64 = read_word(&mut input, is_64)?;
        let asciizeroes: u8 = bincode::deserialize_from(&mut input)?;
        let _unknown2: u16 = bincode::deserialize_from(&mut input)?;
        let tribyte_order: u8 = bincode::deserialize_from(&mut input)?;
        let mf: u8 = bincode::deserialize_from(&mut input)?;
        let org: u8 = bincode::deserialize_from(&mut input)?;
        let assume: u8 = bincode::deserialize_from(&mut input)?;
        let checkarg: u8 = bincode::deserialize_from(&mut input)?;
        // offset 131
        let start_ss: u64 = read_word(&mut input, is_64)?;
        let start_cs: u64 = read_word(&mut input, is_64)?;
        let main: u64 = read_word(&mut input, is_64)?;
        let short_dn: u64 = read_word(&mut input, is_64)?;
        let long_dn: u64 = read_word(&mut input, is_64)?;
        let datatypes: u64 = read_word(&mut input, is_64)?;
        let strtype: u64 = read_word(&mut input, is_64)?;
        let af2: u16 = bincode::deserialize_from(&mut input)?;
        let namelen: u16 = bincode::deserialize_from(&mut input)?;
        let margin: u16 = bincode::deserialize_from(&mut input)?;
        let lenxref: u16 = bincode::deserialize_from(&mut input)?;
        let lprefix: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let lprefixlen: u8 = bincode::deserialize_from(&mut input)?;
        let compiler: u8 = bincode::deserialize_from(&mut input)?;
        let model: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_int: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_bool: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_enum: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_algn: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_short: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_long: u8 = bincode::deserialize_from(&mut input)?;
        let sizeof_llong: u8 = bincode::deserialize_from(&mut input)?;
        let change_counter: u32 = bincode::deserialize_from(&mut input)?;
        let sizeof_ldbl: u8 = bincode::deserialize_from(&mut input)?;
        let _unknown_3: u32 = bincode::deserialize_from(&mut input)?;
        let abiname: [u8; 16] = bincode::deserialize_from(&mut input)?;
        let abibits: u32 = bincode::deserialize_from(&mut input)?;
        let refcmts: u8 = bincode::deserialize_from(&mut input)?;

        Ok(IDBParam::V1(IDBParam1 {
            cpu,
            lflags,
            demnames,
            filetype,
            fcoresize,
            corestart,
            ostype,
            apptype,
            startsp,
            af,
            startip,
            startea,
            minea,
            maxea,
            ominea,
            omaxea,
            lowoff,
            highoff,
            maxref,
            ascii_break,
            wide_high_byte_first,
            indent,
            comment,
            xrefnum,
            entab,
            specsegs,
            voids,
            showauto,
            auto,
            border,
            null,
            genflags,
            showpref,
            prefseg,
            asmtype,
            baseaddr,
            xrefs,
            binpref,
            cmtflag,
            nametype,
            showbads,
            prefflag,
            packbase,
            asciiflags,
            listnames,
            asciiprefs,
            asciisernum,
            asciizeroes,
            tribyte_order,
            mf,
            org,
            assume,
            checkarg,
            start_ss,
            start_cs,
            main,
            short_dn,
            long_dn,
            datatypes,
            strtype,
            af2,
            namelen,
            margin,
            lenxref,
            lprefix,
            lprefixlen,
            compiler,
            model,
            sizeof_int,
            sizeof_bool,
            sizeof_enum,
            sizeof_algn,
            sizeof_short,
            sizeof_long,
            sizeof_llong,
            change_counter,
            sizeof_ldbl,
            abiname,
            abibits,
            refcmts,
        }))
    }

    pub(crate) fn read_v2<I: Read>(
        mut input: I,
        is_64: bool,
        magic_old: bool,
        cpu: String,
    ) -> Result<Self> {
        // NOTE in this version parse_* functions are used
        let genflags = Inffl::new(parse_u16(&mut input)?)?;
        let lflags = Lflg::new(parse_u32(&mut input)?)?;
        let database_change_count = parse_u32(&mut input)?;
        let filetype = FileType::from_value(parse_u16(&mut input)?)
            .ok_or_else(|| anyhow!("Invalid FileType value"))?;
        let ostype = parse_u16(&mut input)?;
        let apptype = parse_u16(&mut input)?;
        let asmtype = parse_u8(&mut input)?;
        let specsegs = parse_u8(&mut input)?;
        let af1 = parse_u32(&mut input)?;
        let af2 = parse_u32(&mut input)?;
        let af = Af::new(af1, af2)?;
        let baseaddr = parse_word(&mut input, is_64)?;
        let start_ss = parse_word(&mut input, is_64)?;
        let start_cs = parse_word(&mut input, is_64)?;
        let start_ip = parse_word(&mut input, is_64)?;
        let start_ea = parse_word(&mut input, is_64)?;
        let start_sp = parse_word(&mut input, is_64)?;
        let main = parse_word(&mut input, is_64)?;
        let min_ea = parse_word(&mut input, is_64)?;
        let max_ea = parse_word(&mut input, is_64)?;
        let omin_ea = parse_word(&mut input, is_64)?;
        let omax_ea = parse_word(&mut input, is_64)?;
        let lowoff = parse_word(&mut input, is_64)?;
        let highoff = parse_word(&mut input, is_64)?;
        let maxref = parse_word(&mut input, is_64)?;
        let privrange_start_ea = parse_word(&mut input, is_64)?;
        let privrange_end_ea = parse_word(&mut input, is_64)?;
        let netdelta = parse_word(&mut input, is_64)?;
        let xrefnum = parse_u8(&mut input)?;
        let type_xrefnum = parse_u8(&mut input)?;
        let refcmtnum = parse_u8(&mut input)?;
        let xrefflag = XRef::new(parse_u8(&mut input)?)?;
        let max_autoname_len = parse_u16(&mut input)?;

        if magic_old {
            let _unknown: [u8; 17] = bincode::deserialize_from(&mut input)?;
        }

        let nametype = parse_u8(&mut input)?;
        let nametype = NameType::new(nametype).ok_or_else(|| anyhow!("Invalid NameType value"))?;
        let short_demnames = parse_u32(&mut input)?;
        let long_demnames = parse_u32(&mut input)?;
        let demnames = DemName::new(parse_u8(&mut input)?)?;
        let listnames = ListName::new(parse_u8(&mut input)?)?;
        let indent = parse_u8(&mut input)?;
        let cmt_ident = parse_u8(&mut input)?;
        let margin = parse_u16(&mut input)?;
        let lenxref = parse_u16(&mut input)?;
        let outflags = OutputFlags::new(parse_u32(&mut input)?)?;
        let cmtflg = CommentOptions::new(parse_u8(&mut input)?);
        let limiter = DelimiterOptions::new(parse_u8(&mut input)?)?;
        let bin_prefix_size = parse_u16(&mut input)?;
        let prefflag = LinePrefixOptions::new(parse_u8(&mut input)?)?;
        let strlit_flags = StrLiteralFlags::new(parse_u8(&mut input)?)?;
        let strlit_break = parse_u8(&mut input)?;
        let strlit_zeroes = parse_u8(&mut input)?;
        let strtype = parse_u32(&mut input)?;

        // TODO read the len and the ignore it?
        let strlit_pref_len = parse_u8(&mut input)?;
        let strlit_pref_len = if magic_old { 16 } else { strlit_pref_len };
        let mut strlit_pref = vec![0; strlit_pref_len.into()];
        input.read_exact(&mut strlit_pref)?;
        let strlit_pref = String::from_utf8(strlit_pref)?;

        let strlit_sernum = parse_word(&mut input, is_64)?;
        let datatypes = parse_word(&mut input, is_64)?;
        let cc_id = Compiler::from_value(parse_u8(&mut input)?)
            .ok_or_else(|| anyhow!("invalid Compiler ID Value"))?;
        let cc_cm = parse_u8(&mut input)?;
        let cc_size_i = parse_u8(&mut input)?;
        let cc_size_b = parse_u8(&mut input)?;
        let cc_size_e = parse_u8(&mut input)?;
        let cc_defalign = parse_u8(&mut input)?;
        let cc_size_s = parse_u8(&mut input)?;
        let cc_size_l = parse_u8(&mut input)?;
        let cc_size_ll = parse_u8(&mut input)?;
        let cc_size_ldbl = parse_u8(&mut input)?;
        let abibits = AbiOptions::new(parse_u32(&mut input)?)?;
        let appcall_options = parse_u32(&mut input)?;

        Ok(IDBParam::V2(IDBParam2 {
            cpu,
            genflags,
            lflags,
            database_change_count,
            filetype,
            ostype,
            apptype,
            asmtype,
            specsegs,
            af,
            baseaddr,
            start_ss,
            start_cs,
            start_ip,
            start_ea,
            start_sp,
            main,
            min_ea,
            max_ea,
            omin_ea,
            omax_ea,
            lowoff,
            highoff,
            maxref,
            privrange_start_ea,
            privrange_end_ea,
            netdelta,
            xrefnum,
            type_xrefnum,
            refcmtnum,
            xrefflag,
            max_autoname_len,
            nametype,
            short_demnames,
            long_demnames,
            demnames,
            listnames,
            indent,
            cmt_ident,
            margin,
            lenxref,
            outflags,
            cmtflg,
            limiter,
            bin_prefix_size,
            prefflag,
            strlit_flags,
            strlit_break,
            strlit_zeroes,
            strtype,
            strlit_pref,
            strlit_sernum,
            datatypes,
            cc_id,
            cc_cm,
            cc_size_i,
            cc_size_b,
            cc_size_e,
            cc_defalign,
            cc_size_s,
            cc_size_l,
            cc_size_ll,
            cc_size_ldbl,
            abibits,
            appcall_options,
        }))
    }
}

/// General idainfo flags
#[derive(Debug, Clone, Copy)]
pub struct Inffl(u8);
impl Inffl {
    fn new(value: u16) -> Result<Self> {
        ensure!(value < 0x100, "Invalid INFFL flag");
        // TODO check for unused flags?
        Ok(Self(value as u8))
    }

    /// Autoanalysis is enabled?
    pub fn is_auto_analysis_enabled(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// May use constructs not supported by the target assembler
    pub fn maybe_not_supported(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// loading an idc file that contains database info
    pub fn is_database_info_in_idc(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// do not store user info in the database
    pub fn is_user_info_not_in_database(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// (internal) temporary interdiction to modify the database
    pub fn is_read_only(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// check manual operands? (unused)
    pub fn is_manual_operands(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// allow non-matched operands? (unused)
    pub fn is_non_matched_operands(&self) -> bool {
        self.0 & 0x40 != 0
    }
    /// currently using graph options
    pub fn is_using_graph(&self) -> bool {
        self.0 & 0x80 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Lflg(u16);
impl Lflg {
    fn new(value: u32) -> Result<Self> {
        ensure!(value < 0x1000, "Invalid LFLG flag");
        Ok(Self(value as u16))
    }

    /// decode floating point processor instructions?
    pub fn is_decode_float(&self) -> bool {
        self.0 & 0x0001 != 0
    }
    /// 32-bit program (or higher)?
    pub fn is_program_32b_or_bigger(&self) -> bool {
        self.0 & 0x0002 != 0
    }
    /// 64-bit program?
    pub fn is_program_64b(&self) -> bool {
        self.0 & 0x0004 != 0
    }
    /// Is dynamic library?
    pub fn is_dyn_lib(&self) -> bool {
        self.0 & 0x0008 != 0
    }
    /// treat ::REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
    pub fn is_flat_off32(&self) -> bool {
        self.0 & 0x0010 != 0
    }
    /// Byte order: is MSB first?
    pub fn is_big_endian(&self) -> bool {
        self.0 & 0x0020 != 0
    }
    /// Bit order of wide bytes: high byte first?
    pub fn is_wide_byte_first(&self) -> bool {
        self.0 & 0x0040 != 0
    }
    /// do not store input full path in debugger process options
    pub fn is_dbg_non_fullpath(&self) -> bool {
        self.0 & 0x0080 != 0
    }
    /// memory snapshot was taken?
    pub fn is_snapshot_taken(&self) -> bool {
        self.0 & 0x0100 != 0
    }
    /// pack the database?
    pub fn is_database_pack(&self) -> bool {
        self.0 & 0x0200 != 0
    }
    /// compress the database?
    pub fn is_database_compress(&self) -> bool {
        self.0 & 0x0400 != 0
    }
    /// is kernel mode binary?
    pub fn is_kernel_mode(&self) -> bool {
        self.0 & 0x0800 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Af(u32, u8);
impl Af {
    fn new(value1: u32, value2: u32) -> Result<Self> {
        ensure!(value2 < 0x8, "Invalid AF2 value {value2:#x}");
        Ok(Self(value1, value2 as u8))
    }

    /// Trace execution flow
    pub fn is_code(&self) -> bool {
        self.0 & 0x00000001 != 0
    }
    /// Mark typical code sequences as code
    pub fn is_markcode(&self) -> bool {
        self.0 & 0x00000002 != 0
    }
    /// Locate and create jump tables
    pub fn is_jumptbl(&self) -> bool {
        self.0 & 0x00000004 != 0
    }
    /// Control flow to data segment is ignored
    pub fn is_purdat(&self) -> bool {
        self.0 & 0x00000008 != 0
    }
    /// Analyze and create all xrefs
    pub fn is_used(&self) -> bool {
        self.0 & 0x00000010 != 0
    }
    /// Delete instructions with no xrefs
    pub fn is_unk(&self) -> bool {
        self.0 & 0x00000020 != 0
    }

    /// Create function if data xref data->code32 exists
    pub fn is_procptr(&self) -> bool {
        self.0 & 0x00000040 != 0
    }
    /// Create functions if call is present
    pub fn is_proc(&self) -> bool {
        self.0 & 0x00000080 != 0
    }
    /// Create function tails
    pub fn is_ftail(&self) -> bool {
        self.0 & 0x00000100 != 0
    }
    /// Create stack variables
    pub fn is_lvar(&self) -> bool {
        self.0 & 0x00000200 != 0
    }
    /// Propagate stack argument information
    pub fn is_stkarg(&self) -> bool {
        self.0 & 0x00000400 != 0
    }
    /// Propagate register argument information
    pub fn is_regarg(&self) -> bool {
        self.0 & 0x00000800 != 0
    }
    /// Trace stack pointer
    pub fn is_trace(&self) -> bool {
        self.0 & 0x00001000 != 0
    }
    /// Perform full SP-analysis.
    pub fn is_versp(&self) -> bool {
        self.0 & 0x00002000 != 0
    }
    /// Perform 'no-return' analysis
    pub fn is_anoret(&self) -> bool {
        self.0 & 0x00004000 != 0
    }
    /// Try to guess member function types
    pub fn is_memfunc(&self) -> bool {
        self.0 & 0x00008000 != 0
    }
    /// Truncate functions upon code deletion
    pub fn is_trfunc(&self) -> bool {
        self.0 & 0x00010000 != 0
    }

    /// Create string literal if data xref exists
    pub fn is_strlit(&self) -> bool {
        self.0 & 0x00020000 != 0
    }
    /// Check for unicode strings
    pub fn is_chkuni(&self) -> bool {
        self.0 & 0x00040000 != 0
    }
    /// Create offsets and segments using fixup info
    pub fn is_fixup(&self) -> bool {
        self.0 & 0x00080000 != 0
    }
    /// Create offset if data xref to seg32 exists
    pub fn is_drefoff(&self) -> bool {
        self.0 & 0x00100000 != 0
    }
    /// Convert 32bit instruction operand to offset
    pub fn is_immoff(&self) -> bool {
        self.0 & 0x00200000 != 0
    }
    /// Automatically convert data to offsets
    pub fn is_datoff(&self) -> bool {
        self.0 & 0x00400000 != 0
    }

    /// Use flirt signatures
    pub fn is_flirt(&self) -> bool {
        self.0 & 0x00800000 != 0
    }
    /// Append a signature name comment for recognized anonymous library functions
    pub fn is_sigcmt(&self) -> bool {
        self.0 & 0x01000000 != 0
    }
    /// Allow recognition of several copies of the same function
    pub fn is_sigmlt(&self) -> bool {
        self.0 & 0x02000000 != 0
    }
    /// Automatically hide library functions
    pub fn is_hflirt(&self) -> bool {
        self.0 & 0x04000000 != 0
    }

    /// Rename jump functions as j_...
    pub fn is_jfunc(&self) -> bool {
        self.0 & 0x08000000 != 0
    }
    /// Rename empty functions as nullsub_...
    pub fn is_nullsub(&self) -> bool {
        self.0 & 0x10000000 != 0
    }

    /// Coagulate data segs at the final pass
    pub fn is_dodata(&self) -> bool {
        self.0 & 0x20000000 != 0
    }
    /// Coagulate code segs at the final pass
    pub fn is_docode(&self) -> bool {
        self.0 & 0x40000000 != 0
    }
    /// Final pass of analysis
    pub fn is_final(&self) -> bool {
        self.0 & 0x80000000 != 0
    }

    /// Handle EH information
    pub fn is_doeh(&self) -> bool {
        self.1 & 0x1 != 0
    }
    /// Handle RTTI information
    pub fn is_dortti(&self) -> bool {
        self.1 & 0x2 != 0
    }
    /// Try to combine several instructions
    pub fn is_macro(&self) -> bool {
        self.1 & 0x4 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct XRef(u8);
impl XRef {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid XRef flag");
        Ok(Self(value))
    }
    /// show segments in xrefs?
    pub fn is_segxrf(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// show xref type marks?
    pub fn is_xrfmrk(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// show function offsets?
    pub fn is_xrffnc(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// show xref values? (otherwise-"...")
    pub fn is_xrfval(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NameType {
    RelOff,
    PtrOff,
    NamOff,
    RelEa,
    PtrEa,
    NamEa,
    Ea,
    Ea4,
    Ea8,
    Short,
    Serial,
}

// InnerRef: 8e6e20
impl NameType {
    fn new(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::RelOff,
            1 => Self::PtrOff,
            2 => Self::NamOff,
            3 => Self::RelEa,
            4 => Self::PtrEa,
            5 => Self::NamEa,
            6 => Self::Ea,
            7 => Self::Ea4,
            8 => Self::Ea8,
            9 => Self::Short,
            10 => Self::Serial,
            _ => return None,
        })
    }
}

// InnerRef: 8e6de0
#[derive(Debug, Clone, Copy)]
pub enum DemNamesForm {
    /// display demangled names as comments
    Cmnt,
    /// display demangled names as regular names
    Name,
    /// don't display demangled names
    None,
}

#[derive(Clone, Copy, Debug)]
pub struct DemName(u8);
impl DemName {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid DemName flag");
        ensure!(value != 0x3);
        Ok(Self(value))
    }
    pub fn name_form(&self) -> DemNamesForm {
        match self.0 & 0x3 {
            0 => DemNamesForm::Cmnt,
            1 => DemNamesForm::Name,
            2 => DemNamesForm::None,
            _ => unreachable!(),
        }
    }

    /// assume gcc3 names (valid for gnu compiler)
    pub fn is_gcc3(&self) -> bool {
        self.0 & 0x4 != 0
    }

    /// override type info
    pub fn override_type_info(&self) -> bool {
        self.0 & 0x8 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ListName(u8);
impl ListName {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid ListName flag");
        Ok(Self(value))
    }
    /// include normal names
    pub fn is_normal(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// include public names
    pub fn is_public(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// include autogenerated names
    pub fn is_auto(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// include weak names
    pub fn is_weak(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OutputFlags(u16);
impl OutputFlags {
    fn new(value: u32) -> Result<Self> {
        ensure!(value < 0x800);
        Ok(Self(value as u16))
    }
    /// Display void marks?
    pub fn show_void(&self) -> bool {
        self.0 & 0x002 != 0
    }
    /// Display autoanalysis indicator?
    pub fn show_auto(&self) -> bool {
        self.0 & 0x004 != 0
    }
    /// Generate empty lines?
    pub fn gen_null(&self) -> bool {
        self.0 & 0x010 != 0
    }
    /// Show line prefixes?
    pub fn show_pref(&self) -> bool {
        self.0 & 0x020 != 0
    }
    /// line prefixes with segment name?
    pub fn is_pref_seg(&self) -> bool {
        self.0 & 0x040 != 0
    }
    /// generate leading zeroes in numbers
    pub fn gen_lzero(&self) -> bool {
        self.0 & 0x080 != 0
    }
    /// Generate 'org' directives?
    pub fn gen_org(&self) -> bool {
        self.0 & 0x100 != 0
    }
    /// Generate 'assume' directives?
    pub fn gen_assume(&self) -> bool {
        self.0 & 0x200 != 0
    }
    /// Generate try/catch directives?
    pub fn gen_tryblks(&self) -> bool {
        self.0 & 0x400 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CommentOptions(u8);
impl CommentOptions {
    fn new(value: u8) -> Self {
        Self(value)
    }
    /// show repeatable comments?
    pub fn is_rptcmt(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// comment all lines?
    pub fn is_allcmt(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// no comments at all
    pub fn is_nocmt(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// show source line numbers
    pub fn is_linnum(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// testida.idc is running
    pub fn is_testmode(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// show hidden instructions
    pub fn is_shhid_item(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// show hidden functions
    pub fn is_shhid_func(&self) -> bool {
        self.0 & 0x40 != 0
    }
    /// show hidden segments
    pub fn is_shhid_segm(&self) -> bool {
        self.0 & 0x80 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DelimiterOptions(u8);
impl DelimiterOptions {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x08);
        Ok(Self(value))
    }
    /// thin borders
    pub fn is_thin(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// thick borders
    pub fn is_thick(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// empty lines at the end of basic blocks
    pub fn is_empty(&self) -> bool {
        self.0 & 0x04 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LinePrefixOptions(u8);
impl LinePrefixOptions {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x10, "Invalid LinePrefixOptions");
        Ok(Self(value))
    }
    /// show segment addresses?
    pub fn is_segadr(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// show function offsets?
    pub fn is_fncoff(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// show stack pointer?
    pub fn is_stack(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// truncate instruction bytes if they would need more than 1 line
    pub fn is_pfxtrunc(&self) -> bool {
        self.0 & 0x08 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StrLiteralFlags(u8);
impl StrLiteralFlags {
    fn new(value: u8) -> Result<Self> {
        ensure!(value < 0x40);
        Ok(Self(value))
    }
    /// generate names?
    pub fn is_gen(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// names have 'autogenerated' bit?
    pub fn is_auto(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// generate serial names?
    pub fn is_serial(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// unicode strings are present?
    pub fn is_unicode(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// generate auto comment for string references?
    pub fn is_comment(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// preserve case of strings for identifiers
    pub fn is_savecase(&self) -> bool {
        self.0 & 0x20 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AbiOptions(u16);
impl AbiOptions {
    fn new(value: u32) -> Result<Self> {
        ensure!(value < 0x400);
        Ok(Self(value as u16))
    }
    /// 4 byte alignment for 8byte scalars (__int64/double) inside structures?
    pub fn is_8align4(&self) -> bool {
        self.0 & 0x001 != 0
    }
    /// do not align stack arguments to stack slots
    pub fn is_pack_stkargs(&self) -> bool {
        self.0 & 0x002 != 0
    }
    /// use natural type alignment for argument if the alignment exceeds native word size.
    /// (e.g. __int64 argument should be 8byte aligned on some 32bit platforms)
    pub fn is_bigarg_align(&self) -> bool {
        self.0 & 0x004 != 0
    }
    /// long double arguments are passed on stack
    pub fn is_stack_ldbl(&self) -> bool {
        self.0 & 0x008 != 0
    }
    /// varargs are always passed on stack (even when there are free registers)
    pub fn is_stack_varargs(&self) -> bool {
        self.0 & 0x010 != 0
    }
    /// use the floating-point register set
    pub fn is_hard_float(&self) -> bool {
        self.0 & 0x020 != 0
    }
    /// compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
    pub fn is_set_by_user(&self) -> bool {
        self.0 & 0x040 != 0
    }
    /// use gcc layout for udts (used for mingw)
    pub fn is_gcc_layout(&self) -> bool {
        self.0 & 0x080 != 0
    }
    /// register arguments are mapped to stack area (and consume stack slots)
    pub fn is_map_stkargs(&self) -> bool {
        self.0 & 0x100 != 0
    }
    /// use natural type alignment for an argument even if its alignment exceeds double
    /// native word size (the default is to use double word max).
    /// e.g. if this bit is set, __int128 has 16-byte alignment.
    /// This bit is not used by ida yet
    pub fn is_hugearg_align(&self) -> bool {
        self.0 & 0x200 != 0
    }
}

// InnerRef: 8e6ee0
#[derive(Debug, Clone)]
pub enum FileType {
    Raw,
    MsdosDriver,
    Ne,
    IntelHex,
    Mex,
    Lx,
    Le,
    Nlm,
    Coff,
    Pe,
    Omf,
    RRecords,
    Zip,
    Omflib,
    Ar,
    LoaderSpecific,
    Elf,
    W32run,
    Aout,
    Palmpilot,
    MsdosExe,
    MsdosCom,
    Aixar,
    Macho,
    Psxobj,
}

impl FileType {
    fn from_value(value: u16) -> Option<Self> {
        Some(match value {
            0x2 => Self::Raw,
            0x3 => Self::MsdosDriver,
            0x4 => Self::Ne,
            0x5 => Self::IntelHex,
            0x6 => Self::Mex,
            0x7 => Self::Lx,
            0x8 => Self::Le,
            0x9 => Self::Nlm,
            0xA => Self::Coff,
            0xB => Self::Pe,
            0xC => Self::Omf,
            0xD => Self::RRecords,
            0xE => Self::Zip,
            0xF => Self::Omflib,
            0x10 => Self::Ar,
            0x11 => Self::LoaderSpecific,
            0x12 => Self::Elf,
            0x13 => Self::W32run,
            0x14 => Self::Aout,
            0x15 => Self::Palmpilot,
            0x16 => Self::MsdosExe,
            0x17 => Self::MsdosCom,
            0x18 => Self::Aixar,
            0x19 => Self::Macho,
            0x1A => Self::Psxobj,
            _ => return None,
        })
    }
}

// InnerRef: 8e6cc0
#[derive(Debug, Clone)]
pub enum Compiler {
    Unknown,
    VisualStudio,
    Borland,
    Watcom,
    Gnu,
    VisualAge,
    Delphi,
}

impl Compiler {
    pub fn from_value(value: u8) -> Option<Self> {
        Some(match value {
            0x0 => Self::Unknown,
            0x1 => Self::VisualStudio,
            0x2 => Self::Borland,
            0x3 => Self::Watcom,
            0x6 => Self::Gnu,
            0x7 => Self::VisualAge,
            0x8 => Self::Delphi,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
enum ID0TreeEntry {
    Index {
        preceeding: Box<ID0TreeEntry>,
        index: Vec<ID0TreeIndex>,
    },
    Leaf(Vec<ID0Entry>),
}

#[derive(Debug, Clone)]
struct ID0TreeIndex {
    page: Box<ID0TreeEntry>,
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
enum ID0TreeEntrRaw {
    Index {
        preceeding: NonZeroU32,
        entries: Vec<ID0TreeIndexRaw>,
    },
    Leaf(Vec<ID0Entry>),
}

#[derive(Debug, Clone)]
struct ID0TreeIndexRaw {
    page: Option<NonZeroU32>,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ID0TreeEntrRaw {
    fn read(page: &[u8], header: &ID0Header) -> Result<Self> {
        match header.version {
            ID0Version::V15 => Self::read_xx(
                page,
                header,
                4,
                Self::header_4,
                Self::index_header_4,
                Self::leaf_header_v15,
                Self::index_value_v1x,
                Self::leaf_value_v1x,
                Self::freeptr_v1x,
            ),
            ID0Version::V16 => Self::read_xx(
                page,
                header,
                6,
                Self::header_6,
                Self::index_header_6,
                Self::leaf_header_v16,
                Self::index_value_v1x,
                Self::leaf_value_v1x,
                Self::freeptr_v1x,
            ),
            ID0Version::V20 => Self::read_xx(
                page,
                header,
                6,
                Self::header_6,
                Self::index_header_6,
                Self::leaf_header_v20,
                Self::index_value_v20,
                Self::leaf_value_v20,
                Self::freeptr_v20,
            ),
        }
    }

    fn read_xx(
        page: &[u8],
        id0_header: &ID0Header,
        entry_len: u16,
        header: fn(&mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)>,
        index_header: fn(&mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)>,
        leaf_header: fn(&mut Cursor<&[u8]>) -> Result<(u16, u16)>,
        index_value: fn(&mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)>,
        leaf_value: fn(&mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)>,
        freeptr: fn(&mut Cursor<&[u8]>) -> Result<u16>,
    ) -> Result<Self> {
        let mut input = Cursor::new(page);
        let (preceeding, count) = header(&mut input)?;
        let min_data_pos = entry_len
            .checked_mul(count + 2)
            .ok_or_else(|| anyhow!("Invalid number of entries"))?;
        ensure!(min_data_pos <= id0_header.page_size);

        let mut data_offsets = (entry_len..).step_by(entry_len.into());
        let entry_offsets = (&mut data_offsets).take(count.into());
        let entry = if let Some(preceeding) = preceeding {
            // index
            let entries = entry_offsets
                .map(|offset| {
                    input.seek(SeekFrom::Start(offset.into())).unwrap();
                    let (page, recofs) = index_header(&mut input)?;
                    ensure!(
                        recofs >= min_data_pos,
                        "Invalid recofs value {recofs} >= {min_data_pos}"
                    );
                    ensure!(recofs < id0_header.page_size);
                    input.seek(SeekFrom::Start(recofs.into())).unwrap();
                    let (key, value) = index_value(&mut input)?;
                    Ok(ID0TreeIndexRaw { page, key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0TreeEntrRaw::Index {
                preceeding,
                entries,
            }
        } else {
            // leaf
            // keys are usually very similar to one another, so it reuses the last key
            // value to build the next
            let mut last_key = Vec::new();
            let entry = entry_offsets
                .map(|offset| {
                    input.seek(SeekFrom::Start(offset.into())).unwrap();
                    let (indent, recofs) = leaf_header(&mut input)?;
                    if recofs == 0 {
                        // TODO this only happen in deleted entries?
                        // TODO have an option to diferenciate?
                        return Ok(ID0Entry {
                            key: vec![],
                            value: vec![],
                        });
                    }
                    ensure!(
                        recofs >= min_data_pos,
                        "Invalid recofs value {recofs} >= {min_data_pos}"
                    );
                    ensure!(recofs < id0_header.page_size);
                    input.seek(SeekFrom::Start(recofs.into())).unwrap();
                    let (ext_key, value) = leaf_value(&mut input)?;

                    // keys may reutilize the start of the last key
                    let reused_key = last_key
                        .get(..indent.into())
                        .ok_or_else(|| anyhow!("key indent is too small"))?;
                    let key: Vec<u8> = reused_key.iter().copied().chain(ext_key).collect();

                    // update the last key
                    last_key.clear();
                    last_key.extend(&key);

                    Ok(ID0Entry { key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0TreeEntrRaw::Leaf(entry)
        };

        input
            .seek(SeekFrom::Start(data_offsets.next().unwrap().into()))
            .unwrap();
        // TODO what is the freeptr?
        let _freeptr = freeptr(&mut input)?;
        Ok(entry)
    }

    fn header_4(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let preceeding: u16 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceeding.into()), count))
    }

    fn header_6(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let preceeding: u32 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceeding), count))
    }

    fn index_header_4(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page.into()), recofs))
    }

    fn index_header_6(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u32 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page), recofs))
    }

    fn leaf_header_v15(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v16(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        // TODO is this _unknown1 just part of indent (u16)?
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown2: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v20(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u16 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent, recofs))
    }

    fn index_value_v1x(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown: u8 = bincode::deserialize_from(&mut *input)?;
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn index_value_v20(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn leaf_value_v1x(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown: u8 = bincode::deserialize_from(&mut *input)?;
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn leaf_value_v20(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn freeptr_v1x(input: &mut Cursor<&[u8]>) -> Result<u16> {
        let _unknown: u16 = bincode::deserialize_from(&mut *input)?;
        let freeptr: u16 = bincode::deserialize_from(input)?;
        Ok(freeptr)
    }

    fn freeptr_v20(input: &mut Cursor<&[u8]>) -> Result<u16> {
        let _unknown: u32 = bincode::deserialize_from(&mut *input)?;
        let freeptr: u16 = bincode::deserialize_from(input)?;
        Ok(freeptr)
    }
}

fn read_exact_or_nothing<R: std::io::Read + ?Sized>(
    this: &mut R,
    mut buf: &mut [u8],
) -> std::io::Result<usize> {
    let len = buf.len();
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(len - buf.len())
}

fn read_word<I: Read>(input: I, is_64: bool) -> Result<u64> {
    if is_64 {
        Ok(bincode::deserialize_from(input)?)
    } else {
        Ok(bincode::deserialize_from::<_, u32>(input).map(u64::from)?)
    }
}

fn parse_word<I: Read>(input: &mut I, is_64: bool) -> Result<u64> {
    if is_64 {
        parse_u64(input)
    } else {
        parse_u32(input).map(u64::from)
    }
}

fn parse_u8<I: Read>(input: &mut I) -> Result<u8> {
    Ok(bincode::deserialize_from(&mut *input)?)
}

/// Reads 1 to 3 bytes.
fn parse_u16<I: Read>(input: &mut I) -> Result<u16> {
    let b1: u8 = bincode::deserialize_from(&mut *input)?;
    match b1 {
        // 16 bits value
        // [1111 1111] xxxx xxxx xxxx xxxx
        0xFF => {
            let value: [u8; 2] = bincode::deserialize_from(&mut *input)?;
            Ok(u16::from_be_bytes(value))
        }
        // 7 bit value
        // [0xxx xxxx]
        ..0x80 => Ok(b1.into()),
        // 14 bits value
        // [1xxx xxxx] xxxx xxxx
        0x80.. => {
            let lo: u8 = bincode::deserialize_from(&mut *input)?;
            Ok(u16::from_be_bytes([b1 & 0x3F, lo]))
        }
    }
}

/// Reads 1 to 5 bytes.
fn parse_u32<I: Read>(input: &mut I) -> Result<u32> {
    let b1: u8 = bincode::deserialize_from(&mut *input)?;
    match b1 {
        // 32 bits value
        // [1111 1111] xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx
        0xFF => Ok(u32::from_be_bytes(bincode::deserialize_from(&mut *input)?)),
        // 7 bit value
        // [0xxx xxxx]
        ..0x80 => Ok(b1.into()),
        // 14 bits value
        // [10xx xxxx] xxxx xxxx
        0x80..0xC0 => {
            let lo: u8 = bincode::deserialize_from(&mut *input)?;
            Ok(u32::from_be_bytes([0, 0, b1 & 0x3F, lo]))
        }
        // 29 bit value:
        // [11xx xxxx] xxxx xxxx xxxx xxxx xxxx xxxx
        0xC0.. => {
            let bytes: [u8; 3] = bincode::deserialize_from(&mut *input)?;
            Ok(u32::from_be_bytes([
                b1 & 0x1F,
                bytes[0],
                bytes[1],
                bytes[2],
            ]))
        }
    }
}

/// Reads 2 to 10 bytes.
fn parse_u64<I: Read>(input: &mut I) -> Result<u64> {
    let lo = parse_u32(&mut *input)?;
    let hi = parse_u32(&mut *input)?;
    Ok((u64::from(hi) << 32) | u64::from(lo))
}

fn parse_number(data: &[u8], big_endian: bool, is_64: bool) -> Option<u64> {
    Some(match (data.len(), is_64, big_endian) {
        (8, true, true) => u64::from_be_bytes(data.try_into().unwrap()),
        (8, true, false) => u64::from_le_bytes(data.try_into().unwrap()),
        (4, false, true) => u32::from_be_bytes(data.try_into().unwrap()).into(),
        (4, false, false) => u32::from_le_bytes(data.try_into().unwrap()).into(),
        _ => return None,
    })
}

// parse a string that maybe is finilized with \x00
fn parse_maybe_cstr(data: &[u8]) -> Option<&str> {
    // find the end of the string
    let end_pos = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    // make sure there is no data after the \x00
    if data[end_pos..].iter().any(|b| *b != 0) {
        return None;
    }
    core::str::from_utf8(&data[0..end_pos]).ok()
}
