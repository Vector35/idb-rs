# IDB format

The IDA Database (IDB) is the main file used by IDA to store the project information,
it works mostly works as a packager,
packing and optionally compressing the information itself.
There are 6 known information sources stored in the IDB file,
those are packed on the IDB as sections: ID0, ID1, ID2, NAM, TIL and SEG,
they are described in more details below.

Although the IDA can be 32 or 64 bits,
the IDB file itself doesn't vary with bitness,
only version affect the IDB format.
The bitness only affect the data stored inside the sections, except for TIL.


There are three main kinds of IDB files:
* V0, created by older version, around version 5.0 and prior.
* V1, V3 and V4, used between around version 5.0 and 6.0, NOTE V2 is unknown.
* V5 and V6, used between around version 6.0 and 9.0.
* V910 used after version 9.1

Those kinds of IDB files can be divided in two main layouts:

#### Pre 9.1

This layout pack each section is packed and compressed separately,
The header stored the offset of each section, so they can be in an arbitrary,
as shown on the layout bellow.

```txt
[file header with the offset of each section]
[section2 - compressed or not]
[sectionN - compressed or not]
[section3 - compressed or not]
[section1 - compressed or not]
```

Unpacking the IDB file is not required, because each section is compressed
independently,
this allow all sections to be read directly from the IDB file.

#### Post 9.1

The header will only contains the sections uncompressed size,
and they are in a fixed order.
All the sections are compressed in a single data stream.

```txt
[file header with the size of each section]
[compressed stream
  [section1]
  [section2]
  [section3]
  [sectionN]
]
```

This don't allow to read the sections directly from the IDB file if they are
compressed,
because to access any sections (other then the first) requires to decompress
all the previous ones,
Requiring the unpacking of the IDB file, into "work" files, like IDA does.

The known extensions of those files are `*.idb` for 32bits version and
`*.i64` for the 64bits version.
Although this rules seems only not to be followed by the fist versions to
implement IDA 64bits.
The only sure way to check if a file is 32/64bits is to check the magic,
if IDA0/IDA1 then 32bits, if IDA2 64bits

NOTE: The `section` word is this doc refer to a section of data of the IDB file,
and a `binary-section` is the section of data or the original
binary (elf, dll, exe) file.


## Sections

The IDB file contains the following sections:

* ID0: Database with most of the metadata.
* ID1: Binary data and information for each byte in certain ranges.
* ID2: Binary data and information for a few bytes in certain ranges.
* NAM: Some kind a "cache" for labels.
* TIL: Database for local types and symbols.
* SEG: Unknown data, only older versions of IDA contains this section.


### ID0

The main database of the project, it contains a list of key and values.

It's stored in a btree format, but if you want care about the parsed ID0,
it's just a Vector with each entry being `{key: Vec<u8>, value: Vec<u8>}`,
the vectors is sorted by key.

It's stored in to btree structure, the sections is divided into pages (usually 0x2000 bytes).
Each page start will contain 0 or more btree entries, each one being a node (points to other pages) or leaf (points to just data).

It's possible that this database contains garbage in some situations,
consequently it should not always be read directly,
usually is used in conjunction with ID1/ID2.
This is probably consequence of IDA being very old and avoiding writing to the
database for each change,
relying instead into changing only flags in ID1/ID2 and only "garbage collecting"
on demand.


### ID1

The bytes and bytes individual information loaded from the original binary file.

It's store sequentially with a page size of (0x2000, aligned or not depending on the version) and the parsed output is just a list of binary-section.
Each binary-sections start at a specific offset, have all the raw bytes of the binary-section, it also include 24bits of unknown information for each byte.

It's possible that some data of this section is not parsed, because it's was seeing in some examples of extra data stored after all the binary-sections are parsed.
Although this is possibly some vestigial data from the original binary.


### ID2

Similar to ID1, but contains information for only a few bytes of the range.
It's a sparse version of ID1.


### NAM

The Nam section contains memory address, is known to point to labels.

It's probably used as a cache to speed up the search and goto.


### TIL

The section contains types/macros information for local types.

This sections format is also used as a stand alone file,
this file is used to describe system libs,
including information about types, symbols and macros information,
like win32, gcc, libc, etc.

NOTE: All IDA versions include a `til` directory in it's installation folder with multiple til files, those can be used for testing.


### SEG

The contents of this data each format is not known at the time.
