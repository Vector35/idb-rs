# IDB format

The idb format consist mainly of a header with the offsets of its sections.

Known extensions are `*.idb` for 32bits version and `*.i64` for the 64bits version.

NOTE: The `section` word is this doc refer to a section of data of the IDB file, and a `binary-section` is the section of data or the original binary (elf, dll, exe) file.

## File overview

```txt
IDB File             +-----------------------------------------------------------+
Start of the file    |[ File Header with offsets for all the sections ][ align  ]|
Offset for Section A |[ Section a Header | Sections A bytes......................|
                     |...........................................................|
End for Section A    |..........................................................]|
Offset for Section B |[ Section a Header | Sections B bytes......................|
                     |...........................................................|
End for Section B    |..........................................................]|
                     +-----------------------------------------------------------+
```


## Sections

The IDB file contains the following sections:

* ID0: Database with most of the metadata.
* ID1: Binary data and information about each byte.
* ID2: Unknown data.
* NAM: Unknown data.
* TIL: Database of types from known library.
* SEG: Unknown data.

Each section include a header with the size of it, so it's possible to ensure that sections don't overlap and once parsing the sections
all the data is parsed or if it contains left-unparsed data.


### ID0

The main database of the project, it contains a list of key and values.

It's stored in a btree format, but if you want care about the parsed ID0, it's just a Vector with each entry being `{key: Vec<u8>, value: Vec<u8>}`,
the vectors is sorted by key.

It's stored in to btree structure, the sections is divided into pages (usually 0x2000 bytes).
Each page start will contain 0 or more btree entries, each one being a node (points to other pages) or leaf (points to just data).

Each page have entries at the start and the offset of it's key/value also is relative to it's page, usually stored at the end of the page.

It's possible that some data of this section is not parsed, mostly because deleted data is not removed from the file, it's just left unlinked to btree.

Although the id0 data format is simple and very well understand, the data stored inside id0 can be very complex or unknown.


### ID1

The bytes and bytes individual information loaded from the original binary file.

It's store sequentially with a page size of (0x2000, aligned or not depending on the version) and the parsed output is just a list of binary-section.
Each binary-sections start at a specific offset, have all the raw bytes of the binary-section, it also include 24bits of unknown information for each byte.

It's possible that some data of this section is not parsed, because it's was seing in some examples of extra data stored after all the binary-sections are parsed.
Although this is possibly some vestigial data from the original binary.


### ID2

The contents of this data each format is not known at the time.


### NAM

The Nam sections is known to contain a list bytes, what this data means is unknown.

It's unlikely that data is left unparsed, mostly because the entire section is parsed, and any in-between data is enforced to be only zeroes.


### TIL

The section contains types/macros informations from external libs, like win32, gcc, libc, etc.

This section is most likely always fully parsed, because any extra data will result into error.

NOTE: All IDA versions include a `til` directory in it's instalation folder with multiple til files, those can be used for testing.


### SEG

The contents of this data each format is not known at the time.
