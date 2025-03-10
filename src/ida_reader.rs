use anyhow::{anyhow, ensure, Result};

use std::io::{BufRead, ErrorKind, Read};
use std::ops::Range;

use crate::til::{TypeAttribute, TypeAttributeExt};
use crate::{IDAKind, IDAUsize};

pub trait IdbRead: Read {
    fn read_u8(&mut self) -> Result<u8> {
        let mut data = [0; 1];
        self.read_exact(&mut data)?;
        Ok(data[0])
    }

    #[cfg(not(feature = "restrictive"))]
    fn read_u8_or_nothing(&mut self) -> Result<Option<u8>> {
        let mut data = [0; 1];
        let read = self.read_exact_or_nothing(&mut data)?;
        Ok((read == data.len()).then_some(data[0]))
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut data = [0; 2];
        self.read_exact(&mut data)?;
        Ok(u16::from_le_bytes(data))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut data = [0; 4];
        self.read_exact(&mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut data = [0; 8];
        self.read_exact(&mut data)?;
        Ok(u64::from_le_bytes(data))
    }

    // read exac number of bytes, Eof (Nothing) or error
    fn read_exact_or_nothing(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(len - buf.len())
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46b610 unpack_dw
    // NOTE: the original implementation never fails, if input hit EoF it a partial result or 0
    /// Reads 1 to 3 bytes.
    fn unpack_dw(&mut self) -> Result<u16> {
        #[cfg(feature = "restrictive")]
        let b1 = self.read_u8()?;
        #[cfg(not(feature = "restrictive"))]
        let Some(b1) = self.read_u8_or_nothing()?
        else {
            return Ok(0);
        };
        match b1 {
            // 7 bit value
            // [0xxx xxxx]
            0x00..=0x7F => Ok(b1.into()),
            // 14 bits value
            // [10xx xxxx] xxxx xxxx
            0x80..=0xBF => {
                #[cfg(feature = "restrictive")]
                let lo = self.read_u8()?;
                #[cfg(not(feature = "restrictive"))]
                let lo = self.read_u8_or_nothing()?.unwrap_or(0);
                Ok(u16::from_be_bytes([b1 & 0x3F, lo]))
            }
            // 16 bits value
            // [11XX XXXX] xxxx xxxx xxxx xxxx
            0xC0..=0xFF => {
                // NOTE first byte 6 bits seems to be ignored
                //ensure!(header != 0xC0 && header != 0xFF);
                #[cfg(feature = "restrictive")]
                let (lo, hi) = (self.read_u8()?, self.read_u8()?);

                #[cfg(not(feature = "restrictive"))]
                let (lo, hi) = (
                    self.read_u8_or_nothing()?.unwrap_or(0),
                    self.read_u8_or_nothing()?.unwrap_or(0),
                );

                Ok(u16::from_be_bytes([lo, hi]))
            }
        }
    }

    // InnerRef b47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46b690 unpack_dd
    // NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
    /// Reads 1 to 5 bytes.
    fn unpack_dd(&mut self) -> Result<u32> {
        let b1 = self.read_u8()?;
        self.unpack_dd_from_byte(b1)
    }

    fn unpack_dd_from_byte(&mut self, b1: u8) -> Result<u32> {
        match b1 {
            // 7 bit value
            // [0xxx xxxx]
            0x00..=0x7F => Ok(b1.into()),
            // 14 bits value
            // [10xx xxxx] xxxx xxxx
            0x80..=0xBF => {
                #[cfg(feature = "restrictive")]
                let lo = self.read_u8()?;
                #[cfg(not(feature = "restrictive"))]
                let lo = self.read_u8_or_nothing()?.unwrap_or(0);
                Ok(u32::from_be_bytes([0, 0, b1 & 0x3F, lo]))
            }
            // 29 bit value:
            // [110x xxxx] xxxx xxxx xxxx xxxx xxxx xxxx
            0xC0..=0xDF => {
                let mut bytes: [u8; 3] = [0; 3];
                #[cfg(feature = "restrictive")]
                self.read_exact(&mut bytes)?;
                #[cfg(not(feature = "restrictive"))]
                let _size = self.read_exact_or_nothing(&mut bytes)?;
                Ok(u32::from_be_bytes([
                    b1 & 0x1F,
                    bytes[0],
                    bytes[1],
                    bytes[2],
                ]))
            }
            // 32 bits value
            // [111X XXXX] xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx
            0xE0..=0xFF => {
                // NOTE first byte 5 bits seems to be ignored
                //ensure!(header != 0xE0 && header != 0xFF);
                let mut bytes: [u8; 4] = [0; 4];
                #[cfg(feature = "restrictive")]
                self.read_exact(&mut bytes)?;
                #[cfg(not(feature = "restrictive"))]
                let _size = self.read_exact_or_nothing(&mut bytes)?;
                Ok(u32::from_be_bytes(bytes))
            }
        }
    }

    ///// unpack 32bits, extending the max value if equal to u32::MAX
    //fn unpack_dd_ext_max(&mut self) -> Result<u64> {
    //    match self.unpack_dd()? {
    //        u32::MAX => Ok(u64::MAX),
    //        value => Ok(u64::from(value)),
    //    }
    //}

    // InnerRef b47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46b7b0 unpack_dq
    // NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
    /// Reads 2 to 10 bytes.
    fn unpack_dq(&mut self) -> Result<u64> {
        let lo = self.unpack_dd()?;
        let hi = self.unpack_dd()?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x46b7e0 unpack_ds
    // NOTE: the original implementation never fails, if input hit EoF it a partial result or 0
    fn unpack_ds(&mut self) -> Result<Vec<u8>> {
        let len = self.unpack_dd()?;
        let mut result = vec![0; len.try_into()?];
        #[cfg(feature = "restrictive")]
        self.read_exact(&mut result)?;
        #[cfg(not(feature = "restrictive"))]
        let _size = self.read_exact_or_nothing(&mut result)?;
        Ok(result)
    }

    fn unpack_dt_bytes(&mut self) -> Result<Vec<u8>> {
        let buf_len = self.read_dt()?;
        let mut buf = vec![0; buf_len.into()];
        #[cfg(feature = "restrictive")]
        self.read_exact(&mut buf)?;
        #[cfg(not(feature = "restrictive"))]
        let _size = self.read_exact_or_nothing(&mut buf)?;
        Ok(buf)
    }

    /// Reads 1 to 5 bytes
    /// Value Range: 0-0xFFFFFFFF
    /// Usage: Enum Deltas
    fn read_de(&mut self) -> Result<u32> {
        // TODO check if the implementation is complete
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cdb0
        let mut acc: u32 = 0;
        for _ in 0..5 {
            #[cfg(feature = "restrictive")]
            let b = self.read_u8()?;
            #[cfg(not(feature = "restrictive"))]
            let Some(b) = self.read_u8_or_nothing()?
            else {
                return Ok(acc);
            };
            if b & 0x80 == 0 {
                acc = (b & 0x3F) as u32 | (acc << 6);
                return Ok(acc);
            }

            acc = (acc << 7) | (b & 0x7F) as u32;
        }
        Err(anyhow!("Can't find the end of DE"))
    }

    /// Reads 1 or 2 bytes.
    /// Value Range: 0-0xFFFE
    /// Usage: 16bit numbers
    fn read_dt(&mut self) -> Result<u16> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cd60
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x4514b
        let value = match self.read_u8()? {
            #[cfg(feature = "restrictive")]
            0 => return Err(anyhow!("DT can't have 0 value")),
            #[cfg(not(feature = "restrictive"))]
            0 => return Ok(0),
            //SEG = 2
            value @ 0x80.. => {
                #[cfg(feature = "restrictive")]
                let inter = self.read_u8()?;
                #[cfg(not(feature = "restrictive"))]
                let inter = self.read_u8_or_nothing()?.unwrap_or(0);
                #[cfg(feature = "restrictive")]
                ensure!(inter != 0, "DT can't have a following 0 value");
                value as u16 & 0x7F | (inter as u16) << 7
            }
            //SEG = 1
            value @ ..=0x7F => value.into(),
        };
        Ok(value - 1)
    }

    fn serialize_dt(value: u16) -> Result<Vec<u8>> {
        if value > 0x7FFE {
            return Err(anyhow!("Invalid value for DT"));
        }
        let lo = value + 1;
        let mut hi = value + 1;
        let mut result: Vec<u8> = Vec::with_capacity(2);
        if lo > 127 {
            result.push((lo & 0x7F | 0x80) as u8);
            hi = (lo >> 7) & 0xFF;
        }
        result.push(hi as u8);
        Ok(result)
    }

    /// Reads 2 to 7 bytes.
    /// Value Range: Nothing or 0-0xFFFF_FFFF
    /// Usage: some kind of size
    fn read_dt_de(&mut self) -> Result<Option<(u32, bool)>> {
        // TODO the return is always NonZero?
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cf20
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x451670
        match self.read_dt()? {
            0 => Ok(None),
            0x7FFE => self.read_de().map(|x| Some((x, x >> 3 == 0))),
            n => Ok(Some((n.into(), false))),
        }
    }

    fn read_type_attribute(&mut self) -> Result<TypeAttribute> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452830
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x2fbf90
        use crate::til::flag::tattr_ext::*;
        #[cfg(feature = "restrictive")]
        let byte0 = self.read_u8()?;
        #[cfg(not(feature = "restrictive"))]
        let Some(byte0) = self.read_u8_or_nothing()?
        else {
            return Ok(TypeAttribute {
                tattr: 0,
                extended: None,
            });
        };
        let mut tattr = 0;
        if byte0 != 0xfe {
            tattr = ((byte0 as u16 & 1) | ((byte0 as u16 >> 3) & 6)) + 1;
        }
        if byte0 == 0xFE || tattr == 8 {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452878
            let mut shift = 0;
            // TODO limit the loop to only 0..n
            loop {
                #[cfg(feature = "restrictive")]
                let next_byte = self.read_u8()?;
                #[cfg(not(feature = "restrictive"))]
                let Some(next_byte) = self.read_u8_or_nothing()?
                else {
                    break;
                };
                ensure!(
                    next_byte != 0,
                    "Failed to parse TypeAttribute, byte is zero"
                );
                tattr |= ((next_byte & 0x7F) as u16) << shift;
                if next_byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
                ensure!(
                    shift < u16::BITS,
                    "Failed to find the end of type attribute"
                );
            }
        }

        if tattr & TAH_HASATTRS == 0 {
            return Ok(TypeAttribute {
                tattr,
                extended: None,
            });
        }
        // consume this flag
        tattr &= !TAH_HASATTRS;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x45289e
        let loop_cnt = self.read_dt()?;
        let extended = (0..loop_cnt)
            .map(|_| {
                let _value1 = self.unpack_dt_bytes()?;
                let _value2 = self.unpack_dt_bytes()?;
                // TODO maybe more...
                Ok(TypeAttributeExt { _value1, _value2 })
            })
            .collect::<Result<_>>()?;
        Ok(TypeAttribute {
            tattr,
            extended: Some(extended),
        })
    }

    fn read_bytes_len_u16(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u16()?;
        let mut bytes = vec![0u8; len.into()];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read_bytes_len_u8(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u8()?;
        let mut bytes = vec![0u8; len.into()];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl<R: Read> IdbRead for R {}

pub trait IdbBufRead: IdbRead + BufRead {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42ad36
    fn read_raw_til_type(&mut self, format: u32) -> Result<Vec<u8>> {
        let flags = self.read_u32()?;
        if flags == 0x7fff_fffe {
            // TODO find the type that have this flag
            let len = self.read_u32()?;
            let mut data = vec![0; 8 + len as usize];
            data[0..4].copy_from_slice(&flags.to_le_bytes());
            data[4..8].copy_from_slice(&len.to_le_bytes());
            self.read_exact(&mut data[8..])?;
            Ok(data)
        } else {
            let mut data = flags.to_le_bytes().to_vec();
            // skip name
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42ad58
            self.read_until(b'\x00', &mut data)?;

            // skip the ordinal number
            match (format, (flags >> 31) != 0) {
                // formats below 0x12 doesn't have 64 bits ord
                (0..=0x11, _) | (_, false) => {
                    data.extend(self.read_u32()?.to_le_bytes())
                }
                (_, true) => data.extend(self.read_u64()?.to_le_bytes()),
            }

            // skip the type itself
            self.read_until(b'\x00', &mut data)?;
            // skip the info field
            self.read_until(b'\x00', &mut data)?;
            // skip the cmt field
            self.read_until(b'\x00', &mut data)?;
            // skip the fieldcmts field
            self.read_until(b'\x00', &mut data)?;
            // skip the sclass
            data.push(self.read_u8()?);
            Ok(data)
        }
    }

    /// Reads 1 to 9 bytes.
    /// ValueRange: 0-0x7FFFFFFF, 0-0xFFFFFFFF
    /// Usage: Arrays
    fn read_da(&mut self) -> Result<(u8, u8)> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478620
        let mut a = 0;
        let mut b = 0;
        let mut da = 0;
        let mut base = 0;
        let mut nelem = 0;
        // TODO check no more then 9 bytes are read
        loop {
            let Some(typ) = self.peek_u8()? else {
                #[cfg(feature = "restrictive")]
                return Err(anyhow!(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EoF on DA"
                )));
                #[cfg(not(feature = "restrictive"))]
                return Ok((nelem, base));
            };
            if typ & 0x80 == 0 {
                break;
            }
            self.consume(1);

            da = (da << 7) | typ & 0x7F;
            b += 1;
            if b >= 4 {
                let z: u8 = self.read_u8()?;
                if z != 0 {
                    base = (da << 4) | z & 0xF
                }
                nelem = (z >> 4) & 7;
                loop {
                    let Some(y) = self.peek_u8()? else {
                        #[cfg(feature = "restrictive")]
                        return Err(anyhow!(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Unexpected EoF on DA"
                        )));
                        #[cfg(not(feature = "restrictive"))]
                        return Ok((nelem, base));
                    };
                    if (y & 0x80) == 0 {
                        break;
                    }
                    self.consume(1);
                    nelem = (nelem << 7) | y & 0x7F;
                    a += 1;
                    if a >= 4 {
                        return Ok((nelem, base));
                    }
                }
            }
        }
        Ok((nelem, base))
    }

    // TODO rename this
    fn read_c_string_raw(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.read_until(b'\x00', &mut buf)?;
        // last char need to be \x00 or we found a EoF
        if let Some(b'\x00') = buf.last() {
            let _ = buf.pop(); // remove the \x00 from the end
        } else {
            // found EOF, aka could not find the \x00 for the string end
            #[cfg(feature = "restrictive")]
            return Err(anyhow!("Unexpected EoF on CStr"));
        }
        Ok(buf)
    }

    // TODO rename this
    fn read_c_string_vec(&mut self) -> Result<Vec<Vec<u8>>> {
        let buf = self.read_c_string_raw()?;
        split_strings_from_array(&buf)
            .ok_or_else(|| anyhow!("Invalid len on Vec of CStr {buf:02x?}"))
    }

    fn peek_u8(&mut self) -> Result<Option<u8>> {
        Ok(self.fill_buf()?.first().copied())
    }

    // InnerRef b47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46b690 unpack_dd
    // NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
    /// Reads 1 to 5 bytes.
    fn unpack_dd_or_eof(&mut self) -> Result<Option<u32>> {
        let Some(b1) = self.peek_u8()? else {
            return Ok(None);
        };
        self.consume(1);
        self.unpack_dd_from_byte(b1).map(Option::Some)
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48ce40
    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x451590
    fn read_ext_att(&mut self) -> Result<u64> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cec0
        // TODO this can't be found at InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x451590
        let start_value = match self.read_dt()? {
            0x400 => return Ok(-1i64 as u64),
            0x200 => return Ok(-1i32 as u64),
            other => other,
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48ce6f
        let mut acc = 0;
        for bit in 0..8 {
            let byte = bit * 8;
            if (start_value >> bit) & 1 != 0 {
                let value = self.read_u8()?;
                // TODO is this an error or expect possible value?
                #[cfg(feature = "restrictive")]
                ensure!(value != 0);
                acc |= (value as u64) << byte;
            }
        }

        if start_value & 0x100 != 0 {
            acc = !acc;
        }
        Ok(acc)
    }

    fn read_tah(&mut self) -> Result<Option<TypeAttribute>> {
        // TODO TAH in each type have a especial meaning, verify those
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x477080
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452830
        let Some(tah) = self.peek_u8()? else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on DA"
            )));
        };
        if tah == 0xFE {
            Ok(Some(self.read_type_attribute()?))
        } else {
            Ok(None)
        }
    }

    fn read_sdacl(&mut self) -> Result<Option<TypeAttribute>> {
        let Some(sdacl) = self.peek_u8()? else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on SDACL"
            )));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x477eff
        //NOTE: original op ((sdacl as u8 & 0xcf) ^ 0xC0) as i32 <= 0x01
        matches!(sdacl, 0xC0..=0xC1 | 0xD0..=0xD1 | 0xE0..=0xE1 | 0xF0..=0xF1)
            .then(|| self.read_type_attribute())
            .transpose()
    }
}

impl<R: BufRead> IdbBufRead for R {}

pub trait IdbReadKind<K: IDAKind>: IdbRead {
    fn read_usize(&mut self) -> Result<K::Usize>
    where
        Self: Sized,
    {
        <K::Usize as IDAUsize>::from_le_reader(self)
    }

    fn read_usize_be(&mut self) -> Result<K::Usize>
    where
        Self: Sized,
    {
        <K::Usize as IDAUsize>::from_be_reader(self)
    }

    fn unpack_usize(&mut self) -> Result<K::Usize>
    where
        Self: Sized,
    {
        <K::Usize as IDAUsize>::unpack_from_reader(self)
    }
    fn unpack_address_range(&mut self) -> Result<Range<K::Usize>>
    where
        Self: Sized,
    {
        // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x28f8cc
        let start = self.unpack_usize()?;
        let len = self.unpack_usize()?;
        // NOTE may not look right, but that's how ida does it
        #[cfg(feature = "restrictive")]
        let end = num_traits::CheckedAdd::checked_add(&start, &len)
            .ok_or_else(|| anyhow!("Function range overflows"))?;
        #[cfg(not(feature = "restrictive"))]
        let end = num_traits::Saturating::saturating_add(start, len);
        Ok(start..end)
    }
}

impl<R: Read, K: IDAKind> IdbReadKind<K> for R {}

pub fn split_strings_from_array(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    if buf.is_empty() {
        return Some(vec![]);
    }

    let mut result = vec![];
    let mut cursor = buf;
    loop {
        // TODO check innerref, maybe this is read_de
        let len = cursor.read_dt().ok()?;
        if cursor.len() < len.into() {
            return None;
        }
        let (value, rest) = cursor.split_at(len.into());
        result.push(value.to_owned());
        if rest.is_empty() {
            break;
        }
        cursor = rest;
    }
    Some(result)
}
