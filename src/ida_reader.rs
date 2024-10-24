use anyhow::{anyhow, ensure, Result};

use std::io::{BufRead, ErrorKind, Read, Seek};
use std::ops::Range;

pub trait IdbReader: Seek + IdaGenericBufUnpack {}
impl<R: Seek + IdaGenericBufUnpack> IdbReader for R {}

pub trait IdaUnpack: IdaGenericUnpack {
    fn is_64(&self) -> bool;

    // TODO rename to deserialize_usize
    fn read_word(&mut self) -> Result<u64> {
        if self.is_64() {
            Ok(bincode::deserialize_from(self)?)
        } else {
            Ok(bincode::deserialize_from::<_, u32>(self).map(u64::from)?)
        }
    }

    fn unpack_usize(&mut self) -> Result<u64> {
        if self.is_64() {
            self.unpack_dq()
        } else {
            self.unpack_dd().map(u64::from)
        }
    }

    // TODO unpack_address_ext
    /// unpack an address and extend to max address if 32bits and u32::MAX
    fn unpack_usize_ext_max(&mut self) -> Result<u64> {
        if self.is_64() {
            self.unpack_dq()
        } else {
            self.unpack_dd_ext_max().map(u64::from)
        }
    }

    // InnerRef fb47a09e-b8d8-42f7-aa80-2435c4d1e049 0x28f8cc
    fn unpack_address_range(&mut self) -> Result<Range<u64>> {
        if self.is_64() {
            let start = self.unpack_dq()?;
            let len = self.unpack_dq()?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| anyhow!("Function range overflows"))?;
            Ok(start..end)
        } else {
            let start = self.unpack_dd_ext_max()?;
            let len = self.unpack_dd()?;
            // NOTE may not look right, but that's how ida does it
            let end = match start.checked_add(len.into()) {
                Some(0xFFFF_FFFF) => u64::MAX,
                Some(value) => value,
                None => return Err(anyhow!("Function range overflows")),
            };
            Ok(start..end)
        }
    }
}

pub struct IdaUnpacker<I> {
    input: I,
    is_64: bool,
}

impl<I> IdaUnpacker<I> {
    pub fn new(input: I, is_64: bool) -> Self {
        Self { input, is_64 }
    }

    pub fn inner(self) -> I {
        self.input
    }
}

impl<I: IdaGenericUnpack> IdaUnpack for IdaUnpacker<I> {
    fn is_64(&self) -> bool {
        self.is_64
    }
}

impl<I: Read> Read for IdaUnpacker<I> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.input.read_vectored(bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.input.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.input.read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.input.read_exact(buf)
    }
}

impl<I: BufRead> BufRead for IdaUnpacker<I> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.input.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.input.consume(amt);
    }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.input.read_until(byte, buf)
    }

    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.input.read_line(buf)
    }
}

pub trait IdaGenericBufUnpack: IdaGenericUnpack + BufRead {
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
            let Some(typ) = self.fill_buf()?.first().copied() else {
                return Err(anyhow!(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EoF on DA"
                )));
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
                    let Some(y) = self.fill_buf()?.first().copied() else {
                        return Err(anyhow!(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Unexpected EoF on DA"
                        )));
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
        ensure!(buf.pop() == Some(b'\x00'), "Unexpected EoF on CStr");
        Ok(buf)
    }

    // TODO rename this
    fn read_c_string_vec(&mut self) -> Result<Vec<Vec<u8>>> {
        let buf = self.read_c_string_raw()?;
        if buf.is_empty() {
            return Ok(vec![]);
        }

        let mut result = vec![];
        // NOTE never 0 because this came from a CStr
        let mut len = buf[0] - 1;
        // NOTE zero len (buf[0] == 1) string is allowed
        let mut current = &buf[1..];
        loop {
            ensure!(current.len() >= len.into(), "Invalid len on Vec of CStr");
            let (value, rest) = current.split_at(len.into());
            result.push(value.to_owned());
            if rest.is_empty() {
                break;
            }
            len = rest[0] - 1;
            current = &rest[1..];
        }
        Ok(result)
    }

    fn peek_u8(&mut self) -> Result<Option<u8>> {
        Ok(self.fill_buf()?.first().copied())
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48ce40
    fn read_ext_att(&mut self) -> Result<Option<u64>> {
        let Some(byte0) = self.peek_u8()? else {
            return Ok(None);
        };
        if byte0 == 0 {
            return Ok(None);
        }
        self.consume(1);

        let start_value: u16 = if byte0 & 0x80 != 0 {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cec0
            let byte1 = self.read_u8()?;
            // TODO is this an error or expect possible value?
            ensure!(byte1 != 0);
            let start_value = ((byte1 as u16) << 7 | (byte0 as u16) & 0x7f) - 1;

            match start_value {
                0x400 => return Ok(Some(-1i64 as u64)),
                0x200 => return Ok(Some(-1i32 as u64)),
                other => other,
            }
        } else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48ce60
            (byte0 - 1).into()
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48ce6f
        let mut acc = 0;
        for bit in 0..8 {
            if (start_value >> bit) & 1 != 0 {
                let value = self.read_u8()?;
                // TODO is this an error or expect possible value?
                ensure!(value != 0);
                acc |= (value as u64) << (bit << 3);
            }
        }

        if start_value & 0x100 != 0 {
            acc = !acc;
        }
        Ok(Some(acc))
    }
}
impl<R: BufRead> IdaGenericBufUnpack for R {}

pub trait IdaGenericUnpack: Read {
    // TODO delete
    fn parse_u8(&mut self) -> Result<u8> {
        self.read_u8()
    }

    fn read_u8(&mut self) -> Result<u8> {
        let mut data = [0; 1];
        self.read_exact(&mut data)?;
        Ok(data[0])
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
        let b1: u8 = bincode::deserialize_from(&mut *self)?;
        match b1 {
            // 7 bit value
            // [0xxx xxxx]
            0x00..=0x7F => Ok(b1.into()),
            // 14 bits value
            // [10xx xxxx] xxxx xxxx
            0x80..=0xBF => {
                let lo: u8 = bincode::deserialize_from(&mut *self)?;
                Ok(u16::from_be_bytes([b1 & 0x3F, lo]))
            }
            // 16 bits value
            // [11XX XXXX] xxxx xxxx xxxx xxxx
            0xC0..=0xFF => {
                // NOTE first byte 6 bits seems to be ignored
                //ensure!(header != 0xC0 && header != 0xFF);
                Ok(u16::from_be_bytes(bincode::deserialize_from(&mut *self)?))
            }
        }
    }

    // InnerRef b47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46b690 unpack_dd
    // NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
    /// Reads 1 to 5 bytes.
    fn unpack_dd(&mut self) -> Result<u32> {
        let b1: u8 = bincode::deserialize_from(&mut *self)?;
        match b1 {
            // 7 bit value
            // [0xxx xxxx]
            0x00..=0x7F => Ok(b1.into()),
            // 14 bits value
            // [10xx xxxx] xxxx xxxx
            0x80..=0xBF => {
                let lo: u8 = bincode::deserialize_from(&mut *self)?;
                Ok(u32::from_be_bytes([0, 0, b1 & 0x3F, lo]))
            }
            // 29 bit value:
            // [110x xxxx] xxxx xxxx xxxx xxxx xxxx xxxx
            0xC0..=0xDF => {
                let bytes: [u8; 3] = bincode::deserialize_from(&mut *self)?;
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
                Ok(u32::from_be_bytes(bincode::deserialize_from(&mut *self)?))
            }
        }
    }

    /// unpack 32bits, extending the max value if equal to u32::MAX
    fn unpack_dd_ext_max(&mut self) -> Result<u64> {
        match self.unpack_dd()? {
            u32::MAX => Ok(u64::MAX),
            value => Ok(u64::from(value)),
        }
    }

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
        self.read_exact(&mut result)?;
        Ok(result)
    }

    fn unpack_dt_bytes(&mut self) -> Result<Vec<u8>> {
        let buf_len = self.read_dt()?;
        let mut buf = vec![0; buf_len.into()];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reads 1 to 5 bytes
    /// Value Range: 0-0xFFFFFFFF
    /// Usage: Enum Deltas
    fn read_de(&mut self) -> Result<u32> {
        // TODO check if the implementation is complete
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cdb0
        let mut val: u32 = 0;
        for _ in 0..5 {
            let mut hi = val << 6;
            let b: u32 = self.read_u8()?.into();
            if b & 0x80 == 0 {
                let lo = b & 0x3F;
                val = lo | hi;
                return Ok(val);
            } else {
                let lo = 2 * hi;
                hi = b & 0x7F;
                val = lo | hi;
            }
        }
        Err(anyhow!("Can't find the end of DE"))
    }

    /// Reads 1 or 2 bytes.
    /// Value Range: 0-0xFFFE
    /// Usage: 16bit numbers
    fn read_dt(&mut self) -> Result<u16> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cd60
        let value = match self.read_u8()? {
            0 => return Err(anyhow!("DT can't have 0 value")),
            //SEG = 2
            value if value & 0x80 != 0 => {
                let inter: u16 = self.read_u8()?.into();
                value as u16 & 0x7F | inter << 7
            }
            //SEG = 1
            value => value.into(),
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
    fn read_dt_de(&mut self) -> Result<Option<u32>> {
        // TODO the return is always NonZero?
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48cf20
        match self.read_dt()? {
            0 => Ok(None),
            0x7FFE => self.read_de().map(Some),
            n => Ok(Some(n.into())),
        }
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

impl<R: Read> IdaGenericUnpack for R {}
