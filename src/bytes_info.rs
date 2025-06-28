use crate::id1::{ByteInfo, ID1Section};
use crate::id2::ID2Section;
use crate::{Address, IDAKind};

#[derive(Clone, Copy)]
pub struct BytesInfo<'a, 'b, K: IDAKind> {
    id1: Option<&'a ID1Section>,
    id2: Option<&'b ID2Section<K>>,
}

impl<'a, 'b, K: IDAKind> BytesInfo<'a, 'b, K> {
    pub fn new(
        id1: Option<&'a ID1Section>,
        id2: Option<&'b ID2Section<K>>,
    ) -> Self {
        Self { id1, id2 }
    }

    pub fn byte_by_address(&self, address: Address<K>) -> Option<ByteInfo> {
        self.id1
            .and_then(|id1| id1.byte_by_address(address.as_raw().into()))
            .or_else(|| {
                self.id2.and_then(|id2| {
                    id2.byte_by_address(address).map(|x| x.byte_info)
                })
            })
    }

    pub fn all_bytes(
        &self,
    ) -> Box<dyn Iterator<Item = (Address<K>, ByteInfo)> + '_> {
        self.id1
            .map(|id1| -> Box<dyn Iterator<Item = _>> {
                Box::new(id1.all_bytes().map(|(addr, byte_info)| {
                    (Address::from_raw(addr.try_into().unwrap()), byte_info)
                }))
            })
            .or_else(|| {
                self.id2.map(|id2| -> Box<dyn Iterator<Item = _>> {
                    Box::new(id2.all_bytes().map(|x| (x.address, x.byte_info)))
                })
            })
            .unwrap_or_else(|| -> Box<dyn Iterator<Item = _>> {
                Box::new([].into_iter())
            })
    }

    pub fn all_bytes_no_tails(
        &self,
    ) -> Box<dyn Iterator<Item = (Address<K>, ByteInfo, usize)> + '_> {
        self.id1
            .map(|id1| -> Box<dyn Iterator<Item = _>> {
                Box::new(id1.all_bytes_no_tails().map(
                    |(addr, byte_info, len)| {
                        (
                            Address::from_raw(addr.try_into().unwrap()),
                            byte_info,
                            len,
                        )
                    },
                ))
            })
            .or_else(|| {
                self.id2.map(|id2| -> Box<dyn Iterator<Item = _>> {
                    Box::new(id2.all_bytes_no_tails().map(|x| {
                        (x.address, x.byte_info, x.len.try_into().unwrap())
                    }))
                })
            })
            .unwrap_or_else(|| -> Box<dyn Iterator<Item = _>> {
                Box::new([].into_iter())
            })
    }
}
