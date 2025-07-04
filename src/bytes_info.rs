use std::collections::HashMap;

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
            .and_then(|id1| id1.byte_by_address(address.into_raw().into()))
            .or_else(|| {
                self.id2.and_then(|id2| {
                    id2.byte_by_address(address).map(|x| x.byte_info)
                })
            })
    }

    pub fn all_bytes_no_tails(&self) -> Vec<(Address<K>, ByteInfo, usize)> {
        let mut bytes = HashMap::new();
        let id1 = self
            .id1
            .iter()
            .flat_map(|id1| id1.all_bytes_no_tails())
            .map(|(addr, byte_info, len)| {
                (Address::from_raw(addr.try_into().unwrap()), byte_info, len)
            });
        let id2 = self
            .id2
            .iter()
            .flat_map(|id2| id2.all_bytes_no_tails())
            .map(|x| (x.address, x.byte_info, x.len.try_into().unwrap()));
        for (addr, byte_info, len) in id1.chain(id2) {
            bytes.entry(addr).or_insert((addr, byte_info, len));
        }
        let mut bytes: Vec<_> = bytes.into_values().collect();
        bytes.sort_by_key(|(addr, _, _)| *addr);
        bytes
    }
}
