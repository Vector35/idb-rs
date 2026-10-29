use crate::id1::{ByteInfo, ID1Section};
use crate::id2::ID2Section;
use crate::{Address, IDAKind};

#[derive(Clone, Copy)]
pub struct BytesInfo<'a, 'b, K: IDAKind> {
    id1: Option<&'a ID1Section<K>>,
    id2: Option<&'b ID2Section<K>>,
}

impl<'a, 'b, K: IDAKind> BytesInfo<'a, 'b, K> {
    pub fn new(
        id1: Option<&'a ID1Section<K>>,
        id2: Option<&'b ID2Section<K>>,
    ) -> Self {
        Self { id1, id2 }
    }

    pub fn byte_by_address(&self, address: Address<K>) -> Option<ByteInfo> {
        self.id1
            .and_then(|id1| id1.byte_by_address(address))
            .or_else(|| {
                self.id2.and_then(|id2| {
                    id2.byte_by_address(address).map(|x| x.byte_info)
                })
            })
    }

    pub fn all_bytes_no_tails(&self) -> Vec<(Address<K>, ByteInfo, usize)> {
        let mut bytes: Vec<_> = self.heads().collect();
        bytes.sort_unstable_by_key(|(addr, _, _)| *addr);
        bytes
    }

    /// Bytes that are not tails and the size of their item, in no particular
    /// order. ID1 takes precedence over ID2.
    pub fn heads(
        &self,
    ) -> impl Iterator<Item = (Address<K>, ByteInfo, usize)> + use<'a, 'b, K>
    {
        let id1 = self.id1;
        let in_id1 = move |addr| {
            id1.and_then(|id1| id1.byte_by_address(addr))
                .is_some_and(|b| !b.byte_type().is_tail())
        };
        let id2 = self
            .id2
            .into_iter()
            .flat_map(|id2| id2.all_bytes_no_tails())
            .filter(move |x| !in_id1(x.address))
            .map(|x| (x.address, x.byte_info, x.len.try_into().unwrap()));
        id1.into_iter()
            .flat_map(|id1| id1.all_bytes_no_tails())
            .chain(id2)
    }
}
