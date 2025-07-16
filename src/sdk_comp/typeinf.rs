use super::pro::tid_t;
use crate::id0::ID0Section;
use crate::IDAKind;

pub fn get_tid_name<K: IDAKind>(
    id0: &ID0Section<K>,
    tid: tid_t<K>,
) -> Option<&[u8]> {
    id0.netnode_name(tid)
}
