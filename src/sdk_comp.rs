pub mod bytes;
pub mod frame;
pub mod funcs;
pub mod lines;
pub mod nalt;
pub mod netnode;
pub mod pro;
pub mod range;
pub mod segment;
pub mod typeinf;

// TODO
//pub mod loader;

pub enum DataFetch<T> {
    Qty(u16),
    Data(Vec<T>),
}

pub mod prelude {
    pub use super::bytes::*;
    pub use super::frame::*;
    pub use super::funcs::*;
    pub use super::lines::*;
    pub use super::nalt::*;
    pub use super::netnode::*;
    pub use super::pro::*;
    pub use super::range::*;
    pub use super::segment::*;
    pub use super::typeinf::*;
}
