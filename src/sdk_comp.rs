pub mod bytes;
pub mod frame;
pub mod funcs;
/// Functions that are exported on the lib but not part of the SDK
pub mod inner;
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
    pub use super::inner::*;
    pub use super::lines::*;
    pub use super::nalt::*;
    pub use super::netnode::*;
    pub use super::pro::*;
    pub use super::range::*;
    pub use super::segment::*;
    pub use super::typeinf::*;
}
