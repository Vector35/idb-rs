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
