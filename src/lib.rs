mod dlcat;
mod op_cat;
#[allow(dead_code)]
// #[allow(unused_imports)]
mod op_ctv;
mod utils;

pub use dlcat::{build_cat_taproot_leafs, build_ctv_taproot_leafs};

// TODO:
//
// Seperate the CTV script for each outcome & be able to get script for outcome.
// Multi-party outcomes, if x then alice and bob get paid.
