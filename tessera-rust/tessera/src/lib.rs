//! Tessera — conformant Rust implementation of the VCR protocol.
//!
//! Implements receipt creation, canonical serialisation, signing, and
//! verification per VCR-SPEC.md. Produces identical `receipt_id` values
//! as the Python reference implementation for identical fields.

pub mod merkle;
pub mod receipt;
pub mod transfer;
