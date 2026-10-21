#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub mod association;
pub mod chunk;
mod error;
pub mod error_cause;
pub mod packet;
pub mod param;
pub(crate) mod queue;
pub mod stream;
pub(crate) mod timer;
pub(crate) mod util;

pub use association::send_error::transient_send_errors;
pub use error::Error;
pub use timer::rtx_timer::{max_timer_backoff, set_max_timer_backoff};

#[cfg(test)]
mod fuzz_artifact_test;
