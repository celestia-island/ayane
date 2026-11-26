//! The inbound SMTP side of the ayane mail service.
//!
//! This crate lands in layers: this tree holds the **spool** — the file
//! queue a message enters after the server has accepted it, and the only
//! place that decides what "accepted" means.
//!
//! # What the spool promises
//!
//! A message the server acknowledged is on disk, and the acknowledgement
//! is the last thing that happens: the data file, then the entry that
//! describes it, then the directory holding both. A crash between any two
//! of those steps leaves either a message the queue can still deliver or
//! no trace of a message that was never acknowledged — never a promise
//! the disk did not keep (RFC 5321 §6.1 puts the responsibility on the
//! server from the moment it answers).
//!
//! Recovery is the other half of that promise: a file that does not match
//! its own size and digest is moved aside rather than delivered, and a
//! half-written temporary file is discarded.

pub mod queue;

pub use queue::{
    Envelope, FsyncEvent, FsyncKind, FsyncObserver, FsyncOp, QueueState, QueuedMessage, Spool,
    StagedMessage, SyncHook,
};
