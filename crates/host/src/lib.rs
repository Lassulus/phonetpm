//! Host side of phonetpm: talks to the phone over iroh and exposes its keys
//! as an ssh-agent and an age plugin.

pub mod agekey;
pub mod config;
pub mod control;
pub mod sshagent;
pub mod transport;

pub use phonetpm_proto as proto;
