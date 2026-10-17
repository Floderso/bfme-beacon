//! BFME integration: install detection and exe identity ([`detect`]), the hook DLL
//! in the game folder ([`hook`]), Network.ini `UserName` ([`netini`]), test-mode user
//! directories ([`userdir`]) and starting the game ([`launch`]).

pub mod detect;
pub mod hook;
pub mod launch;
pub mod netini;
pub mod userdir;

pub use detect::{detect, GameInfo, Registry, SystemRegistry, UserDirs};
