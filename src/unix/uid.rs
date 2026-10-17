use libc::uid_t;
use std::convert::Infallible;
use std::str::FromStr;

/// User identity on *nix.
#[derive(Clone)]
pub enum Uid {
    Id(uid_t),
    Name(Box<str>),
}

impl FromStr for Uid {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s.parse() {
            Ok(v) => Self::Id(v),
            Err(_) => Self::Name(s.into()),
        };

        Ok(v)
    }
}
