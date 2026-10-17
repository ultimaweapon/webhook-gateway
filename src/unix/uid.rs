use libc::{_SC_GETPW_R_SIZE_MAX, getpwnam_r, sysconf, uid_t};
use std::convert::Infallible;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::mem::zeroed;
use std::ptr::null_mut;
use std::str::FromStr;
use thiserror::Error;

/// User identity on *nix.
#[derive(Clone)]
pub enum Uid {
    Id(uid_t),
    Name(Box<str>),
}

impl Uid {
    pub fn resolve(&self) -> Result<uid_t, UidError> {
        let name = match self {
            Self::Id(v) => return Ok(*v),
            Self::Name(v) => CString::new(v.as_ref()).map_err(|_| UidError::NulInName)?,
        };

        // Allocate buffer.
        let len = unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) }
            .try_into()
            .map_err(|_| UidError::NoGetPwSize)?;
        let mut buf = vec![0; len];

        // Resolve.
        let mut pwd = unsafe { zeroed() };
        let mut out = null_mut();
        let r = unsafe { getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), len, &mut out) };

        if r != 0 {
            return Err(UidError::Lookup(std::io::Error::from_raw_os_error(r)));
        }

        Ok(pwd.pw_uid)
    }
}

impl FromStr for Uid {
    type Err = Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s.parse() {
            Ok(v) => Self::Id(v),
            Err(_) => Self::Name(s.into()),
        };

        Ok(v)
    }
}

impl Display for Uid {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(v) => v.fmt(f),
            Self::Name(v) => v.fmt(f),
        }
    }
}

/// Error of [Uid::resolve()].
#[derive(Debug, Error)]
pub enum UidError {
    #[error("name contains NUL character")]
    NulInName,

    #[error("no value for _SC_GETPW_R_SIZE_MAX")]
    NoGetPwSize,

    #[error("couldn't lookup user with getpwnam_r")]
    Lookup(#[source] std::io::Error),
}
