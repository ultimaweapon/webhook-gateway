use libc::{_SC_GETGR_R_SIZE_MAX, getgrnam_r, gid_t, sysconf};
use std::convert::Infallible;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::mem::zeroed;
use std::ptr::null_mut;
use std::str::FromStr;
use thiserror::Error;

/// Group identity on *nix.
#[derive(Clone)]
pub enum Gid {
    Id(gid_t),
    Name(Box<str>),
}

impl Gid {
    pub fn resolve(&self) -> Result<gid_t, GidError> {
        let name = match self {
            Self::Id(v) => return Ok(*v),
            Self::Name(v) => CString::new(v.as_ref()).map_err(|_| GidError::NulInName)?,
        };

        // Allocate buffer.
        let len = unsafe { sysconf(_SC_GETGR_R_SIZE_MAX) }
            .try_into()
            .map_err(|_| GidError::NoGetGrSize)?;
        let mut buf = vec![0; len];

        // Resolve.
        let mut grp = unsafe { zeroed() };
        let mut out = null_mut();
        let r = unsafe { getgrnam_r(name.as_ptr(), &mut grp, buf.as_mut_ptr(), len, &mut out) };

        if r != 0 {
            return Err(GidError::Lookup(std::io::Error::from_raw_os_error(r)));
        }

        Ok(grp.gr_gid)
    }
}

impl FromStr for Gid {
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

impl Display for Gid {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(v) => v.fmt(f),
            Self::Name(v) => v.fmt(f),
        }
    }
}

/// Error of [Gid::resolve()].
#[derive(Debug, Error)]
pub enum GidError {
    #[error("name contains NUL character")]
    NulInName,

    #[error("no value for _SC_GETGR_R_SIZE_MAX")]
    NoGetGrSize,

    #[error("couldn't lookup group with getgrnam_r")]
    Lookup(#[source] std::io::Error),
}
