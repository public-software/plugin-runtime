use std::fmt;
use std::str::FromStr;

use crate::error::{Error, What};

/// A path as the plugin sees it: absolute, `/`-separated, normalised (no empty, `.` or `..`
/// component, no trailing slash), the root being `/`. What host directory it maps to is the
/// host's business.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GuestPath {
    components: Vec<String>,
}

impl GuestPath {
    /// Parses an absolute, normalised path.
    pub fn parse(text: &str) -> Result<GuestPath, Error> {
        let fail = |reason| Err(Error::new(What::Path, text, reason));
        let Some(rest) = text.strip_prefix('/') else {
            return fail("a guest path is absolute: it starts with `/`");
        };
        if rest.is_empty() {
            return Ok(GuestPath {
                components: Vec::new(),
            });
        }
        let mut components = Vec::new();
        for component in rest.split('/') {
            match component {
                "" => return fail("a guest path has no empty component and no trailing slash"),
                "." | ".." => return fail("a guest path is normalised: no `.` or `..` component"),
                c if c.contains('\0') => return fail("a guest path has no NUL byte"),
                c => components.push(c.to_owned()),
            }
        }
        Ok(GuestPath { components })
    }

    /// The components between the slashes; none for the root.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }

    /// Whether the other path is this one or below it.
    pub fn covers(&self, other: &GuestPath) -> bool {
        other.components.starts_with(&self.components)
    }
}

impl FromStr for GuestPath {
    type Err = Error;

    fn from_str(text: &str) -> Result<GuestPath, Error> {
        GuestPath::parse(text)
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("/");
        }
        for component in &self.components {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

/// What a plugin may do in a directory: read it, or read and write it. Read is below
/// read-write, so a grant of read-write allows a request of read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Access {
    /// Read files and list directories.
    Read,
    /// Read, and also create, write, rename and remove.
    ReadWrite,
}

impl Access {
    /// Whether this access is at least the one requested.
    pub fn allows(self, requested: Access) -> bool {
        requested <= self
    }

    /// The text form: `read` or `read-write`.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::ReadWrite => "read-write",
        }
    }
}

impl FromStr for Access {
    type Err = Error;

    fn from_str(text: &str) -> Result<Access, Error> {
        match text {
            "read" => Ok(Access::Read),
            "read-write" => Ok(Access::ReadWrite),
            _ => Err(Error::new(
                What::Access,
                text,
                "an access is `read` or `read-write`",
            )),
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_has_no_component_and_covers_everything() {
        let root = GuestPath::parse("/").unwrap();
        assert_eq!(root.components().count(), 0);
        assert_eq!(root.to_string(), "/");
        let deep = GuestPath::parse("/a/b/c").unwrap();
        assert_eq!(deep.components().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert!(root.covers(&deep));
        assert!(!deep.covers(&root));
    }

    #[test]
    fn a_component_is_matched_whole() {
        let data = GuestPath::parse("/data").unwrap();
        assert!(!data.covers(&GuestPath::parse("/data2").unwrap()));
        assert!(!data.covers(&GuestPath::parse("/dat").unwrap()));
        assert!(data.covers(&GuestPath::parse("/data/2").unwrap()));
    }
}
