use std::fmt;
use std::str::FromStr;

use crate::error::{Error, What};

/// A version the way a Component Model interface name carries one: a Semantic Versioning 2.0
/// version, or one of the canonical prefixes the Component Model reduces it to (`1`, `0.2`,
/// `0.0.3`).
///
/// Two versions are compatible when they share the canonical prefix ([`Version::canonical`]):
/// the major number when it is above zero, else `0.minor` when the minor number is above zero,
/// else the whole `0.0.patch`; a pre-release version is compatible only with itself. That is the
/// rule under which a Component Model host resolves an import, so it is the rule a grant of an
/// interface covers a request with.
///
/// The derived ordering is structural, for keeping versions in sets; it is not Semantic
/// Versioning precedence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: Option<u64>,
    patch: Option<u64>,
    pre: Option<String>,
    build: Option<String>,
}

impl Version {
    /// Parses a version: `major`, `major.minor` or `major.minor.patch`, the last with an optional
    /// `-pre-release` and `+build` the way Semantic Versioning 2.0 spells them.
    pub fn parse(text: &str) -> Result<Version, Error> {
        let fail = |reason| Err(Error::new(What::Version, text, reason));
        if text.is_empty() {
            return fail("a version is major, major.minor or major.minor.patch");
        }
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        let (numbers, pre) = match rest.split_once('-') {
            Some((numbers, pre)) => (numbers, Some(pre)),
            None => (rest, None),
        };
        let mut parts = Vec::with_capacity(3);
        for part in numbers.split('.') {
            match parse_number(part) {
                Some(n) => parts.push(n),
                None => return fail("a version number is decimal digits without a leading zero"),
            }
        }
        if parts.len() > 3 {
            return fail("a version has at most major, minor and patch");
        }
        if (pre.is_some() || build.is_some()) && parts.len() != 3 {
            return fail("a pre-release or build suffix needs major.minor.patch");
        }
        if let Some(pre) = pre
            && !pre.split('.').all(is_pre_release_identifier)
        {
            return fail(
                "a pre-release is dot-separated identifiers of letters, digits and hyphens, numeric ones without a leading zero",
            );
        }
        if let Some(build) = build
            && !build.split('.').all(is_build_identifier)
        {
            return fail("a build is dot-separated identifiers of letters, digits and hyphens");
        }
        Ok(Version {
            major: parts[0],
            minor: parts.get(1).copied(),
            patch: parts.get(2).copied(),
            pre: pre.map(str::to_owned),
            build: build.map(str::to_owned),
        })
    }

    /// The major number.
    pub fn major(&self) -> u64 {
        self.major
    }

    /// The minor number, when the version has one.
    pub fn minor(&self) -> Option<u64> {
        self.minor
    }

    /// The patch number, when the version has one.
    pub fn patch(&self) -> Option<u64> {
        self.patch
    }

    /// The pre-release identifiers after the hyphen, when there are any.
    pub fn pre_release(&self) -> Option<&str> {
        self.pre.as_deref()
    }

    /// The build identifiers after the plus sign, when there are any.
    pub fn build(&self) -> Option<&str> {
        self.build.as_deref()
    }

    /// The canonical prefix the Component Model reduces this version to: the major number when
    /// it is above zero (`1.2.3` gives `1`), else `0.minor` when the minor number is above zero
    /// (`0.2.6` gives `0.2`), else `0.0.patch`; a pre-release version keeps its three numbers
    /// and its pre-release, and build metadata is always dropped.
    pub fn canonical(&self) -> Version {
        let minor = self.minor.unwrap_or(0);
        let patch = self.patch.unwrap_or(0);
        if let Some(pre) = &self.pre {
            Version {
                major: self.major,
                minor: Some(minor),
                patch: Some(patch),
                pre: Some(pre.clone()),
                build: None,
            }
        } else if self.major > 0 {
            Version {
                major: self.major,
                minor: None,
                patch: None,
                pre: None,
                build: None,
            }
        } else if minor > 0 {
            Version {
                major: 0,
                minor: Some(minor),
                patch: None,
                pre: None,
                build: None,
            }
        } else {
            Version {
                major: 0,
                minor: Some(0),
                patch: Some(patch),
                pre: None,
                build: None,
            }
        }
    }

    /// Whether the two versions share a canonical prefix, so that an import of one is satisfied
    /// by an export of the other.
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.canonical() == other.canonical()
    }
}

fn parse_number(part: &str) -> Option<u64> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    part.parse().ok()
}

fn is_build_identifier(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_pre_release_identifier(part: &str) -> bool {
    if !is_build_identifier(part) {
        return false;
    }
    let numeric = part.bytes().all(|b| b.is_ascii_digit());
    !(numeric && part.len() > 1 && part.starts_with('0'))
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(text: &str) -> Result<Version, Error> {
        Version::parse(text)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.major)?;
        if let Some(minor) = self.minor {
            write!(f, ".{minor}")?;
        }
        if let Some(patch) = self.patch {
            write!(f, ".{patch}")?;
        }
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        if let Some(build) = &self.build {
            write!(f, "+{build}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_are_kept_as_written() {
        let v = Version::parse("1.2.3-rc.1+sha.5114f85").unwrap();
        assert_eq!((v.major(), v.minor(), v.patch()), (1, Some(2), Some(3)));
        assert_eq!(v.pre_release(), Some("rc.1"));
        assert_eq!(v.build(), Some("sha.5114f85"));
        assert_eq!(v.to_string(), "1.2.3-rc.1+sha.5114f85");
        let short = Version::parse("0.2").unwrap();
        assert_eq!(
            (short.major(), short.minor(), short.patch()),
            (0, Some(2), None)
        );
    }

    #[test]
    fn a_suffix_needs_three_numbers() {
        assert!(Version::parse("1.2-alpha").is_err());
        assert!(Version::parse("1+build").is_err());
        assert!(Version::parse("1.2.3-01").is_err());
        assert!(Version::parse("1.2.3-0.1.a-b").is_ok());
        assert!(Version::parse("1.2.3+01").is_ok());
    }

    #[test]
    fn numbers_take_the_whole_u64() {
        let v = Version::parse("18446744073709551615.0.0").unwrap();
        assert_eq!(v.major(), u64::MAX);
        assert!(Version::parse("18446744073709551616").is_err());
    }
}
