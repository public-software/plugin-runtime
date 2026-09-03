use std::fmt;
use std::str::FromStr;

use crate::error::{Error, What};
use crate::version::Version;

/// A kebab-case label, the way the Component Model names an interface, a function or a plugin:
/// fragments joined by single hyphens, each a word (lowercase letters and digits) or an
/// acronym (uppercase letters and digits), the first starting with a letter. `foo`,
/// `red-green-blue` and `parse-XML-document` are labels; `Foo`, `foo_bar` and `1foo` are not.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Label(String);

impl Label {
    /// Checks the text against the label grammar.
    pub fn new(text: &str) -> Result<Label, Error> {
        check_label(text).map_err(|reason| Error::new(What::Label, text, reason))?;
        Ok(Label(text.to_owned()))
    }

    /// The label as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn check_label(text: &str) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("a label has at least one word");
    }
    for (i, fragment) in text.split('-').enumerate() {
        let bytes = fragment.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err("a label's fragments are separated by single hyphens, none at the ends");
        };
        let word = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let acronym = bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if !(word || acronym) {
            return Err(
                "a fragment is a word of lowercase letters and digits or an acronym of uppercase letters and digits",
            );
        }
        if i == 0 && !first.is_ascii_alphabetic() {
            return Err("a label starts with a letter");
        }
    }
    Ok(())
}

/// Lowercase words joined by single hyphens, the first starting with a letter: the shape of a
/// namespace and of a package name.
fn check_words(text: &str) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("a namespace and a package are lowercase words joined by hyphens");
    }
    for (i, word) in text.split('-').enumerate() {
        let Some(&first) = word.as_bytes().first() else {
            return Err("a namespace and a package are lowercase words joined by single hyphens");
        };
        if !word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err("a namespace and a package are lowercase words of letters and digits");
        }
        if i == 0 && !first.is_ascii_lowercase() {
            return Err("a namespace and a package start with a letter");
        }
    }
    Ok(())
}

impl FromStr for Label {
    type Err = Error;

    fn from_str(text: &str) -> Result<Label, Error> {
        Label::new(text)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a Component Model interface, `namespace:package/interface@version`, the way a
/// `public:*` or `wasi:*` import is named: `wasi:filesystem/types@0.2.8`,
/// `public:doc/graph@1.0.0`. The namespace and the package are lowercase words, the interface a
/// [`Label`], the version optional. Nested namespaces and packages are not accepted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceName {
    namespace: String,
    package: String,
    interface: Label,
    version: Option<Version>,
}

impl InterfaceName {
    /// Parses `namespace:package/interface` with an optional `@version`.
    pub fn parse(text: &str) -> Result<InterfaceName, Error> {
        let fail = |reason| Error::new(What::InterfaceName, text, reason);
        let (name, version) = match text.split_once('@') {
            Some((name, version)) => (name, Some(version)),
            None => (text, None),
        };
        let Some((namespace, rest)) = name.split_once(':') else {
            return Err(fail(
                "an interface name is namespace:package/interface[@version]",
            ));
        };
        let Some((package, interface)) = rest.split_once('/') else {
            return Err(fail(
                "an interface name is namespace:package/interface[@version]",
            ));
        };
        if package.contains(':') || interface.contains(['/', ':']) {
            return Err(fail("nested namespaces and packages are not supported"));
        }
        check_words(namespace).map_err(fail)?;
        check_words(package).map_err(fail)?;
        let interface = Label::new(interface).map_err(|e| fail(e.reason()))?;
        let version = match version {
            Some(v) => Some(Version::parse(v).map_err(|e| fail(e.reason()))?),
            None => None,
        };
        Ok(InterfaceName {
            namespace: namespace.to_owned(),
            package: package.to_owned(),
            interface,
            version,
        })
    }

    /// The namespace, `wasi` in `wasi:filesystem/types@0.2.8`.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The package, `filesystem` in `wasi:filesystem/types@0.2.8`.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// The interface, `types` in `wasi:filesystem/types@0.2.8`.
    pub fn interface(&self) -> &Label {
        &self.interface
    }

    /// The version, when the name carries one.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Whether the two names denote the same interface, whatever their versions.
    pub fn is_same_interface(&self, other: &InterfaceName) -> bool {
        self.namespace == other.namespace
            && self.package == other.package
            && self.interface == other.interface
    }

    /// Whether a grant of this name covers a request of the other: the same interface, and
    /// either this name has no version (any version is granted) or both have one and they are
    /// compatible ([`Version::is_compatible_with`]). A request without a version is covered only
    /// by a grant without one.
    pub fn covers(&self, request: &InterfaceName) -> bool {
        if !self.is_same_interface(request) {
            return false;
        }
        match (&self.version, &request.version) {
            (None, _) => true,
            (Some(granted), Some(requested)) => granted.is_compatible_with(requested),
            (Some(_), None) => false,
        }
    }
}

impl FromStr for InterfaceName {
    type Err = Error;

    fn from_str(text: &str) -> Result<InterfaceName, Error> {
        InterfaceName::parse(text)
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{}", self.namespace, self.package, self.interface)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_after_the_first_may_start_with_a_digit() {
        assert!(Label::new("foo-1").is_ok());
        assert!(Label::new("foo-1a").is_ok());
        assert!(Label::new("1-foo").is_err());
        assert!(Label::new("foo-1A").is_ok(), "1A is an acronym fragment");
        assert!(Label::new("foo-1a-B2").is_ok());
    }

    #[test]
    fn namespaces_and_packages_are_lowercase_words() {
        assert!(InterfaceName::parse("wasi:file-system/types").is_ok());
        assert!(InterfaceName::parse("wasi:XML/types").is_err());
        assert!(InterfaceName::parse("wasi:file--system/types").is_err());
        assert!(InterfaceName::parse("wasi:-fs/types").is_err());
        assert!(InterfaceName::parse("wasi:1fs/types").is_err());
        assert!(InterfaceName::parse("wasi:fs1/types").is_ok());
    }

    #[test]
    fn coverage_is_the_same_interface_at_a_compatible_version() {
        let grant = InterfaceName::parse("wasi:filesystem/types@0.2").unwrap();
        let request = InterfaceName::parse("wasi:filesystem/types@0.2.8").unwrap();
        let other = InterfaceName::parse("wasi:filesystem/preopens@0.2.8").unwrap();
        assert!(grant.covers(&request));
        assert!(request.covers(&grant));
        assert!(!grant.covers(&other));
        assert!(grant.is_same_interface(&request));
        assert!(!grant.is_same_interface(&other));
        let any = InterfaceName::parse("wasi:filesystem/types").unwrap();
        assert!(any.covers(&request));
        assert!(any.covers(&any));
        assert!(!grant.covers(&any));
    }
}
