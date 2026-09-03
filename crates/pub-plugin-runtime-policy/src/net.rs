use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::error::{Error, What};

/// A host a plugin may reach: a DNS name (lowercased; `api.example.org`), an IP address
/// (`127.0.0.1`, `[::1]`), or a suffix pattern (`*.example.org`: every name at least one label
/// below `example.org`, not `example.org` itself).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    /// One DNS name, lowercase.
    Name(String),
    /// An IP address.
    Address(IpAddr),
    /// Every name below the suffix; the suffix is kept without the leading `*.`.
    Suffix(String),
}

impl Host {
    /// Parses a name, an address (IPv6 in brackets) or a `*.suffix` pattern.
    pub fn parse(text: &str) -> Result<Host, Error> {
        let fail = |reason| Error::new(What::Host, text, reason);
        if text.is_empty() {
            return Err(fail(
                "a host is a DNS name, an IP address or a `*.suffix` pattern",
            ));
        }
        if let Some(inner) = text.strip_prefix('[') {
            let Some(inner) = inner.strip_suffix(']') else {
                return Err(fail("an IPv6 address is written in brackets, `[::1]`"));
            };
            return match Ipv6Addr::from_str(inner) {
                Ok(v6) => Ok(Host::Address(IpAddr::V6(v6))),
                Err(_) => Err(fail("the brackets hold an IPv6 address")),
            };
        }
        if text.contains(':') {
            return Err(fail("an IPv6 address is written in brackets, `[::1]`"));
        }
        if let Ok(v4) = Ipv4Addr::from_str(text) {
            return Ok(Host::Address(IpAddr::V4(v4)));
        }
        if let Some(suffix) = text.strip_prefix("*.") {
            let suffix = check_name(suffix).map_err(fail)?;
            return Ok(Host::Suffix(suffix));
        }
        Ok(Host::Name(check_name(text).map_err(fail)?))
    }

    /// Whether a grant of this host covers a request of the other: the same name or address, or
    /// a suffix pattern the requested name is below (a narrower pattern is below a wider one).
    pub fn covers(&self, request: &Host) -> bool {
        match (self, request) {
            (Host::Name(a), Host::Name(b)) => a == b,
            (Host::Address(a), Host::Address(b)) => a == b,
            (Host::Suffix(suffix), Host::Name(name)) => is_below(name, suffix),
            (Host::Suffix(wide), Host::Suffix(narrow)) => wide == narrow || is_below(narrow, wide),
            _ => false,
        }
    }
}

/// Whether `name` ends with `.suffix`.
fn is_below(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len()
        && name.ends_with(suffix)
        && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
}

fn check_name(text: &str) -> Result<String, &'static str> {
    if text.is_empty() {
        return Err("a name has at least one label");
    }
    let name = text.to_ascii_lowercase();
    let mut last_has_letter = false;
    for label in name.split('.') {
        if label.is_empty() {
            return Err("a name's labels are separated by single dots, none at the ends");
        }
        if label.len() > 63 {
            return Err("a name's label is at most 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("a name's label is letters, digits and hyphens");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a name's label neither starts nor ends with a hyphen");
        }
        last_has_letter = label.bytes().any(|b| b.is_ascii_lowercase());
    }
    if !last_has_letter {
        return Err("a name's last label has a letter (an IPv4 address is four numbers)");
    }
    Ok(name)
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(text: &str) -> Result<Host, Error> {
        Host::parse(text)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(name) => f.write_str(name),
            Host::Address(IpAddr::V4(v4)) => write!(f, "{v4}"),
            Host::Address(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            Host::Suffix(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

/// A port a plugin may reach: one number, or any (`*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Port {
    /// Any port.
    Any,
    /// One port.
    Number(u16),
}

impl Port {
    /// Whether a grant of this port covers a request of the other.
    pub fn covers(self, request: Port) -> bool {
        match (self, request) {
            (Port::Any, _) => true,
            (Port::Number(a), Port::Number(b)) => a == b,
            (Port::Number(_), Port::Any) => false,
        }
    }
}

impl FromStr for Port {
    type Err = Error;

    fn from_str(text: &str) -> Result<Port, Error> {
        if text == "*" {
            return Ok(Port::Any);
        }
        if !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = text.parse()
        {
            return Ok(Port::Number(n));
        }
        Err(Error::new(
            What::Port,
            text,
            "a port is a number from 0 to 65535, or `*` for any",
        ))
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Port::Any => f.write_str("*"),
            Port::Number(n) => write!(f, "{n}"),
        }
    }
}

/// An environment variable a plugin may read: one name (`HOME`), or every name with a prefix
/// (`PUB_*`). A name is a letter or underscore, then letters, digits and underscores.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variable {
    /// One variable.
    Name(String),
    /// Every variable whose name starts with the prefix; kept without the trailing `*`.
    Prefix(String),
}

impl Variable {
    /// Parses a name or a `PREFIX*` pattern.
    pub fn parse(text: &str) -> Result<Variable, Error> {
        let fail = |reason| Error::new(What::Variable, text, reason);
        if text.is_empty() {
            return Err(fail("a variable is a name or a `PREFIX*` pattern"));
        }
        if let Some(prefix) = text.strip_suffix('*') {
            if prefix.is_empty() {
                return Err(fail("a pattern has a prefix before the `*`"));
            }
            check_variable(prefix).map_err(fail)?;
            return Ok(Variable::Prefix(prefix.to_owned()));
        }
        check_variable(text).map_err(fail)?;
        Ok(Variable::Name(text.to_owned()))
    }

    /// Whether a grant of this variable covers a request of the other: the same name, or a
    /// prefix the requested name (or the requested, narrower prefix) starts with.
    pub fn covers(&self, request: &Variable) -> bool {
        match (self, request) {
            (Variable::Name(a), Variable::Name(b)) => a == b,
            (Variable::Prefix(prefix), Variable::Name(name)) => name.starts_with(prefix.as_str()),
            (Variable::Prefix(wide), Variable::Prefix(narrow)) => narrow.starts_with(wide.as_str()),
            (Variable::Name(_), Variable::Prefix(_)) => false,
        }
    }
}

fn check_variable(text: &str) -> Result<(), &'static str> {
    let mut bytes = text.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return Err("a variable name starts with a letter or an underscore"),
    }
    if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("a variable name is letters, digits and underscores");
    }
    Ok(())
}

impl FromStr for Variable {
    type Err = Error;

    fn from_str(text: &str) -> Result<Variable, Error> {
        Variable::parse(text)
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variable::Name(name) => f.write_str(name),
            Variable::Prefix(prefix) => write!(f, "{prefix}*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercased_and_addresses_kept_apart() {
        assert_eq!(
            Host::parse("Example.ORG").unwrap(),
            Host::Name("example.org".into())
        );
        assert_eq!(
            Host::parse("10.0.0.1").unwrap(),
            Host::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            Host::parse("[::1]").unwrap(),
            Host::Address(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            Host::parse("*.Example.org").unwrap(),
            Host::Suffix("example.org".into())
        );
        assert!(Host::parse(&format!("{}.org", "a".repeat(64))).is_err());
        assert!(Host::parse(&format!("{}.org", "a".repeat(63))).is_ok());
    }

    #[test]
    fn a_suffix_needs_a_whole_label_boundary() {
        let suffix = Host::parse("*.example.org").unwrap();
        assert!(suffix.covers(&Host::parse("a.example.org").unwrap()));
        assert!(!suffix.covers(&Host::parse("aexample.org").unwrap()));
        assert!(!suffix.covers(&Host::parse("example.org").unwrap()));
        assert!(!suffix.covers(&Host::parse("*.org").unwrap()));
        assert!(!Host::parse("example.org").unwrap().covers(&suffix));
    }

    #[test]
    fn ports_reject_signs_and_spaces() {
        assert!("+443".parse::<Port>().is_err());
        assert!(" 443".parse::<Port>().is_err());
        assert_eq!("0".parse::<Port>().unwrap(), Port::Number(0));
        assert_eq!("65535".parse::<Port>().unwrap(), Port::Number(65535));
        assert!("65536".parse::<Port>().is_err());
    }

    #[test]
    fn a_prefix_covers_itself_and_what_starts_with_it() {
        let p = Variable::parse("PUB_").unwrap();
        let any = Variable::parse("PUB_*").unwrap();
        assert!(any.covers(&p));
        assert!(!p.covers(&any));
        assert!(any.covers(&Variable::parse("PUB_*").unwrap()));
    }
}
