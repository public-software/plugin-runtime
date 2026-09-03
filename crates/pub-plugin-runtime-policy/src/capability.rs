use std::fmt;
use std::str::FromStr;

use crate::error::{Error, What};
use crate::name::InterfaceName;
use crate::net::{Host, Port, Variable};
use crate::path::{Access, GuestPath};

/// One thing a plugin may be allowed to do. A manifest requests capabilities; a policy grants
/// them; the same type serves both, a grant being allowed to be wider than a request
/// ([`Capability::covers`]).
///
/// The four kinds are what a Component Model host has to configure: which interfaces to link
/// (`public:*` and `wasi:*` alike), which directories to preopen, which environment variables
/// to pass, and which socket addresses to admit. Each has a one-line text form
/// ([`FromStr`] and [`Display`](fmt::Display)):
///
/// ```text
/// interface wasi:filesystem/types@0.2.8
/// directory read-write /data
/// environment PUB_*
/// network *.example.org:443
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Importing a host interface, named the Component Model way.
    Interface(InterfaceName),
    /// A directory of the guest's filesystem, with read or read-write access.
    Directory {
        /// The directory as the plugin sees it.
        path: GuestPath,
        /// What the plugin may do in it.
        access: Access,
    },
    /// Reading an environment variable, or every variable with a prefix.
    Environment(Variable),
    /// Connecting to a host and port.
    Network {
        /// The host, or a suffix pattern of hosts.
        host: Host,
        /// The port, or any.
        port: Port,
    },
}

impl Capability {
    /// An interface capability from its name.
    pub fn interface(name: &str) -> Result<Capability, Error> {
        Ok(Capability::Interface(InterfaceName::parse(name)?))
    }

    /// A directory capability from a guest path and an access.
    pub fn directory(path: &str, access: Access) -> Result<Capability, Error> {
        Ok(Capability::Directory {
            path: GuestPath::parse(path)?,
            access,
        })
    }

    /// An environment capability from a variable name or a `PREFIX*` pattern.
    pub fn environment(variable: &str) -> Result<Capability, Error> {
        Ok(Capability::Environment(Variable::parse(variable)?))
    }

    /// A network capability from a host (or `*.suffix` pattern) and a port.
    pub fn network(host: &str, port: Port) -> Result<Capability, Error> {
        Ok(Capability::Network {
            host: Host::parse(host)?,
            port,
        })
    }

    /// Whether this capability, as a grant, covers the other, as a request: the same kind, and
    /// the same interface at a compatible version (or any version), a directory at or above the
    /// requested one with at least the requested access, the same variable or a prefix of it,
    /// the same host or a suffix pattern of it at the same or any port.
    pub fn covers(&self, request: &Capability) -> bool {
        match (self, request) {
            (Capability::Interface(g), Capability::Interface(r)) => g.covers(r),
            (
                Capability::Directory {
                    path: g,
                    access: ga,
                },
                Capability::Directory {
                    path: r,
                    access: ra,
                },
            ) => g.covers(r) && ga.allows(*ra),
            (Capability::Environment(g), Capability::Environment(r)) => g.covers(r),
            (
                Capability::Network { host: gh, port: gp },
                Capability::Network { host: rh, port: rp },
            ) => gh.covers(rh) && gp.covers(*rp),
            _ => false,
        }
    }
}

impl FromStr for Capability {
    type Err = Error;

    fn from_str(text: &str) -> Result<Capability, Error> {
        let fail = |reason| Error::new(What::Capability, text, reason);
        let line = text.trim();
        let (kind, rest) = match line.split_once(char::is_whitespace) {
            Some((kind, rest)) => (kind, rest.trim()),
            None => (line, ""),
        };
        let one_word = |what: &'static str| {
            if rest.is_empty() {
                Err(fail(what))
            } else if rest.contains(char::is_whitespace) {
                Err(fail("one value, without spaces, follows the kind"))
            } else {
                Ok(rest)
            }
        };
        match kind {
            "interface" => {
                let name =
                    one_word("`interface` is followed by namespace:package/interface[@version]")?;
                Capability::interface(name).map_err(|e| fail(e.reason()))
            }
            "directory" => {
                let Some((access, path)) = rest.split_once(char::is_whitespace) else {
                    return Err(fail(
                        "`directory` is followed by `read` or `read-write`, then the path",
                    ));
                };
                let access = Access::from_str(access).map_err(|e| fail(e.reason()))?;
                Capability::directory(path.trim(), access).map_err(|e| fail(e.reason()))
            }
            "environment" => {
                let variable =
                    one_word("`environment` is followed by a variable name or a PREFIX* pattern")?;
                Capability::environment(variable).map_err(|e| fail(e.reason()))
            }
            "network" => {
                let address =
                    one_word("`network` is followed by host:port, the port a number or `*`")?;
                let (host, port) = split_address(address).ok_or_else(|| {
                    fail("`network` is followed by host:port, the port a number or `*`")
                })?;
                let port = Port::from_str(port).map_err(|e| fail(e.reason()))?;
                Capability::network(host, port).map_err(|e| fail(e.reason()))
            }
            _ => Err(fail(
                "a capability is `interface`, `directory`, `environment` or `network`",
            )),
        }
    }
}

/// Splits `host:port`, the host possibly a bracketed IPv6 address.
fn split_address(address: &str) -> Option<(&str, &str)> {
    let (host, port) = if address.starts_with('[') {
        let end = address.find(']')?;
        let (host, rest) = address.split_at(end + 1);
        (host, rest.strip_prefix(':')?)
    } else {
        address.rsplit_once(':')?
    };
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Interface(name) => write!(f, "interface {name}"),
            Capability::Directory { path, access } => write!(f, "directory {access} {path}"),
            Capability::Environment(variable) => write!(f, "environment {variable}"),
            Capability::Network { host, port } => write!(f, "network {host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_never_cover_each_other() {
        let interface = Capability::interface("wasi:cli/environment@0.2.8").unwrap();
        let variable = Capability::environment("HOME").unwrap();
        let directory = Capability::directory("/", Access::ReadWrite).unwrap();
        let network = Capability::network("*.org", Port::Any).unwrap();
        for a in [&interface, &variable, &directory, &network] {
            for b in [&interface, &variable, &directory, &network] {
                assert_eq!(a.covers(b), std::ptr::eq(a, b), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn a_path_may_contain_spaces_in_the_text_form() {
        let c: Capability = "directory read /a/b c/d".parse().unwrap();
        assert_eq!(c.to_string(), "directory read /a/b c/d");
    }

    #[test]
    fn addresses_split_at_the_last_colon_or_after_the_bracket() {
        assert_eq!(split_address("[::1]:80"), Some(("[::1]", "80")));
        assert_eq!(split_address("a.b:80"), Some(("a.b", "80")));
        assert_eq!(split_address("[::1]"), None);
        assert_eq!(split_address("[::1]80"), None);
        assert_eq!(split_address(":80"), None);
        assert_eq!(split_address("a.b"), None);
    }

    #[test]
    fn errors_are_about_the_capability_line() {
        let err = "network api.example.org:99999"
            .parse::<Capability>()
            .unwrap_err();
        assert_eq!(err.what(), What::Capability);
        assert_eq!(err.input(), "network api.example.org:99999");
        assert!(err.reason().contains("65535"));
    }
}
