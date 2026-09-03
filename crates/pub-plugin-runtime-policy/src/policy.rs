use std::collections::BTreeSet;
use std::fmt;

use crate::capability::Capability;
use crate::name::{InterfaceName, Label};

/// What a plugin asks for: its name and the set of capabilities it requests. Whatever it never
/// requested is denied, however generous the host's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    name: Label,
    requests: BTreeSet<Capability>,
}

impl Manifest {
    /// A manifest with no request.
    pub fn new(name: Label) -> Manifest {
        Manifest {
            name,
            requests: BTreeSet::new(),
        }
    }

    /// The plugin's name.
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Adds a request; a repeated one is one request.
    pub fn request(&mut self, capability: Capability) -> &mut Manifest {
        self.requests.insert(capability);
        self
    }

    /// The requests, in their set order.
    pub fn requests(&self) -> impl Iterator<Item = &Capability> {
        self.requests.iter()
    }

    /// Whether some request covers the capability ([`Capability::covers`]): a request of a
    /// directory covers the use of a path below it, a request of `*.example.org` the use of one
    /// name under it.
    pub fn requests_cover(&self, capability: &Capability) -> bool {
        self.requests.iter().any(|r| r.covers(capability))
    }
}

/// What a host allows: the set of capabilities it grants. Empty by default, and an empty policy
/// denies everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    grants: BTreeSet<Capability>,
}

impl Policy {
    /// The policy that grants nothing.
    pub fn new() -> Policy {
        Policy::default()
    }

    /// Adds a grant; a repeated one is one grant.
    pub fn grant(&mut self, capability: Capability) -> &mut Policy {
        self.grants.insert(capability);
        self
    }

    /// The grants, in their set order.
    pub fn grants(&self) -> impl Iterator<Item = &Capability> {
        self.grants.iter()
    }

    /// Whether some grant covers the capability ([`Capability::covers`]).
    pub fn grants_cover(&self, capability: &Capability) -> bool {
        self.grants.iter().any(|g| g.covers(capability))
    }

    /// Decides one capability for one manifest: granted when the manifest requested it (or
    /// something covering it) and some grant covers it, else denied with the reason. The manifest
    /// is checked first, so an unrequested capability is [`Denial::NotRequested`] whatever the
    /// grants say. When no grant covers a requested capability, the nearest grant is named: the
    /// same interface at an incompatible version ([`Denial::VersionMismatch`]) or the same
    /// directory with narrower access ([`Denial::AccessExceeded`]); otherwise it is
    /// [`Denial::NotGranted`].
    pub fn decide(&self, manifest: &Manifest, capability: &Capability) -> Decision {
        if !manifest.requests_cover(capability) {
            return Decision::Denied(Denial::NotRequested);
        }
        if let Some(grant) = self.grants.iter().find(|g| g.covers(capability)) {
            return Decision::Granted { by: grant.clone() };
        }
        Decision::Denied(self.nearest_denial(capability))
    }

    fn nearest_denial(&self, capability: &Capability) -> Denial {
        match capability {
            Capability::Interface(requested) => self.grants.iter().find_map(|g| match g {
                Capability::Interface(granted) if granted.is_same_interface(requested) => {
                    Some(Denial::VersionMismatch {
                        granted: granted.clone(),
                    })
                }
                _ => None,
            }),
            Capability::Directory {
                path: requested, ..
            } => self.grants.iter().find_map(|g| match g {
                Capability::Directory { path: granted, .. } if granted.covers(requested) => {
                    Some(Denial::AccessExceeded { granted: g.clone() })
                }
                _ => None,
            }),
            Capability::Environment(_) | Capability::Network { .. } => None,
        }
        .unwrap_or(Denial::NotGranted)
    }

    /// Decides every request of the manifest: the granted requests (as requested, so the host
    /// preopens and links exactly what the plugin asked for, never the wider grant) and the
    /// denied ones with their reasons, in the manifest's order.
    pub fn evaluate(&self, manifest: &Manifest) -> Evaluation {
        let mut evaluation = Evaluation {
            granted: BTreeSet::new(),
            denied: Vec::new(),
        };
        for request in manifest.requests() {
            match self.decide(manifest, request) {
                Decision::Granted { .. } => {
                    evaluation.granted.insert(request.clone());
                }
                Decision::Denied(denial) => evaluation.denied.push((request.clone(), denial)),
            }
        }
        evaluation
    }
}

/// The outcome of [`Policy::decide`] for one capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The capability is requested and granted; `by` is the grant that covers it.
    Granted {
        /// The grant that covers the capability.
        by: Capability,
    },
    /// The capability is denied, for this reason.
    Denied(Denial),
}

impl Decision {
    /// Whether the decision is a grant.
    pub fn is_granted(&self) -> bool {
        matches!(self, Decision::Granted { .. })
    }

    /// The reason, when the decision is a denial.
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Decision::Granted { .. } => None,
            Decision::Denied(denial) => Some(denial),
        }
    }
}

/// Why a capability is denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The manifest never requested it, nor anything covering it.
    NotRequested,
    /// No grant covers it, and none comes close.
    NotGranted,
    /// The interface is granted, but at a version incompatible with the one requested.
    VersionMismatch {
        /// The grant of the same interface.
        granted: InterfaceName,
    },
    /// The directory is granted (itself or a parent), but with narrower access than requested.
    AccessExceeded {
        /// The grant of the directory.
        granted: Capability,
    },
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::NotRequested => f.write_str("not requested by the manifest"),
            Denial::NotGranted => f.write_str("not granted by the policy"),
            Denial::VersionMismatch { granted } => {
                write!(f, "granted only as `{granted}`, an incompatible version")
            }
            Denial::AccessExceeded { granted } => {
                write!(f, "granted only as `{granted}`, a narrower access")
            }
        }
    }
}

/// The outcome of [`Policy::evaluate`]: what a host may set up, and what it must refuse or ask
/// about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    granted: BTreeSet<Capability>,
    denied: Vec<(Capability, Denial)>,
}

impl Evaluation {
    /// The requests that are granted, as requested.
    pub fn granted(&self) -> impl Iterator<Item = &Capability> {
        self.granted.iter()
    }

    /// The requests that are denied, each with its reason, in the manifest's order.
    pub fn denied(&self) -> impl Iterator<Item = (&Capability, &Denial)> {
        self.denied.iter().map(|(c, d)| (c, d))
    }

    /// Whether every request is granted.
    pub fn is_granted_in_full(&self) -> bool {
        self.denied.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(text: &str) -> Capability {
        text.parse().unwrap()
    }

    #[test]
    fn the_nearest_grant_is_named_only_when_one_comes_close() {
        let mut policy = Policy::new();
        policy
            .grant(cap("interface wasi:cli/environment@0.2"))
            .grant(cap("directory read /data"))
            .grant(cap("environment HOME"));
        let mut manifest = Manifest::new(Label::new("p").unwrap());
        manifest
            .request(cap("interface wasi:cli/environment@0.3.0"))
            .request(cap("interface wasi:cli/exit@0.2.0"))
            .request(cap("directory read-write /data/x"))
            .request(cap("directory read /other"))
            .request(cap("environment PATH"))
            .request(cap("network a.org:1"));
        let evaluation = policy.evaluate(&manifest);
        let denials: Vec<_> = evaluation.denied().map(|(_, d)| d.clone()).collect();
        assert_eq!(
            denials,
            [
                Denial::VersionMismatch {
                    granted: "wasi:cli/environment@0.2".parse().unwrap()
                },
                Denial::NotGranted,
                Denial::AccessExceeded {
                    granted: cap("directory read /data")
                },
                Denial::NotGranted,
                Denial::NotGranted,
                Denial::NotGranted,
            ]
        );
        assert!(evaluation.granted().next().is_none());
        assert!(!evaluation.is_granted_in_full());
        assert!(Decision::Denied(Denial::NotGranted).denial().is_some());
        assert!(
            Decision::Granted {
                by: cap("environment HOME")
            }
            .denial()
            .is_none()
        );
    }
}
