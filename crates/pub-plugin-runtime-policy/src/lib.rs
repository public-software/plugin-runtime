//! `pub-plugin-runtime-policy` — the `policy` library of
//! [`plugin-runtime`](https://github.com/public-software/plugin-runtime).
//!
//! The capability policy a plugin host enforces, settled before the host exists. A plugin's
//! [`Manifest`] requests capabilities; a host's [`Policy`] grants some; a [`Capability`] is
//! one of four kinds, which are what a Component Model host has to configure: an
//! [`Interface`](Capability::Interface) to link (`public:*` and `wasi:*` imports alike, named
//! `namespace:package/interface@version` by an [`InterfaceName`]), a
//! [`Directory`](Capability::Directory) to preopen (a [`GuestPath`] with an [`Access`]), an
//! [`Environment`](Capability::Environment) variable to pass (a [`Variable`], or a `PREFIX*`
//! of them), and a [`Network`](Capability::Network) address to admit (a [`Host`], or a
//! `*.suffix` of them, and a [`Port`]). A grant may be wider than a request
//! ([`Capability::covers`]): any or a compatible [`Version`] of an interface, a parent
//! directory with at least the access, a prefix, a suffix, any port.
//!
//! Two conditions decide, and both must hold: the manifest requested the capability (or one
//! covering it) and a grant covers it. [`Policy::decide`] answers for one capability with a
//! [`Decision`], the denial carrying its [`Denial`] reason (not requested, not granted, the
//! same interface at an incompatible version, the same directory with narrower access);
//! [`Policy::evaluate`] answers for a whole manifest with an [`Evaluation`]: the granted
//! requests, as requested, and the denials. An empty policy denies everything.
//!
//! Every kind has a one-line text form, so policies and manifests can be written as text:
//!
//! ```
//! use pub_plugin_runtime_policy::{Capability, Decision, Denial, Label, Manifest, Policy};
//!
//! let mut manifest = Manifest::new(Label::new("word-count")?);
//! manifest
//!     .request("interface wasi:filesystem/types@0.2.8".parse()?)
//!     .request("directory read /documents".parse()?)
//!     .request("network api.example.org:443".parse()?);
//!
//! let mut policy = Policy::new();
//! policy
//!     .grant("interface wasi:filesystem/types@0.2".parse()?)
//!     .grant("directory read-write /".parse()?);
//!
//! let evaluation = policy.evaluate(&manifest);
//! assert_eq!(evaluation.granted().count(), 2);
//! let (denied, why) = evaluation.denied().next().unwrap();
//! assert_eq!(denied.to_string(), "network api.example.org:443");
//! assert_eq!(*why, Denial::NotGranted);
//!
//! let unrequested: Capability = "environment HOME".parse()?;
//! assert_eq!(policy.decide(&manifest, &unrequested), Decision::Denied(Denial::NotRequested));
//! # Ok::<(), pub_plugin_runtime_policy::Error>(())
//! ```
//!
//! Not here: the manifest file format (the plugin ABI specification in the `specs`
//! repository), the host that links and preopens (the next crate of this repository), and
//! resource limits (memory, time), which are budgets rather than capabilities. The crate has
//! no dependency and is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

mod capability;
mod error;
mod name;
mod net;
mod path;
mod policy;
mod version;

pub use capability::Capability;
pub use error::{Error, What};
pub use name::{InterfaceName, Label};
pub use net::{Host, Port, Variable};
pub use path::{Access, GuestPath};
pub use policy::{Decision, Denial, Evaluation, Manifest, Policy};
pub use version::Version;
