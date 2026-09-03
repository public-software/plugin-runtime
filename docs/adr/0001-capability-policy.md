# ADR-0001: A plugin gets what it requested and the host granted, nothing else

- Status: accepted
- Date: 2026-09-03
- Scope: this repository only (cross-repo decisions are RFCs in public-software/rfcs)

## Context

Every plugin of the suite is a WebAssembly component the host instantiates with exactly the imports and
resources it is allowed: which host interfaces are linked (`public:*` and `wasi:*`), which directories are
preopened, which environment variables are passed, which socket addresses the network check admits. The
Component Model names an interface `namespace:package/interface@version` and resolves an import by the
canonical prefix of its version (the major number above zero, else `0.minor`, else `0.0.patch`; a
pre-release exactly). WASI 0.2 is a set of such interfaces (`wasi:filesystem/types`, `wasi:sockets/tcp`,
`wasi:cli/environment`, …), so a WASI import and a `public:*` import are the same kind of thing; what
WASI adds is the resource behind the interface, and the documentation of the runtimes consulted (listed
in `PROVENANCE.md`) agrees on how that is granted: nothing by default, then named preopened directories
with a permission, named hosts, named variables. That model has to exist before the host does, so that
the host is plumbing over a settled policy and the manifest specification in `specs` has a model to
name.

## Decision

`pub-plugin-runtime-policy` is the model, with no dependency and no `unsafe_code`:

1. **Four capability kinds, one type.** `Capability::Interface(InterfaceName)`, `Directory { path:
   GuestPath, access: Access }`, `Environment(Variable)`, `Network { host: Host, port: Port }`. They are
   what a host configures: a linker entry, a preopen, an environment entry, a socket address check.
   Stdio is not a kind: `wasi:cli/stdin`, `stdout` and `stderr` are interfaces. Memory and time limits
   are not kinds: they are budgets, a later concern of the host.
2. **Names follow the Component Model.** An interface name's namespace and package are lowercase
   words, its interface a kebab-case label of words and acronyms, its version optional; nested
   namespaces are refused in this slice. A plugin's name is a label too. A `Version` is `major`,
   `major.minor` or `major.minor.patch` with the Semantic Versioning suffixes; two versions are
   compatible when their canonical prefixes are equal.
3. **A grant may be wider than a request; `covers` is the subsumption per kind.** An interface grant
   covers the same interface at a compatible version, or at any version when the grant names none; a
   request without a version is covered only by a grant without one. A directory grant covers its
   subtree with at least the requested access (read below read-write); a guest path is absolute and
   normalised. A variable grant is a name or a `PREFIX*`; a host grant is a name, an address or a
   `*.suffix` that covers names at least one label below it and narrower suffixes, never the apex; a
   port grant is a number or any. Kinds never cover each other.
4. **Two conditions, checked in this order.** `Policy::decide(manifest, capability)` is `Granted { by }`
   when some request of the manifest covers the capability and some grant of the policy covers it; else
   `Denied(NotRequested)` when the manifest never asked, whatever the policy says; else the nearest
   grant is named (`VersionMismatch { granted }` for the same interface at an incompatible version,
   `AccessExceeded { granted }` for the same directory with narrower access), else `NotGranted`. An
   empty policy is the default and denies everything. `Policy::evaluate(manifest)` decides every
   request and returns the granted requests as requested (the host preopens and links what the plugin
   asked for, never the wider grant) and the denials in the manifest's order.
5. **One line per capability.** `interface wasi:filesystem/types@0.2.8`, `directory read-write /data`,
   `environment PUB_*`, `network *.example.org:443` (IPv6 in brackets); `FromStr` and `Display` round
   trip, every part refuses malformed text with the part, the text and a reason. This is the form a
   policy file and a manifest can use until the plugin ABI specification fixes theirs.

## Consequences

- The host crate maps kinds to Wasmtime without judgment of its own: granted interfaces are linked,
  granted directories preopened with the access as the permission, granted variables passed, and the
  socket address check is `Policy::decide` on a `Network` capability. An `Evaluation` with denials is
  the host's reason to refuse instantiation or the UI's list of what to ask the user.
- The manifest specification in `specs` names capabilities in these four kinds; its file format
  (TOML, JSON or a custom section of the component) is its decision, and a parser of it lands here as a
  separate crate or feature. Until then the text form above is what tests and tools use.
- Deferred, with the shape known: CIDR ranges for `Host::Address`, a `Deny` list inside a policy (today
  a policy only grants), resource budgets, and the `stdio` interfaces' streams (interfaces already).
