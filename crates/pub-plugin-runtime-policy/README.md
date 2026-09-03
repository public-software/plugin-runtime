# pub-plugin-runtime-policy

The `policy` library of [plugin-runtime](https://github.com/public-software/plugin-runtime), part of Public Software. Kind: `lib`.

The capability policy a plugin host enforces, settled before the host exists. A plugin's `Manifest`
requests capabilities, a host's `Policy` grants some, and a `Capability` is one of four kinds, which are
what a Component Model host has to configure: an `Interface` to link (`public:*` and `wasi:*` imports
alike, named `namespace:package/interface@version` the Component Model way), a `Directory` to preopen
(an absolute guest path with `read` or `read-write` access), an `Environment` variable to pass (a name or
a `PREFIX*`), and a `Network` address to admit (a host, an IP address or a `*.suffix`, and a port or
any). A grant may be wider than a request (`Capability::covers`: any or a compatible version under the
Component Model's canonical-prefix rule, a parent directory with at least the access, a prefix, a
suffix, any port). Two conditions decide and both must hold: the manifest requested it and a grant
covers it. `Policy::decide` answers for one capability with a `Decision` whose denial carries its
reason (`NotRequested`, `NotGranted`, `VersionMismatch` naming the grant, `AccessExceeded` naming the
grant); `Policy::evaluate` answers for a whole manifest with the granted requests, as requested, and the
denials. An empty policy denies everything. Every kind has a one-line text form that round-trips. The
design is [ADR-0001](../../docs/adr/0001-capability-policy.md); the references are in the repository's
`PROVENANCE.md`.

Not here, on purpose: the manifest file format (the plugin ABI specification in `specs`), the host that
links and preopens (the next crate), resource budgets (memory, time). No dependency, no `unsafe_code`.

```rust
use pub_plugin_runtime_policy::{Decision, Denial, Label, Manifest, Policy};

let mut manifest = Manifest::new(Label::new("word-count")?);
manifest
    .request("interface wasi:filesystem/types@0.2.8".parse()?)
    .request("directory read /documents".parse()?);

let mut policy = Policy::new();
policy.grant("interface wasi:filesystem/types@0.2".parse()?).grant("directory read-write /".parse()?);

assert!(policy.evaluate(&manifest).is_granted_in_full());
let home = "environment HOME".parse()?;
assert_eq!(policy.decide(&manifest, &home), Decision::Denied(Denial::NotRequested));
```

```sh
cargo nextest run -p pub-plugin-runtime-policy
```

Its entry in the repository's `CATALOG.toml`:

```toml
[[component]]
crate     = "pub-plugin-runtime-policy"
kind      = "lib"
ledger    = "plugin-runtime"
readiness = "seed"
effort    = 3
specs     = ["component-model-wit"]
provides  = []
requires  = []
```
