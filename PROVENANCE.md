# Provenance

This repository is a spec-first cleanroom implementation. Record here what was consulted.

## Specifications used
- WebAssembly Component Model, "Component Model AST Explainer" (design/mvp/Explainer.md of
  https://github.com/WebAssembly/component-model, Apache-2.0; consulted 2026-09-03): the grammar of
  import and export names (`label`, `word`, `acronym`, `interfacename`, `namespace`, `words`,
  `projection`, `interfaceversion`) and the "Canonical interface name" rule that splits a version after
  the major number when it is above zero, else after the minor number when it is above zero, else keeps
  it whole, and never splits a pre-release. `Label`, `InterfaceName` and `Version::canonical` in
  `pub-plugin-runtime-policy` follow these; nested namespaces and packages (the 🪺 feature) are refused.
- WebAssembly Component Model, "The `wit` format" (design/mvp/WIT.md of the same repository,
  Apache-2.0): the `package-decl` and `use-path` productions (`id:id/id@valid-semver`), the kebab-case
  identifier form and its `%` escape, and the example `wasi:http/types@1.0.0`.
- Semantic Versioning 2.0.0 (https://semver.org/spec/v2.0.0.html, CC BY 3.0): the
  `major.minor.patch(-pre)(+build)` syntax, no leading zeros in numeric parts, the identifier rules of
  pre-release and build metadata. `Version::parse` implements these and additionally accepts the
  one- and two-number canonical prefixes.
- WASI CLI world, `wit/command.wit` and `wit/imports.wit` of https://github.com/WebAssembly/wasi-cli
  at `wasi:cli@0.2.8` (published by the WebAssembly Community Group under the W3C Community
  Contributor License Agreement): the interfaces a command imports (`wasi:clocks`, `wasi:filesystem`,
  `wasi:sockets`, `wasi:random`, `wasi:io`, and the `wasi:cli` environment, exit, stdio and terminal
  interfaces), each a named interface. This is why a WASI import and a `public:*` import are the same
  capability kind (`Capability::Interface`) and why stdio is not a kind of its own.

## Behavioural references (cited, not copied)
- Wasmtime, `wasmtime_wasi::WasiCtxBuilder` API documentation
  (https://docs.wasmtime.dev/api/wasmtime_wasi/struct.WasiCtxBuilder.html, documentation of an
  Apache-2.0 WITH LLVM-exception project): a guest has no preopened directory, no environment variable,
  no argument, a closed stdin and no TCP, UDP or name lookup unless the builder grants them
  (`preopened_dir` with directory and file permissions, `env`, `inherit_network`, `allow_tcp`,
  `allow_udp`, `allow_ip_name_lookup`, `socket_addr_check` per address). The deny-by-default rule, the
  directory-with-access and the per-address network capability of `pub-plugin-runtime-policy` follow
  this; the library's source was not opened.
- Extism, "The Manifest" (https://extism.org/docs/concepts/manifest/, documentation of a BSD-3-Clause
  project): `allowed_hosts` grants nothing when empty and `allowed_paths` maps host paths to the paths
  the plugin sees and grants no file access when empty or absent. The guest-side path (`GuestPath`) and
  the empty-policy-denies rule follow this; the library's source was not opened.

## Copyleft sources
None consulted. Contributors who have studied GPL/AGPL implementations of this domain do not author the corresponding modules (two-team rule; see the Charter §09).

## AI assistance
Prompts point at the specifications and conformance suites above, never at copyleft source. Generated code is reviewed against this list before merge.
