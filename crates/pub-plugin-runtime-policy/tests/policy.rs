//! The capability policy, end to end: the names, the subsumption per kind, the two conditions
//! (requested and granted), the reasons, and the textual form.

use pub_plugin_runtime_policy::{
    Access, Capability, Decision, Denial, Error, GuestPath, Host, InterfaceName, Label, Manifest,
    Policy, Port, Variable, Version,
};

fn cap(text: &str) -> Capability {
    text.parse()
        .unwrap_or_else(|e: Error| panic!("{text}: {e}"))
}

fn manifest(requests: &[&str]) -> Manifest {
    let mut m = Manifest::new(Label::new("example").unwrap());
    for r in requests {
        m.request(cap(r));
    }
    m
}

fn policy(grants: &[&str]) -> Policy {
    let mut p = Policy::new();
    for g in grants {
        p.grant(cap(g));
    }
    p
}

// ---- names ---------------------------------------------------------------------------------

#[test]
fn labels_are_kebab_case_words_and_acronyms() {
    for ok in [
        "foo",
        "red-green-blue",
        "parse-XML-document",
        "a1",
        "XML",
        "foo-1",
        "x",
    ] {
        assert_eq!(Label::new(ok).unwrap().as_str(), ok);
    }
    for bad in [
        "", "Foo", "foo--bar", "-foo", "foo-", "foo_bar", "1foo", "fooBar", "XMl", "foo bar", "föö",
    ] {
        let err = Label::new(bad).unwrap_err();
        assert_eq!(err.input(), bad);
        assert!(!err.reason().is_empty(), "{bad}");
    }
}

#[test]
fn interface_names_parse_and_print_canonically() {
    let name: InterfaceName = "wasi:filesystem/types@0.2.8".parse().unwrap();
    assert_eq!(name.namespace(), "wasi");
    assert_eq!(name.package(), "filesystem");
    assert_eq!(name.interface().as_str(), "types");
    assert_eq!(
        name.version().map(Version::to_string).as_deref(),
        Some("0.2.8")
    );
    assert_eq!(name.to_string(), "wasi:filesystem/types@0.2.8");

    let bare: InterfaceName = "public:doc/graph".parse().unwrap();
    assert_eq!(bare.version(), None);
    assert_eq!(bare.to_string(), "public:doc/graph");

    let hyphenated: InterfaceName = "wasi:foo-bar/baz-qux@1".parse().unwrap();
    assert_eq!(hyphenated.package(), "foo-bar");
    assert_eq!(hyphenated.to_string(), "wasi:foo-bar/baz-qux@1");

    let pre: InterfaceName = "public:ui/widget@1.0.0-alpha.1+build.5".parse().unwrap();
    assert_eq!(pre.to_string(), "public:ui/widget@1.0.0-alpha.1+build.5");

    for bad in [
        "",
        "wasi",
        "wasi:filesystem",
        "wasi/types",
        "wasi:filesystem/",
        ":filesystem/types",
        "Wasi:filesystem/types",
        "wasi:filesystem/types@",
        "wasi:filesystem/types@abc",
        "wasi:filesystem/types@1.2.3.4",
        "wasi:filesystem/types@01.2.3",
        "wasi:a:b/c/d",
        "wasi:file system/types",
        "wasi:filesystem/Types",
    ] {
        let err = bad.parse::<InterfaceName>().unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }
}

#[test]
fn versions_canonicalise_by_the_component_model_rule() {
    let canonical = |v: &str| v.parse::<Version>().unwrap().canonical().to_string();
    assert_eq!(canonical("1.2.3"), "1");
    assert_eq!(canonical("1"), "1");
    assert_eq!(canonical("0.2.6"), "0.2");
    assert_eq!(canonical("0.2"), "0.2");
    assert_eq!(canonical("0.0.1"), "0.0.1");
    assert_eq!(canonical("0.0.0"), "0.0.0");
    assert_eq!(canonical("0"), "0.0.0");
    assert_eq!(canonical("1.0.0-alpha"), "1.0.0-alpha");
    assert_eq!(canonical("0.0.1+sha.5114f85"), "0.0.1");
    assert_eq!(canonical("0.0.1-alpha+sha.5114f85"), "0.0.1-alpha");

    let compatible = |a: &str, b: &str| {
        a.parse::<Version>()
            .unwrap()
            .is_compatible_with(&b.parse::<Version>().unwrap())
    };
    assert!(compatible("0.2", "0.2.8"));
    assert!(compatible("0.2.8", "0.2.0"));
    assert!(compatible("1", "1.4.0"));
    assert!(compatible("1.4.0", "1.9.9"));
    assert!(compatible("0.0.1", "0.0.1+meta"));
    assert!(!compatible("0.2.8", "0.3.0"));
    assert!(!compatible("1.0.0", "2.0.0"));
    assert!(!compatible("0.0.1", "0.0.2"));
    assert!(!compatible("1.0.0-alpha", "1.0.0"));
    assert!(!compatible("1.0.0-alpha", "1.0.0-beta"));

    for bad in [
        "",
        "01.2.3",
        "1.2.03",
        "1.2.3-",
        "1.2.3+",
        "a",
        "1.-2",
        "1..2",
        "1.2.3-a b",
        " 1",
    ] {
        let err = bad.parse::<Version>().unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }
}

// ---- scopes --------------------------------------------------------------------------------

#[test]
fn guest_paths_are_absolute_and_normalised() {
    for ok in ["/", "/data", "/data/logs", "/a/b c/d.e"] {
        assert_eq!(GuestPath::parse(ok).unwrap().to_string(), ok);
    }
    for bad in [
        "",
        "data",
        "/data/",
        "//",
        "/data//x",
        "/data/./x",
        "/data/../x",
        "/.",
        "/data\0x",
    ] {
        let err = GuestPath::parse(bad).unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }
    let root = GuestPath::parse("/").unwrap();
    let data = GuestPath::parse("/data").unwrap();
    let logs = GuestPath::parse("/data/logs").unwrap();
    let database = GuestPath::parse("/database").unwrap();
    assert!(root.covers(&root));
    assert!(root.covers(&logs));
    assert!(data.covers(&data));
    assert!(data.covers(&logs));
    assert!(!data.covers(&database));
    assert!(!logs.covers(&data));
    assert!(!data.covers(&root));
}

#[test]
fn access_is_ordered_read_below_read_write() {
    assert!(Access::ReadWrite.allows(Access::Read));
    assert!(Access::ReadWrite.allows(Access::ReadWrite));
    assert!(Access::Read.allows(Access::Read));
    assert!(!Access::Read.allows(Access::ReadWrite));
    assert!(Access::Read < Access::ReadWrite);
    assert_eq!(Access::Read.to_string(), "read");
    assert_eq!(Access::ReadWrite.to_string(), "read-write");
    assert_eq!("read-write".parse::<Access>().unwrap(), Access::ReadWrite);
    assert!("rw".parse::<Access>().is_err());
}

#[test]
fn hosts_are_names_addresses_or_suffix_patterns() {
    assert_eq!(
        Host::parse("api.example.org").unwrap().to_string(),
        "api.example.org"
    );
    assert_eq!(
        Host::parse("API.Example.org").unwrap().to_string(),
        "api.example.org"
    );
    assert_eq!(Host::parse("localhost").unwrap().to_string(), "localhost");
    assert_eq!(Host::parse("127.0.0.1").unwrap().to_string(), "127.0.0.1");
    assert_eq!(Host::parse("[::1]").unwrap().to_string(), "[::1]");
    assert_eq!(
        Host::parse("*.example.org").unwrap().to_string(),
        "*.example.org"
    );
    for bad in [
        "",
        "*",
        "*.",
        "*example.org",
        "**.example.org",
        "a.*.org",
        "-bad.org",
        "bad-.org",
        ".org",
        "org.",
        "a..b",
        "[::1",
        "::1",
        "a_b.org",
        "ex ample.org",
        "1.2.3",
    ] {
        let err = Host::parse(bad).unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }

    let any_sub = Host::parse("*.example.org").unwrap();
    let api = Host::parse("api.example.org").unwrap();
    let deep = Host::parse("a.b.example.org").unwrap();
    let apex = Host::parse("example.org").unwrap();
    let lookalike = Host::parse("xexample.org").unwrap();
    let any_org = Host::parse("*.org").unwrap();
    assert!(any_sub.covers(&api));
    assert!(any_sub.covers(&deep));
    assert!(any_sub.covers(&any_sub));
    assert!(!any_sub.covers(&apex));
    assert!(!any_sub.covers(&lookalike));
    assert!(any_org.covers(&any_sub));
    assert!(!any_sub.covers(&any_org));
    assert!(api.covers(&api));
    assert!(!api.covers(&deep));
    assert!(!api.covers(&any_sub));
    let v4 = Host::parse("127.0.0.1").unwrap();
    assert!(v4.covers(&v4));
    assert!(!any_org.covers(&v4));
}

#[test]
fn ports_are_numbers_or_any() {
    assert_eq!("443".parse::<Port>().unwrap(), Port::Number(443));
    assert_eq!("*".parse::<Port>().unwrap(), Port::Any);
    assert_eq!(Port::Number(8080).to_string(), "8080");
    assert_eq!(Port::Any.to_string(), "*");
    for bad in ["", "70000", "abc", "-1", "0x1", "443 "] {
        let err = bad.parse::<Port>().unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }
    assert!(Port::Any.covers(Port::Number(443)));
    assert!(Port::Any.covers(Port::Any));
    assert!(Port::Number(443).covers(Port::Number(443)));
    assert!(!Port::Number(443).covers(Port::Number(80)));
    assert!(!Port::Number(443).covers(Port::Any));
}

#[test]
fn variables_are_names_or_prefix_patterns() {
    assert_eq!(Variable::parse("HOME").unwrap().to_string(), "HOME");
    assert_eq!(Variable::parse("_x1").unwrap().to_string(), "_x1");
    assert_eq!(Variable::parse("PUB_*").unwrap().to_string(), "PUB_*");
    for bad in ["", "1X", "PU*B", "*", "a-b", "A B", "A=1", "PUB_**"] {
        let err = Variable::parse(bad).unwrap_err();
        assert_eq!(err.input(), bad, "{err}");
    }
    let pub_any = Variable::parse("PUB_*").unwrap();
    let pub_home = Variable::parse("PUB_HOME").unwrap();
    let pub_x_any = Variable::parse("PUB_X*").unwrap();
    let home = Variable::parse("HOME").unwrap();
    assert!(pub_any.covers(&pub_home));
    assert!(pub_any.covers(&pub_any));
    assert!(pub_any.covers(&pub_x_any));
    assert!(!pub_x_any.covers(&pub_any));
    assert!(!pub_any.covers(&home));
    assert!(home.covers(&home));
    assert!(!pub_home.covers(&pub_any));
}

// ---- the textual form ----------------------------------------------------------------------

#[test]
fn capabilities_round_trip_through_their_text() {
    for text in [
        "interface wasi:filesystem/types@0.2.8",
        "interface public:doc/graph",
        "directory read /data/logs",
        "directory read-write /",
        "environment HOME",
        "environment PUB_*",
        "network api.example.org:443",
        "network *.example.org:*",
        "network [::1]:8080",
        "network 127.0.0.1:53",
    ] {
        assert_eq!(cap(text).to_string(), text);
    }
    assert_eq!(
        cap("  directory   read   /data  ").to_string(),
        "directory read /data"
    );
    assert_eq!(
        cap("interface wasi:filesystem/types@0.2.8"),
        Capability::interface("wasi:filesystem/types@0.2.8").unwrap()
    );
    assert_eq!(
        cap("directory read /data"),
        Capability::directory("/data", Access::Read).unwrap()
    );
    assert_eq!(
        cap("environment HOME"),
        Capability::environment("HOME").unwrap()
    );
    assert_eq!(
        cap("network *.example.org:*"),
        Capability::network("*.example.org", Port::Any).unwrap()
    );

    for bad in [
        "",
        "interface",
        "interface wasi:filesystem",
        "directory /data",
        "directory rw /data",
        "directory read data",
        "directory read",
        "environment",
        "environment 1X",
        "network",
        "network api.example.org",
        "network [::1]",
        "network api.example.org:99999",
        "network :443",
        "teleport anywhere",
        "interface wasi:filesystem/types extra",
    ] {
        let err = bad.parse::<Capability>().unwrap_err();
        assert!(!err.reason().is_empty(), "{bad:?}");
        assert!(!err.to_string().is_empty());
    }
}

// ---- decisions -----------------------------------------------------------------------------

const REQUESTS: [&str; 4] = [
    "interface wasi:filesystem/types@0.2.8",
    "directory read /data",
    "environment HOME",
    "network api.example.org:443",
];

#[test]
fn an_empty_policy_denies_everything() {
    let m = manifest(&REQUESTS);
    let p = Policy::new();
    assert_eq!(p, Policy::default());
    assert!(p.grants().next().is_none());
    for r in REQUESTS {
        assert_eq!(
            p.decide(&m, &cap(r)),
            Decision::Denied(Denial::NotGranted),
            "{r}"
        );
    }
    let evaluation = p.evaluate(&m);
    assert!(evaluation.granted().next().is_none());
    assert_eq!(evaluation.denied().count(), 4);
    assert!(!evaluation.is_granted_in_full());
}

#[test]
fn what_the_manifest_never_requested_is_denied_even_when_granted() {
    let m = manifest(&["directory read /data"]);
    let p = policy(&REQUESTS);
    for r in [
        "interface wasi:filesystem/types@0.2.8",
        "environment HOME",
        "network api.example.org:443",
    ] {
        assert_eq!(
            p.decide(&m, &cap(r)),
            Decision::Denied(Denial::NotRequested),
            "{r}"
        );
    }
    assert_eq!(
        p.decide(&m, &cap("directory read /data")),
        Decision::Granted {
            by: cap("directory read /data")
        }
    );
    let evaluation = p.evaluate(&m);
    assert_eq!(
        evaluation.granted().cloned().collect::<Vec<_>>(),
        vec![cap("directory read /data")]
    );
    assert!(evaluation.is_granted_in_full());
}

#[test]
fn what_was_requested_but_not_granted_is_denied_with_the_reason() {
    let m = manifest(&REQUESTS);
    let p = policy(&["environment HOME", "network api.example.org:443"]);
    assert_eq!(
        p.decide(&m, &cap("interface wasi:filesystem/types@0.2.8")),
        Decision::Denied(Denial::NotGranted)
    );
    assert_eq!(
        p.decide(&m, &cap("directory read /data")),
        Decision::Denied(Denial::NotGranted)
    );
    let evaluation = p.evaluate(&m);
    let denied: Vec<_> = evaluation.denied().collect();
    assert_eq!(denied.len(), 2);
    assert_eq!(
        denied,
        vec![
            (
                &cap("interface wasi:filesystem/types@0.2.8"),
                &Denial::NotGranted
            ),
            (&cap("directory read /data"), &Denial::NotGranted),
        ]
    );
    assert_eq!(evaluation.granted().count(), 2);
    assert!(Denial::NotGranted.to_string().contains("not granted"));
    assert!(Denial::NotRequested.to_string().contains("not requested"));
}

#[test]
fn an_interface_grant_covers_compatible_versions_and_names_the_grant_otherwise() {
    let m = manifest(&[
        "interface wasi:filesystem/types@0.2.8",
        "interface public:doc/graph@1.4.0",
        "interface public:ui/widget@0.3.0",
        "interface public:media/frame",
    ]);
    let p = policy(&[
        "interface wasi:filesystem/types@0.2",
        "interface public:doc/graph@1",
        "interface public:ui/widget@0.2",
        "interface public:media/frame@2.0.0",
    ]);
    assert_eq!(
        p.decide(&m, &cap("interface wasi:filesystem/types@0.2.8")),
        Decision::Granted {
            by: cap("interface wasi:filesystem/types@0.2")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("interface public:doc/graph@1.4.0")),
        Decision::Granted {
            by: cap("interface public:doc/graph@1")
        }
    );
    let mismatch = p.decide(&m, &cap("interface public:ui/widget@0.3.0"));
    let granted: InterfaceName = "public:ui/widget@0.2".parse().unwrap();
    assert_eq!(
        mismatch,
        Decision::Denied(Denial::VersionMismatch {
            granted: granted.clone()
        })
    );
    assert!(
        mismatch
            .denial()
            .unwrap()
            .to_string()
            .contains("public:ui/widget@0.2")
    );
    // A versionless request is only covered by a versionless grant.
    assert_eq!(
        p.decide(&m, &cap("interface public:media/frame")),
        Decision::Denied(Denial::VersionMismatch {
            granted: "public:media/frame@2.0.0".parse().unwrap()
        })
    );
    let open = policy(&["interface public:media/frame"]);
    let m2 = manifest(&[
        "interface public:media/frame",
        "interface public:media/frame@3.1.0",
    ]);
    assert_eq!(
        open.decide(&m2, &cap("interface public:media/frame")),
        Decision::Granted {
            by: cap("interface public:media/frame")
        }
    );
    assert_eq!(
        open.decide(&m2, &cap("interface public:media/frame@3.1.0")),
        Decision::Granted {
            by: cap("interface public:media/frame")
        }
    );
    // Another interface of the same package is not the same capability.
    let m3 = manifest(&["interface wasi:filesystem/preopens@0.2.8"]);
    assert_eq!(
        p.decide(&m3, &cap("interface wasi:filesystem/preopens@0.2.8")),
        Decision::Denied(Denial::NotGranted)
    );
}

#[test]
fn a_directory_grant_covers_its_subtree_with_at_least_the_access_requested() {
    let m = manifest(&[
        "directory read /data/logs",
        "directory read-write /data/cache",
        "directory read-write /etc",
        "directory read /database",
    ]);
    let p = policy(&["directory read-write /data", "directory read /etc"]);
    assert_eq!(
        p.decide(&m, &cap("directory read /data/logs")),
        Decision::Granted {
            by: cap("directory read-write /data")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("directory read-write /data/cache")),
        Decision::Granted {
            by: cap("directory read-write /data")
        }
    );
    let exceeded = p.decide(&m, &cap("directory read-write /etc"));
    assert_eq!(
        exceeded,
        Decision::Denied(Denial::AccessExceeded {
            granted: cap("directory read /etc")
        })
    );
    assert!(
        exceeded
            .denial()
            .unwrap()
            .to_string()
            .contains("directory read /etc")
    );
    assert_eq!(
        p.decide(&m, &cap("directory read /database")),
        Decision::Denied(Denial::NotGranted)
    );

    let root = policy(&["directory read-write /"]);
    let evaluation = root.evaluate(&m);
    assert!(evaluation.is_granted_in_full());
    // The host preopens what was requested, not the wider grant.
    assert_eq!(evaluation.granted().count(), 4);
    assert!(
        evaluation
            .granted()
            .any(|c| *c == cap("directory read /data/logs"))
    );
}

#[test]
fn network_and_environment_grants_cover_by_pattern() {
    let m = manifest(&[
        "network api.example.org:443",
        "network api.example.org:8443",
        "network example.org:443",
        "network cdn.example.net:80",
        "network 127.0.0.1:53",
        "environment PUB_HOME",
        "environment HOME",
    ]);
    let p = policy(&[
        "network *.example.org:443",
        "network *.example.net:*",
        "network 127.0.0.1:*",
        "environment PUB_*",
    ]);
    assert_eq!(
        p.decide(&m, &cap("network api.example.org:443")),
        Decision::Granted {
            by: cap("network *.example.org:443")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("network api.example.org:8443")),
        Decision::Denied(Denial::NotGranted)
    );
    assert_eq!(
        p.decide(&m, &cap("network example.org:443")),
        Decision::Denied(Denial::NotGranted)
    );
    assert_eq!(
        p.decide(&m, &cap("network cdn.example.net:80")),
        Decision::Granted {
            by: cap("network *.example.net:*")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("network 127.0.0.1:53")),
        Decision::Granted {
            by: cap("network 127.0.0.1:*")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("environment PUB_HOME")),
        Decision::Granted {
            by: cap("environment PUB_*")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("environment HOME")),
        Decision::Denied(Denial::NotGranted)
    );
    let evaluation = p.evaluate(&m);
    assert_eq!(evaluation.granted().count(), 4);
    assert_eq!(evaluation.denied().count(), 3);
}

#[test]
fn a_request_covers_the_narrower_uses_a_host_asks_about() {
    let m = manifest(&[
        "directory read /data",
        "network *.example.org:*",
        "environment PUB_*",
    ]);
    let p = policy(&[
        "directory read-write /",
        "network *.org:*",
        "environment PUB_*",
    ]);
    assert_eq!(
        p.decide(&m, &cap("directory read /data/logs/today")),
        Decision::Granted {
            by: cap("directory read-write /")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("directory read-write /data/logs")),
        Decision::Denied(Denial::NotRequested)
    );
    assert_eq!(
        p.decide(&m, &cap("directory read /etc")),
        Decision::Denied(Denial::NotRequested)
    );
    assert_eq!(
        p.decide(&m, &cap("network api.example.org:443")),
        Decision::Granted {
            by: cap("network *.org:*")
        }
    );
    assert_eq!(
        p.decide(&m, &cap("network example.org:443")),
        Decision::Denied(Denial::NotRequested)
    );
    assert_eq!(
        p.decide(&m, &cap("environment PUB_HOME")),
        Decision::Granted {
            by: cap("environment PUB_*")
        }
    );
    assert!(p.decide(&m, &cap("environment PUB_HOME")).is_granted());
    assert!(!p.decide(&m, &cap("environment HOME")).is_granted());
}

#[test]
fn manifests_and_policies_are_sets_under_a_label() {
    let mut m = Manifest::new(Label::new("my-plugin").unwrap());
    assert_eq!(m.name().as_str(), "my-plugin");
    m.request(cap("environment HOME"))
        .request(cap("environment HOME"));
    assert_eq!(m.requests().count(), 1);
    assert!(m.requests_cover(&cap("environment HOME")));
    assert!(!m.requests_cover(&cap("environment PATH")));

    let mut p = Policy::new();
    p.grant(cap("environment HOME"))
        .grant(cap("environment HOME"));
    assert_eq!(p.grants().count(), 1);
    assert!(p.grants_cover(&cap("environment HOME")));

    assert!(Label::new("My Plugin").is_err());
    assert_eq!(
        Capability::interface("nope").unwrap_err().to_string(),
        "nope".parse::<InterfaceName>().unwrap_err().to_string()
    );
}
