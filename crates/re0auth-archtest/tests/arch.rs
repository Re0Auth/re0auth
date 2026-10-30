use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn metadata() -> serde_json::Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .expect("cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("metadata is JSON")
}

#[derive(Default)]
struct DepGraph {
    packages: BTreeSet<String>,
    normal: BTreeMap<String, BTreeSet<String>>,
    dev: BTreeMap<String, BTreeSet<String>>,
    build: BTreeMap<String, BTreeSet<String>>,
}

fn dep_graph() -> DepGraph {
    let meta = metadata();
    let mut graph = DepGraph::default();
    for pkg in meta["packages"].as_array().expect("packages") {
        let name = pkg["name"].as_str().expect("name").to_string();
        graph.packages.insert(name.clone());
        graph.normal.entry(name.clone()).or_default();
        for dep in pkg["dependencies"].as_array().expect("dependencies") {
            let dep_name = dep["name"].as_str().expect("dep name");
            if !dep_name.starts_with("re0auth-") {
                continue;
            }
            let bucket = match dep["kind"].as_str() {
                Some("dev") => &mut graph.dev,
                Some("build") => &mut graph.build,
                _ => &mut graph.normal,
            };
            bucket
                .entry(name.clone())
                .or_default()
                .insert(dep_name.to_string());
        }
    }
    graph
}

fn workspace_deps() -> BTreeMap<String, BTreeSet<String>> {
    dep_graph().normal
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|s| s.to_str()) == Some("target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn production_rust_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    rust_files(&root().join("crates"), &mut files);
    // `src/` only: the rules below police implementation code. A test harness may
    // legitimately spawn tasks (e.g. to race two writers against one constraint).
    files.retain(|path| {
        let rel = rel(path);
        !rel.starts_with("crates/re0auth-archtest/") && !rel.contains("/tests/")
    });
    files
}

fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .expect("inside workspace")
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_lower_hex(c: char) -> bool {
    c.is_ascii_digit() || ('a'..='f').contains(&c)
}

/// The declared surface of the composition root, by exact repo-relative path.
///
/// `AGENTS.md` §3.2 names what belongs in `re0auth-server`: assembly, config, env
/// overrides, the admin CLI. Listing the files rather than describing them is what
/// makes an addition visible — a new module has to be added here on purpose.
const COMPOSITION_ROOT_MODULES: &[&str] = &[
    "crates/re0auth-server/src/cli.rs",
    "crates/re0auth-server/src/config.rs",
    // Unit tests for private config parsing; no routing or policy lives here.
    "crates/re0auth-server/src/config/tests.rs",
    "crates/re0auth-server/src/config_env.rs",
    "crates/re0auth-server/src/main.rs",
];

const REGISTERED_CRATES: &[&str] = &[
    "re0auth-api",
    "re0auth-domain",
    "re0auth-app",
    "re0auth-adapters",
    "re0auth-connectors",
    "re0auth-idp",
    "re0auth-runtime",
    "re0auth-http",
    "re0auth-server",
    "re0auth-upstream-kit",
    "re0auth-contract",
    "re0auth-archtest",
];

#[test]
fn the_six_production_crates_exist() {
    let deps = workspace_deps();
    for name in [
        "re0auth-api",
        "re0auth-domain",
        "re0auth-app",
        "re0auth-adapters",
        "re0auth-http",
        "re0auth-server",
    ] {
        assert!(deps.contains_key(name), "missing workspace crate {name}");
    }
}

#[test]
fn every_workspace_crate_is_registered() {
    let graph = dep_graph();
    let unregistered: Vec<_> = graph
        .packages
        .iter()
        .filter(|name| !REGISTERED_CRATES.contains(&name.as_str()))
        .cloned()
        .collect();
    assert!(
        unregistered.is_empty(),
        "unregistered workspace crates: {unregistered:?}; add them to REGISTERED_CRATES and the dependency whitelist before merging"
    );
    for name in REGISTERED_CRATES {
        assert!(
            graph.packages.contains(*name),
            "REGISTERED_CRATES lists missing workspace crate {name}"
        );
    }
}

#[test]
fn build_dependencies_are_forbidden() {
    let graph = dep_graph();
    let edges: Vec<String> = graph
        .build
        .iter()
        .flat_map(|(pkg, deps)| deps.iter().map(move |dep| format!("{pkg} -> {dep}")))
        .collect();
    assert!(
        edges.is_empty(),
        "workspace build dependencies are forbidden: {edges:?}"
    );
}

#[test]
fn dev_dependencies_are_limited_to_contract_suites() {
    let graph = dep_graph();
    let allowed = [
        ("re0auth-adapters", "re0auth-contract"),
        ("re0auth-connectors", "re0auth-contract"),
        ("re0auth-app", "re0auth-contract"),
        // The composition root is allowed to use the contract suite because the
        // end-to-end wiring test lives there: it is the only crate that may know
        // both the HTTP layer and the adapter implementations.
        ("re0auth-server", "re0auth-contract"),
        // `api_contract` compares the DTOs the SPA consumes against the zod
        // schemas in `web/src/lib/api.ts`. That is a check *on* those crates, so
        // it has to see their types; there is no way to assert a serialisation
        // shape without naming the type that produces it. The direction is
        // test-only and points away from production, which is why it does not
        // reopen the layering question.
        ("re0auth-archtest", "re0auth-http"),
        ("re0auth-archtest", "re0auth-app"),
        // `re0auth-api` for the same reason: `missing_bindings` is a
        // `Vec<MissingBinding>`, and the nested object has its own zod schema, so
        // the test has to build one. Same test-only direction as the two above.
        ("re0auth-archtest", "re0auth-api"),
    ];
    for (pkg, deps) in &graph.dev {
        for dep in deps {
            assert!(
                allowed.contains(&(pkg.as_str(), dep.as_str())),
                "dev edge {pkg} -> {dep} is not allowed; only adapters may dev-depend on the contract suite"
            );
        }
    }
}

#[test]
fn upstream_kit_has_no_internal_dependencies() {
    let deps = workspace_deps();
    let kit = deps
        .get("re0auth-upstream-kit")
        .expect("re0auth-upstream-kit must be a workspace member");
    assert!(
        kit.is_empty(),
        "re0auth-upstream-kit must stay standalone; found internal deps: {kit:?}"
    );
}

#[test]
fn dependency_direction_is_enforced() {
    let deps = workspace_deps();
    let expected: &[(&str, &[&str])] = &[
        ("re0auth-api", &[]),
        ("re0auth-domain", &["re0auth-api"]),
        ("re0auth-app", &["re0auth-api", "re0auth-domain"]),
        ("re0auth-adapters", &["re0auth-api", "re0auth-runtime"]),
        // ADR-0021: the two planes are separate crates and must not know each
        // other. Both may use `runtime`, which is infrastructure.
        ("re0auth-idp", &["re0auth-api", "re0auth-runtime"]),
        ("re0auth-connectors", &["re0auth-api", "re0auth-runtime"]),
        // ADR-0026: runtime is infrastructure, not a business adapter. It may
        // see the contract layer only, never a use case or another adapter.
        ("re0auth-runtime", &["re0auth-api"]),
        ("re0auth-contract", &["re0auth-api"]),
        ("re0auth-http", &["re0auth-api", "re0auth-app"]),
        (
            "re0auth-server",
            &[
                "re0auth-api",
                "re0auth-domain",
                "re0auth-app",
                "re0auth-adapters",
                "re0auth-connectors",
                "re0auth-idp",
                "re0auth-runtime",
                "re0auth-http",
            ],
        ),
        ("re0auth-archtest", &[]),
        ("re0auth-upstream-kit", &[]),
    ];

    for (crate_name, allowed) in expected {
        let actual = deps
            .get(*crate_name)
            .unwrap_or_else(|| panic!("missing workspace crate {crate_name}"));
        let allowed: BTreeSet<String> = allowed.iter().map(|s| s.to_string()).collect();
        let extra: Vec<_> = actual.difference(&allowed).cloned().collect();
        assert!(
            extra.is_empty(),
            "{crate_name} has disallowed workspace dependencies: {extra:?}"
        );
    }
}

#[test]
fn api_and_domain_have_no_runtime_or_io_dependencies() {
    let meta = metadata();
    for pkg in meta["packages"].as_array().expect("packages") {
        let name = pkg["name"].as_str().expect("name");
        if name != "re0auth-api" && name != "re0auth-domain" {
            continue;
        }
        for dep in pkg["dependencies"].as_array().expect("dependencies") {
            let dep_name = dep["name"].as_str().expect("dep name");
            for forbidden in ["tokio", "axum", "sqlx", "reqwest"] {
                assert_ne!(dep_name, forbidden, "{name} must not depend on {forbidden}");
            }
        }
    }
}

#[test]
fn reqwest_client_is_only_constructed_in_the_guarded_adapter() {
    let files = production_rust_files();
    assert!(
        files.len() >= 7,
        "only {} production Rust files found; the walk is not reading the tree",
        files.len()
    );
    for path in files {
        let text = fs::read_to_string(&path).expect("read Rust file");
        if text.contains("reqwest::Client::new") {
            let rel = rel(&path);
            assert!(
                rel.starts_with("crates/re0auth-runtime/src/http_client"),
                "reqwest::Client::new is only allowed in crates/re0auth-runtime/src/http_client, found in {rel} (HR-05)"
            );
        }
    }
}

/// 代理会重新解析域名，钉住随之失效
#[test]
fn guarded_client_disables_system_proxies() {
    let path = root().join("crates/re0auth-runtime/src/http_client.rs");
    let text = fs::read_to_string(path).expect("read http_client.rs");
    let guarded = text
        .split("reqwest::Client::builder()")
        .nth(1)
        .expect("the guarded client must be built through Client::builder")
        .split(".build()")
        .next()
        .expect("the builder chain must end with .build()");
    assert!(
        guarded.contains(".no_proxy()"),
        "the guarded client must call .no_proxy(): a system proxy re-resolves the host and bypasses address pinning (INV-OUT-02)"
    );
}

#[test]
fn tokio_spawn_is_only_used_in_the_runtime_scheduler() {
    // ADR-0026 / INV-SPAWN-01: the scheduler is the single legal spawn point.
    // Keeping it in `runtime` rather than the composition root is what makes
    // "an adapter never spawns" enforceable: if the spawn lived in `server`,
    // every adapter would still be one refactor away from starting its own task.
    let files = production_rust_files();
    assert!(
        files.len() >= 7,
        "only {} production Rust files found; the walk is not reading the tree",
        files.len()
    );
    let mut found = 0;
    for path in files {
        let text = fs::read_to_string(&path).expect("read Rust file");
        if text.contains("tokio::spawn") {
            let rel = rel(&path);
            assert!(
                rel == "crates/re0auth-runtime/src/lib.rs",
                "tokio::spawn is only allowed in the runtime scheduler, found in {rel}"
            );
            found += 1;
        }
    }
    assert_eq!(
        found, 1,
        "the scheduler must be the only spawning file; found {found}"
    );
}

#[test]
fn workflow_actions_are_pinned_to_full_shas() {
    let dir = root().join(".github/workflows");
    let entries = fs::read_dir(&dir).expect("workflows directory");
    let mut pinned = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yml") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read workflow");
        for (index, line) in text.lines().enumerate() {
            let line = line.trim().trim_start_matches("- ").trim();
            let Some(rest) = line.strip_prefix("uses:") else {
                continue;
            };
            let value = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .trim_matches('\'');
            if value.starts_with("./") || value.starts_with("docker://") {
                continue;
            }
            pinned += 1;
            let Some((_, sha)) = value.rsplit_once('@') else {
                panic!("{}:{}: uses {value} has no @ref", path.display(), index + 1);
            };
            assert!(
                sha.len() == 40 && sha.chars().all(is_lower_hex),
                "{}:{}: uses {value} is not pinned to a full lowercase SHA",
                path.display(),
                index + 1
            );
        }
    }
    assert!(
        pinned >= 1,
        "no remote uses: found; the parser is not reading the workflows"
    );
}

#[test]
fn ci_runs_the_required_gates() {
    let text = fs::read_to_string(root().join(".github/workflows/ci.yml")).expect("ci.yml");
    for needle in [
        "cargo fmt",
        "cargo clippy",
        "cargo test",
        "check-config.sh",
        "check-semver.sh",
        "docker-smoke.sh",
    ] {
        assert!(text.contains(needle), "ci.yml is missing {needle}");
    }
}

#[test]
fn dockerfile_is_non_root_and_has_a_smoke_gate() {
    let dockerfile = fs::read_to_string(root().join("Dockerfile")).expect("Dockerfile");
    assert!(
        dockerfile.contains("USER 65532:65532"),
        "the container must run as a non-root numeric user"
    );
    assert!(
        dockerfile.contains("HEALTHCHECK"),
        "the image must define a health check"
    );
    let smoke = fs::read_to_string(root().join("tools/docker-smoke.sh")).expect("docker-smoke.sh");
    for needle in ["/healthz", "/readyz", "65532:65532"] {
        assert!(
            smoke.contains(needle),
            "docker-smoke.sh is missing {needle}"
        );
    }
}

#[test]
fn readiness_probe_touches_storage() {
    // INV-READY-01. A hardcoded "ready" is indistinguishable from a real probe
    // in every test that only checks the happy path, yet it defeats the whole
    // purpose: an orchestrator keeps routing to an instance whose database is
    // gone. The probe must call into storage, and the two endpoints must be
    // separate handlers.
    let lib = fs::read_to_string(root().join("crates/re0auth-http/src/lib.rs"))
        .expect("re0auth-http lib.rs");
    assert!(
        lib.contains("async fn readyz("),
        "/readyz must have its own handler so its behaviour can be tested"
    );
    let start = lib.find("async fn readyz(").expect("readyz");
    let body = &lib[start..(start + 500).min(lib.len())];
    assert!(
        body.contains("check_storage"),
        "/readyz must probe storage; a constant response is a lie to the orchestrator"
    );
    assert!(
        body.contains("SERVICE_UNAVAILABLE"),
        "/readyz must report a non-2xx status when the probe fails"
    );
}

#[test]
fn api_semver_gate_is_wired() {
    let ci = fs::read_to_string(root().join(".github/workflows/ci.yml")).expect("ci.yml");
    assert!(
        ci.contains("check-semver.sh"),
        "ci.yml must call tools/check-semver.sh"
    );
    let script = fs::read_to_string(root().join("tools/check-semver.sh")).expect("check-semver.sh");
    assert!(
        script.contains("cargo semver-checks"),
        "the semver gate must invoke cargo semver-checks"
    );
    assert!(
        script.contains("re0auth-api"),
        "the semver gate must target the re0auth-api contract crate"
    );
}

#[test]
fn config_example_parses() {
    let text = fs::read_to_string(root().join("config.example.toml")).expect("config example");
    let value: toml::Value = text.parse().expect("valid TOML");
    assert!(
        value
            .get("server")
            .and_then(|v| v.get("issuer"))
            .and_then(|v| v.as_str())
            .is_some(),
        "server.issuer is missing"
    );
    assert!(
        value
            .get("database")
            .and_then(|v| v.get("url"))
            .and_then(|v| v.as_str())
            .is_some(),
        "database.url is missing"
    );
    assert!(
        value
            .get("crypto")
            .and_then(|v| v.get("master_key_file"))
            .and_then(|v| v.as_str())
            .is_some(),
        "crypto.master_key_file is missing"
    );
    assert!(
        value
            .get("limits")
            .and_then(|v| v.get("upstream_response_bytes"))
            .and_then(|v| v.as_integer())
            .is_some(),
        "limits.upstream_response_bytes is missing"
    );
}

#[test]
fn identity_flows_never_reference_connector_ports() {
    // INV-LOGIN-03: identity paths must compile without the data plane.
    for rel in [
        "crates/re0auth-app/src/auth.rs",
        "crates/re0auth-app/src/oauth.rs",
    ] {
        let text = fs::read_to_string(root().join(rel)).expect("identity source");
        for forbidden in [
            "Connector",
            "UpstreamError",
            "ConnectorBroker",
            "connector::",
        ] {
            assert!(
                !text.contains(forbidden),
                "{rel} must not reference {forbidden}; identity flows cannot depend on the data plane"
            );
        }
    }
}

#[test]
fn the_two_planes_are_separate_crates() {
    // ADR-0021: identity and data live in different crates so neither plane is
    // *forced* to be present. Splitting the crate is necessary but not
    // sufficient: `cargo` rejects a cycle, not a one-way edge, so
    // `re0auth-idp -> re0auth-connectors` builds fine. Verified by adding that
    // edge — `cargo check` passed, and only this test failed.
    //
    // What the split actually buys is composition: a build can include the
    // identity plane alone, so login works with no upstream configured. This
    // gate is what keeps that true.
    let deps = workspace_deps();
    for (plane, crate_name) in [("identity", "re0auth-idp"), ("data", "re0auth-connectors")] {
        assert!(
            deps.contains_key(crate_name),
            "the {plane} plane must be its own crate ({crate_name})"
        );
    }
    let identity = deps.get("re0auth-idp").expect("idp deps");
    let data = deps.get("re0auth-connectors").expect("connectors deps");
    assert!(
        !identity.contains("re0auth-connectors"),
        "re0auth-idp must not depend on the data plane"
    );
    assert!(
        !data.contains("re0auth-idp"),
        "re0auth-connectors must not depend on the identity plane"
    );
}

#[test]
fn the_composition_root_only_wires() {
    // AGENTS.md §3.2: `re0auth-server` keeps only assembly (`main.rs`), config,
    // env overrides, and the admin CLI. Routes belong to `re0auth-http`; guards,
    // policies and observers belong to their own crates.
    //
    // The dependency direction is already enforced elsewhere, but that gate only
    // proves the root does not *depend* on the wrong thing — it says nothing about
    // what the root defines. A composition root can accumulate a router, a
    // policy and a retry rule while depending on nothing unusual.
    let dir = root().join("crates/re0auth-server/src");
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    assert!(
        files.len() >= 4,
        "only {} files found under the composition root; the walk is not reading the tree",
        files.len()
    );
    for path in &files {
        let rel = rel(path);
        assert!(
            COMPOSITION_ROOT_MODULES.contains(&rel.as_str()),
            "{rel} is outside the composition root's declared surface. Adding one is \
             allowed but has to be a decision: routing goes to `re0auth-http`, and \
             guards / policies / observers go to their own crates (AGENTS.md §3.2). \
             If this file is genuinely wiring, add it to COMPOSITION_ROOT_MODULES."
        );
    }

    // A root that can register a route has stopped being a composition root, so
    // this half holds even for a file that was just added to the list above.
    for path in &files {
        let text = fs::read_to_string(path).expect("read composition root source");
        let code = code_without_comments_or_strings(&text);
        for forbidden in ["Router::new", ".route(", "FromRequest"] {
            assert!(
                !code.contains(forbidden),
                "{} defines routes ({forbidden}); routing lives in `re0auth-http`",
                rel(path)
            );
        }
    }
}

#[test]
fn production_code_has_no_test_switches() {
    // AGENTS.md §3.2: needing a test-only switch means the guard should have been
    // a port instead. A switch is worse than a missing abstraction — it makes the
    // tested behaviour differ from the shipped behaviour, so every test that
    // covers the relaxed path is evidence about a program nobody runs.
    let files = production_rust_files();
    assert!(
        files.len() >= 7,
        "only {} production Rust files found; the walk is not reading the tree",
        files.len()
    );
    for path in files {
        let text = fs::read_to_string(&path).expect("read Rust file");
        let code = code_without_comments_or_strings(&text);
        let switches = test_flag_predicates(&code);
        assert!(
            switches.is_empty(),
            "{}: {switches:?} make production behaviour depend on whether tests are \
             running. A guard that needs relaxing under test should be a port instead, \
             and test-only code belongs in `#[cfg(test)] mod ...` (AGENTS.md §3.2).",
            rel(&path)
        );
    }
}

/// INV-CONN-02 / `AGENTS.md` §2.1: no core crate names a game root credential,
/// even as a field name. `re0auth-connectors` is deliberately **out** of scope:
/// it carries upstream differences and may hold root credentials (ADR-0041).
#[test]
fn core_crates_do_not_name_game_root_credentials() {
    // `session_cookie` is deliberately absent from this set. It collides with
    // Re0Auth's *own* session-cookie helper (`re0auth_http::parsers::session_cookie`),
    // so banning it would forbid our own feature — the same mistake `SECURITY.md`
    // records for a bare `session` / `cookie` rule. A game-side session cookie
    // lives in `re0auth-connectors`, which is out of scope anyway.
    const NEEDLES: &[&str] = &[
        "stoken",
        "sessiontoken",
        "gamepassword",
        "tappassword",
        "taptappassword",
    ];
    const CORE: &[&str] = &[
        "crates/re0auth-api/",
        "crates/re0auth-domain/",
        "crates/re0auth-app/",
        "crates/re0auth-adapters/",
        "crates/re0auth-idp/",
        "crates/re0auth-runtime/",
        "crates/re0auth-http/",
        "crates/re0auth-server/",
    ];

    for path in production_rust_files() {
        let rel = rel(&path);
        if !CORE.iter().any(|prefix| rel.starts_with(prefix)) {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        for (index, line) in text.lines().enumerate() {
            for needle in NEEDLES {
                assert!(
                    !names_token(line, needle),
                    "{rel}:{} names game root credential {needle}: {line}",
                    index + 1
                );
            }
        }
    }
}

/// Matches `needle` on word boundaries, case-insensitively.
///
/// Separators are normalised first, so `session_token`, `session-token`, and
/// `sessionToken` all reduce to `sessiontoken`: one spelling cannot slip past
/// the others, while an unrelated word still does not match.
fn names_token(line: &str, needle: &str) -> bool {
    let normalised: String = line
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect();
    let mut from = 0;
    while let Some(at) = normalised[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before_ok = !normalised[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        let after_ok = !normalised[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// A gate that cannot catch a planted field name is worthless.
#[test]
fn the_root_credential_matcher_covers_every_spelling() {
    assert!(names_token("let x = body.session_token;", "sessiontoken"));
    assert!(names_token("sessionToken: String", "sessiontoken"));
    assert!(names_token("session-token", "sessiontoken"));
    assert!(names_token("let v = tap_tap_password;", "taptappassword"));
    assert!(names_token("stoken", "stoken"));
    assert!(
        !names_token("session_cookie(&headers)", "sessiontoken"),
        "our own session cookie must not be flagged"
    );
    assert!(!names_token("mystoken", "stoken"), "a suffix is not a name");
    assert!(
        !names_token("session token", "sessiontoken"),
        "a space is not a separator"
    );
}

#[test]
fn gateway_invariants_have_executable_tests() {
    let text = fs::read_to_string(root().join("crates/re0auth-app/tests/gateway.rs"))
        .expect("gateway tests");
    for invariant_test in [
        "missing_binding_is_business_and_writes_no_circuit_state",
        "upstream_401_marks_needs_reauth_without_tripping_the_breaker",
        "upstream_403_keeps_the_binding_active",
        "traversal_is_rejected_before_the_upstream",
        "oversized_payload_is_truncated_and_internal",
    ] {
        assert!(
            text.contains(invariant_test),
            "gateway invariant test {invariant_test} is missing"
        );
    }
    let docs = fs::read_to_string(root().join("crates/re0auth-archtest/contract/invariants.md"))
        .expect("invariant contract");
    for invariant in [
        "INV-LOGIN-02",
        "INV-LOGIN-03",
        "INV-LOGIN-04",
        "INV-GW-01",
        "INV-GW-06",
    ] {
        assert!(
            docs.contains(invariant),
            "invariant document is missing {invariant}"
        );
    }
}

#[test]
fn the_cache_is_read_only_after_authorization() {
    // INV-CACHE-01. A behaviour test proves the ordering for the cases it
    // covers; this proves it for the code as written, so a later edit that
    // hoists the read cannot slip past while the tests happen to still pass.
    let text = fs::read_to_string(root().join("crates/re0auth-app/src/gateway.rs"))
        .expect("gateway source");
    let fetch_start = text.find("pub async fn fetch").expect("fetch");
    let body = &text[fetch_start..];
    // Only the first `fetch` body matters; stop at the next method.
    let body_end = body.find("\n    /// INV-RAW-01").unwrap_or(body.len());
    let body = &body[..body_end];

    let scope_gate = body
        .find("scope_allows")
        .expect("the scope gate must exist in fetch");
    let binding_lookup = body
        .find(".bindings()\n            .find")
        .expect("the binding lookup must exist in fetch");
    let cache_read = body
        .find("self.cache.get")
        .expect("the cache read must exist");

    assert!(
        scope_gate < cache_read,
        "INV-CACHE-01 violated: the cache is read before the scope gate, so a \
         caller without the scope can receive a cached payload"
    );
    assert!(
        binding_lookup < cache_read,
        "INV-CACHE-01 violated: the cache is read before the binding lookup, so \
         a revoked binding can still be served"
    );
}

#[test]
fn cache_invariants_have_executable_tests() {
    // Each red line must have a test that fails when the protection is removed.
    let caps = [
        (
            "crates/re0auth-app/tests/gateway.rs",
            "a_caller_without_the_scope_never_receives_a_cached_payload",
            "INV-CACHE-01",
        ),
        (
            "crates/re0auth-app/tests/gateway.rs",
            "a_revoked_binding_never_receives_a_cached_payload",
            "INV-CACHE-01",
        ),
        (
            "crates/re0auth-app/tests/gateway.rs",
            "a_raw_request_is_never_served_from_the_cache",
            "INV-CACHE-03",
        ),
        (
            "crates/re0auth-app/tests/cache_invalidation.rs",
            "revoking_a_binding_sweeps_its_cached_responses",
            "INV-CACHE-02",
        ),
        (
            "crates/re0auth-app/tests/cache_invalidation.rs",
            "revoking_leaves_other_bindings_cached",
            "INV-CACHE-02",
        ),
    ];
    for (rel, test_name, invariant) in caps {
        let text = fs::read_to_string(root().join(rel)).expect("test file");
        assert!(
            text.contains(test_name),
            "{invariant} has no executable test: {test_name} is missing from {rel}"
        );
    }
}

#[test]
fn core_invariants_are_locatable_in_source() {
    // A named invariant with no anchor in the code is a claim nobody can audit.
    // Each pair is (invariant id, file that must mention it).
    for (invariant, rel) in [
        ("INV-AUTH-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-BIND-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-BIND-04", "crates/re0auth-app/src/binding.rs"),
        ("INV-CONSENT-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-DEV-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-DEVICE-02", "crates/re0auth-api/src/ports.rs"),
        ("INV-FK-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-PK-01", "crates/re0auth-api/src/lib.rs"),
        ("INV-REFRESH-01", "crates/re0auth-api/src/ports.rs"),
        ("INV-TICKET-01", "crates/re0auth-api/src/ports.rs"),
        (
            "INV-SESSION-01",
            "crates/re0auth-http/src/routes/session.rs",
        ),
        ("INV-LOGIN-05", "crates/re0auth-http/src/routes/session.rs"),
        ("INV-HTTP-01", "crates/re0auth-http/src/routes/session.rs"),
        ("INV-RATE-01", "crates/re0auth-http/src/lib.rs"),
        ("INV-OUT-01", "crates/re0auth-runtime/src/http_client.rs"),
        ("INV-OUT-02", "crates/re0auth-runtime/src/http_client.rs"),
        ("INV-RES-01", "crates/re0auth-runtime/src/http_client.rs"),
        ("INV-TOKEN-01", "crates/re0auth-idp/src/lib.rs"),
        ("INV-CONFIG-01", "crates/re0auth-server/src/config.rs"),
        ("INV-NOLOG-01", "crates/re0auth-server/src/main.rs"),
    ] {
        let text = fs::read_to_string(root().join(rel)).expect("source file");
        assert!(
            text.contains(invariant),
            "{rel} no longer anchors {invariant}; an invariant without an anchor cannot be audited"
        );
    }
}

#[test]
fn ssrf_guard_has_executable_tests() {
    let text = fs::read_to_string(root().join("crates/re0auth-runtime/src/outbound.rs"))
        .expect("outbound guard source");
    for invariant in [
        "ipv4_mapped_addresses_are_normalized_first",
        "metadata_is_blocked_even_with_private_net",
        "mixed_answer_is_rejected_as_rebinding",
        "loopback_requires_the_explicit_local_policy",
        "loopback_policy_does_not_open_metadata",
        "schemes_other_than_https_are_rejected",
    ] {
        assert!(
            text.contains(invariant),
            "INV-SSRF-01 test {invariant} is missing"
        );
    }
    let client = fs::read_to_string(root().join("crates/re0auth-runtime/src/http_client.rs"))
        .expect("guarded client source");
    assert!(
        client.contains("redirect::Policy::none()"),
        "the guard must not follow redirects"
    );
    assert!(
        client.contains(".resolve(host, pinned)"),
        "the guard must pin the vetted address"
    );
}

#[test]
fn circuit_breaker_has_half_open_probe() {
    let text = fs::read_to_string(root().join("crates/re0auth-app/src/circuit.rs"))
        .expect("circuit source");
    for needle in [
        "HalfOpen",
        "probe_in_flight",
        "pub fn admit",
        "pub fn settle",
    ] {
        assert!(text.contains(needle), "circuit breaker is missing {needle}");
    }
    for case in [
        "cooldown_expiry_allows_exactly_one_probe",
        "successful_probe_closes_the_breaker",
        "failed_probe_reopens_and_restarts_the_clock",
        "business_outcomes_do_not_open_the_breaker",
    ] {
        assert!(text.contains(case), "circuit test {case} is missing");
    }
}

#[test]
fn tls_trust_is_injected_not_system_derived() {
    let text =
        fs::read_to_string(root().join("crates/re0auth-runtime/src/tls.rs")).expect("tls source");
    assert!(
        text.contains("webpki_roots::TLS_SERVER_ROOTS"),
        "the trust store must start from the Mozilla bundle"
    );
    for forbidden in [
        "rustls_native_certs",
        "rustls_platform_verifier",
        "load_native_certs",
    ] {
        assert!(
            !text.contains(forbidden),
            "tls.rs must not read the host trust store ({forbidden})"
        );
    }
    let client = fs::read_to_string(root().join("crates/re0auth-runtime/src/http_client.rs"))
        .expect("guarded client source");
    assert!(
        client.contains("use_preconfigured_tls"),
        "the guard must inject its own rustls config"
    );
    let tests =
        fs::read_to_string(root().join("crates/re0auth-runtime/src/tls.rs")).expect("tls source");
    for case in [
        "mozilla_bundle_is_loaded",
        "missing_extra_ca_file_is_an_error",
        "empty_pem_file_is_an_error",
        "garbage_pem_is_an_error",
    ] {
        assert!(tests.contains(case), "tls test {case} is missing");
    }
}

#[test]
fn secret_bearing_types_redact_their_debug_output() {
    // INV-NOLOG-01 has two halves. The runtime half (no secrets in log lines)
    // is enforced by `ports.rs`'s own tests; this half is the structural one:
    // every type that carries a hash, nonce or one-time code must implement
    // `Debug` by hand. A `derive(Debug)` on any of these would silently print
    // the secret, so the gate is "the derive is absent", not "a test exists".
    let ports =
        fs::read_to_string(root().join("crates/re0auth-api/src/ports.rs")).expect("ports source");
    let secret =
        fs::read_to_string(root().join("crates/re0auth-api/src/secret.rs")).expect("secret source");
    let oauth =
        fs::read_to_string(root().join("crates/re0auth-api/src/oauth.rs")).expect("oauth source");

    // Types whose fields include a hash, a nonce, a verifier or a one-time code.
    let guarded = [
        "Session",
        "AuthCode",
        "ConsumeAuthCode",
        "DeviceCode",
        "LoginTransaction",
        "RefreshToken",
        "RotateRefreshToken",
        "PendingAuthorization",
        "ApprovalTicket",
    ];
    for name in guarded {
        assert!(
            ports.contains(&format!("impl std::fmt::Debug for {name}")),
            "{name} must implement Debug by hand so INV-NOLOG-01 cannot regress"
        );
        // The derive is the failure mode: it would shadow nothing but print
        // everything. Match the exact attribute line that would apply to it.
        let derived = format!("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct {name}");
        assert!(
            !ports.contains(&derived),
            "{name} still derives Debug; its secret fields would be printed"
        );
    }
    for (name, source) in [
        ("SealedSecret", &secret),
        ("ClientSecretHash", &secret),
        ("IdTokenClaims", &oauth),
        ("ApprovalTicketClaims", &oauth),
    ] {
        assert!(
            source.contains(&format!("impl std::fmt::Debug for {name}")),
            "{name} must implement Debug by hand"
        );
    }
}

#[test]
fn credential_comparisons_are_constant_time() {
    // A secret compared with `==` short-circuits at the first differing byte, so
    // the time it takes leaks how much of the value was guessed correctly. The
    // client-secret verifier got this right early (through `Mac::verify_slice`);
    // the CSRF check did not, and nothing caught it because both forms produce
    // the same answer — there is no behaviour test that can distinguish them.
    //
    // The scan keys on the *hashing call*, not on the function name. A verifier
    // can be called anything (`csrf_matches`, `session_ok`, ...), so matching
    // names missed the exact case this gate was written for: the first version
    // of the gate let `csrf_matches` through because it was not in the list.
    //
    // A hash lookup in a store (`find(|x| x.hash == wanted)`) also uses `==`,
    // but it never hashes anything: the hash is the table key, chosen by the
    // caller and already indexable. The rule is about comparing a *freshly
    // computed* digest against a stored one.
    let mut offenders = Vec::new();
    for path in production_rust_files() {
        let text = fs::read_to_string(&path).expect("read source");
        let text = match text.find("#[cfg(test)]") {
            Some(index) => text[..index].to_string(),
            None => text,
        };
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if !(trimmed.contains(" == ") || trimmed.contains(" != ")) {
                continue;
            }
            if trimmed.contains("ct_eq") || trimmed.contains("verify_slice") {
                continue;
            }
            // Look at this line and the two before it: a digest computed into a
            // local is usually compared on the next line.
            let window = lines[index.saturating_sub(2)..=index].join("\n");
            if window.contains("hash_secret(") || window.contains("digest(") {
                offenders.push(format!("{}:{}", rel(&path), index + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a freshly computed credential digest must be compared in constant time \
         (use `subtle::ConstantTimeEq::ct_eq` or `Mac::verify_slice`): {offenders:?}"
    );
}

#[test]
fn runtime_logging_goes_through_tracing() {
    // A `println!` in the serve path bypasses the subscriber, so it ignores
    // RUST_LOG, emits no level and cannot be collected as JSON. The CLI's
    // operator output is the one exception: it is a command result, not a log.
    let main =
        fs::read_to_string(root().join("crates/re0auth-server/src/main.rs")).expect("main source");
    // Drop the CLI module boundary by reading main.rs only; cli.rs is separate.
    let serve_start = main.find("async fn serve").expect("serve fn");
    let serve_body = &main[serve_start..];
    assert!(
        !serve_body.contains("println!"),
        "the serve path must log through tracing, not println!"
    );
    assert!(
        main.contains(".with_ansi(false)"),
        "ANSI colour must be off: escape codes corrupt collected logs"
    );
    assert!(
        main.contains("EnvFilter"),
        "RUST_LOG filtering must be wired in"
    );

    let runtime = fs::read_to_string(root().join("crates/re0auth-runtime/src/lib.rs"))
        .expect("runtime source");
    assert!(
        !runtime.contains("eprintln!"),
        "the scheduler must log through tracing"
    );
}

#[test]
fn rust_files_stay_under_the_line_budget() {
    let files = production_rust_files();
    assert!(
        files.len() >= 7,
        "only {} production Rust files found; the walk is not reading the tree",
        files.len()
    );
    for path in files {
        let lines = fs::read_to_string(&path)
            .expect("read Rust file")
            .lines()
            .count();
        assert!(
            lines <= 1500,
            "{} has {lines} lines; the per-file budget is 1500",
            path.display()
        );
    }
}

/// Files that define the strings returned to clients as `error` values.
/// Keeping this list explicit is the point: a new error-code home has to be
/// registered here, which forces the author to think about the API surface.
const ERROR_CODE_SOURCES: [&str; 4] = [
    "crates/re0auth-app/src/gateway.rs",
    "crates/re0auth-app/src/oauth.rs",
    "crates/re0auth-http/src/error.rs",
    "crates/re0auth-http/src/lib.rs",
];

#[test]
fn published_error_codes_match_the_code() {
    // The API surface document is a promise. This gate is what stops it from
    // drifting into fiction: a code listed as implemented must exist somewhere,
    // and a code listed as unimplemented must not be emitted by anything.
    let doc = fs::read_to_string(root().join("crates/re0auth-archtest/contract/api-surface.md"))
        .expect("api-surface contract");
    // Only files that define error codes. Scanning every source file would also
    // pick up unrelated string tables (audit actions, scope names) that happen
    // to share a spelling with a planned error code.
    let sources = ERROR_CODE_SOURCES
        .iter()
        .map(|path| fs::read_to_string(root().join(path)).expect("read error-code source"))
        .collect::<Vec<_>>()
        .join("\n");

    let (implemented, planned) = split_error_code_sections(&doc);
    assert!(
        implemented.len() >= 15,
        "only {} implemented codes parsed; the section split broke",
        implemented.len()
    );
    assert!(
        planned.len() >= 3,
        "only {} planned codes parsed; the section split broke",
        planned.len()
    );

    for code in &implemented {
        assert!(
            sources.contains(&format!("\"{code}\"")),
            "API-SURFACE.md lists `{code}` as implemented, but no source emits it"
        );
    }
    for code in &planned {
        assert!(
            !sources.contains(&format!("\"{code}\"")),
            "API-SURFACE.md lists `{code}` as not implemented, but the code emits it"
        );
    }
}

/// INV-DOC-01: appendix A of `API-SURFACE.md` claims to be "可执行事实" — the list
/// of routes the router actually serves. This gate is what makes that claim
/// checkable instead of aspirational.
///
/// It exists because the list had already drifted: five routes were missing,
/// including the whole binding group, while the document still said routes must be
/// kept in sync. A promise about a list is worth nothing without something that
/// compares the list to its source.
#[test]
fn the_routes_in_api_surface_match_the_router() {
    let source = fs::read_to_string(root().join("crates/re0auth-http/src/lib.rs"))
        .expect("re0auth-http source");
    let served = router_routes(&source);
    assert!(
        served.len() >= 20,
        "only {} routes parsed from the router; the parser is broken",
        served.len()
    );

    let doc = fs::read_to_string(root().join("crates/re0auth-archtest/contract/api-surface.md"))
        .expect("api-surface contract");
    let documented = appendix_a_routes(&doc);
    assert!(
        documented.len() >= 20,
        "only {} routes parsed from appendix A; the parser is broken",
        documented.len()
    );

    let missing: Vec<_> = served.difference(&documented).collect();
    let extra: Vec<_> = documented.difference(&served).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "appendix A does not match `re0auth-http::router()`.\n\
         served but undocumented: {missing:?}\n\
         documented but not served: {extra:?}\n\
         Update the appendix in the same change as the route."
    );
}

/// The SPA fallback answers with the shell for anything it does not recognise, so
/// its list of reserved namespaces is a second copy of routing knowledge. That is
/// the kind of copy that drifts: a new top-level namespace added to `router()` and
/// not to `is_reserved_path` turns an unknown API path into a 200 HTML page
/// instead of a 404.
///
/// The other direction matters too: if the list grew to cover a path the app
/// really serves, `/account` (the fallback's own redirect target) would 404.
#[test]
fn every_route_is_reserved_by_the_fallback() {
    let source = fs::read_to_string(root().join("crates/re0auth-http/src/lib.rs"))
        .expect("re0auth-http source");
    let served = router_routes(&source);
    assert!(
        served.len() >= 20,
        "only {} routes parsed from the router; the parser is broken",
        served.len()
    );

    let uncovered: Vec<_> = served
        .iter()
        .filter(|entry| {
            let path = entry
                .split_once(' ')
                .map_or(entry.as_str(), |(_, path)| path);
            !re0auth_http::is_reserved_path(path)
        })
        .cloned()
        .collect();
    assert!(
        uncovered.is_empty(),
        "these routes would be answered by the SPA fallback instead of the router: \
         {uncovered:?}\nAdd their namespace to `static_assets::is_reserved_path`."
    );
}

/// The `(method, path)` pairs registered by `.route(...)` in `source`.
///
/// Reads the source text rather than the comment-stripped form, because the paths
/// *are* string literals. A `.route(` that is not immediately followed by a string
/// is treated as prose and skipped, which is what keeps a comment documenting the
/// call from being counted as one.
fn router_routes(source: &str) -> BTreeSet<String> {
    // The axum method wrappers that can appear in a `.route(...)` chain.
    const METHODS: [&str; 8] = [
        "get", "post", "put", "patch", "delete", "head", "options", "trace",
    ];
    let mut routes = BTreeSet::new();
    let mut search = 0;
    while let Some(at) = source[search..].find(".route(") {
        let open = search + at + ".route".len();
        search = open;
        let Some(path) = first_string_literal(&source[open..]) else {
            continue;
        };
        let after = open + path.1;
        // Read the whole method chain (`get(a)`, `get(a).delete(b)`, ...), not
        // just the first wrapper. Chaining is valid axum, and reading only the
        // first method would let a chained route slip past this gate as
        // "documented but not served" the wrong way — silently unlisted.
        let end = matching_paren(source, open).expect("a `.route(...)` with balanced parentheses");
        let chain = &source[after..end];
        let mut found = false;
        for method in METHODS {
            if chain.contains(&format!("{method}(")) {
                routes.insert(format!("{} {}", method.to_uppercase(), path.0));
                found = true;
            }
        }
        assert!(
            found,
            "a `.route(...)` in re0auth-http has no method wrapper near byte {open}"
        );
    }
    routes
}

/// A gate that silently misses a served route is worse than no gate: chaining
/// methods on one `.route(...)` is valid axum, so the parser must read the whole
/// chain rather than only the first wrapper.
#[test]
fn the_router_parser_sees_a_chained_method() {
    let routes = router_routes(r#"Router::new().route("/x", get(a).delete(b));"#);
    assert!(routes.contains("GET /x"), "the first wrapper is read");
    assert!(
        routes.contains("DELETE /x"),
        "a chained method must not be missed: {routes:?}"
    );
}

/// The first `"..."` literal in `text`, with the offset just past its closing quote.
fn first_string_literal(text: &str) -> Option<(String, usize)> {
    let open = text.find('"')?;
    // A route path cannot contain a quote, so the next one closes it.
    let close = text[open + 1..].find('"')? + open + 1;
    Some((text[open + 1..close].to_string(), close + 1))
}

/// The routes listed in `API-SURFACE.md` appendix A, as `(METHOD, PATH)` pairs.
fn appendix_a_routes(doc: &str) -> BTreeSet<String> {
    let mut routes = BTreeSet::new();
    let mut in_appendix = false;
    let mut in_block = false;
    for line in doc.lines() {
        if line.starts_with("## 附录 A") {
            in_appendix = true;
            continue;
        }
        if !in_appendix {
            continue;
        }
        if line.starts_with("```") {
            if in_block {
                break;
            }
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
            continue;
        };
        assert!(
            path.starts_with('/'),
            "appendix A line is neither a comment nor a route: {line:?}"
        );
        routes.insert(format!("{method} {path}"));
    }
    routes
}

/// INV-CONFIG-02: every config field must be read by production code.
///
/// A parsed, validated, documented setting that nothing reads is worse than a
/// missing feature: the operator sets it, believes it took effect, and gets no
/// error. `limits.inbound_body_bytes` was exactly that — the router used axum's
/// built-in default instead.
///
/// This is deliberately not a text search for `.field_name`. A substring match
/// accepted `.name` on any type, so renaming `ResourceConfig::path` to `name`
/// made a dead field pass because `.name` appears elsewhere 52 times. The check
/// below parses every production file and tracks which variables actually hold
/// a config type, so a hit only counts when the receiver is that struct.
///
/// Fields listed in `CONFIG_FIELDS_NOT_YET_USED` are acknowledged debt with an
/// open issue. Adding an entry is a deliberate act; a silent new dead field
/// fails here.
#[test]
fn every_config_field_is_read_by_production_code() {
    let config_path = root().join("crates/re0auth-server/src/config.rs");
    let config = fs::read_to_string(&config_path).expect("config.rs");
    let schema = ConfigSchema::parse(&config);
    assert!(
        schema.structs.len() >= 8,
        "only {} config structs parsed; the parser broke",
        schema.structs.len()
    );
    assert!(
        schema.total_fields() >= 30,
        "only {} config fields parsed; the parser broke",
        schema.total_fields()
    );

    let mut read = BTreeSet::new();
    for path in production_rust_files() {
        let text = fs::read_to_string(&path).expect("read source");
        let text = match text.find("#[cfg(test)]") {
            Some(index) => text[..index].to_string(),
            None => text,
        };
        collect_config_reads(&text, &schema, &mut read);
    }

    let mut dead = Vec::new();
    for (struct_name, fields) in &schema.structs {
        for field in fields {
            if CONFIG_FIELDS_NOT_YET_USED.contains(&field.as_str()) {
                continue;
            }
            if !read.contains(&(struct_name.clone(), field.clone())) {
                dead.push(format!("{struct_name}::{field}"));
            }
        }
    }
    assert!(
        dead.is_empty(),
        "these config fields are parsed but never read ({dead:?}); \
         either wire them up or add them to CONFIG_FIELDS_NOT_YET_USED with an issue"
    );
}

/// Field names per config struct, plus the config type each field holds.
struct ConfigSchema {
    structs: BTreeMap<String, Vec<String>>,
    /// `(struct, field) -> (config struct it holds, is it a Vec)`
    field_types: BTreeMap<(String, String), (String, bool)>,
}

/// Field names of one struct, with the config type each field holds (if any).
type DeclaredFields = Vec<(String, Option<(String, bool)>)>;

impl ConfigSchema {
    fn parse(source: &str) -> Self {
        let file = syn::parse_file(source).expect("config.rs parses");
        let mut declared: BTreeMap<String, DeclaredFields> = BTreeMap::new();
        for item in &file.items {
            let syn::Item::Struct(item) = item else {
                continue;
            };
            let fields = item
                .fields
                .iter()
                .filter_map(|field| {
                    let ident = field.ident.as_ref()?;
                    Some((ident.to_string(), config_type_of(&field.ty)))
                })
                .collect::<Vec<_>>();
            declared.insert(item.ident.to_string(), fields);
        }

        // A struct is part of the config schema if it is named `Config`, ends in
        // `Config`, or is reachable from `Config` through a field. Reachability
        // matters because `TlsSettings` is neither: it is only identified by
        // being the type of `Config::tls`.
        let mut included: BTreeSet<String> = declared
            .keys()
            .filter(|name| *name == "Config" || name.ends_with("Config"))
            .cloned()
            .collect();
        let mut changed = true;
        while changed {
            changed = false;
            for name in included.clone() {
                let Some(fields) = declared.get(&name) else {
                    continue;
                };
                for (_, target) in fields {
                    if let Some((target, _)) = target
                        && declared.contains_key(target)
                        && included.insert(target.clone())
                    {
                        changed = true;
                    }
                }
            }
        }

        let mut structs = BTreeMap::new();
        let mut field_types = BTreeMap::new();
        for (name, fields) in declared {
            if !included.contains(&name) {
                continue;
            }
            structs.insert(
                name.clone(),
                fields.iter().map(|(field, _)| field.clone()).collect(),
            );
            for (field, target) in fields {
                if let Some(target) = target {
                    field_types.insert((name.clone(), field), target);
                }
            }
        }
        Self {
            structs,
            field_types,
        }
    }

    fn total_fields(&self) -> usize {
        self.structs.values().map(Vec::len).sum()
    }

    /// The config struct a field holds, if it holds one directly.
    fn field_target(&self, struct_name: &str, field: &str) -> Option<&str> {
        self.field_types
            .get(&(struct_name.to_string(), field.to_string()))
            .map(|(target, _)| target.as_str())
    }
}

/// `CryptoConfig` -> (CryptoConfig, false); `Vec<ConnectorConfig>` -> (ConnectorConfig, true).
fn config_type_of(ty: &syn::Type) -> Option<(String, bool)> {
    match ty {
        syn::Type::Path(path) => {
            let segment = path.path.segments.last()?;
            if segment.ident == "Vec"
                && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
                && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
            {
                return config_type_of(inner).map(|(name, _)| (name, true));
            }
            Some((segment.ident.to_string(), false))
        }
        syn::Type::Reference(reference) => config_type_of(&reference.elem),
        _ => None,
    }
}

/// Records `(struct, field)` for every field access whose receiver is known to
/// hold that config struct.
///
/// Only the receiver forms this codebase actually uses are understood:
///
/// - `cfg.server.issuer`: a path rooted at a parameter typed as a config struct,
///   followed by field selections that resolve through the schema.
/// - `self.master_key_file` inside `impl CryptoConfig`.
/// - `resource.path` inside `for resource in &connector.resources`.
/// - `idp.issuer` inside `for idp in &cfg.identity_providers`.
///
/// Anything else is ignored rather than guessed, so the check can miss a read
/// but never invent one.
fn collect_config_reads(
    source: &str,
    schema: &ConfigSchema,
    read: &mut BTreeSet<(String, String)>,
) {
    let Ok(file) = syn::parse_file(source) else {
        return;
    };
    visit_items(&file.items, schema, read);
}

fn visit_items(items: &[syn::Item], schema: &ConfigSchema, read: &mut BTreeSet<(String, String)>) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                let mut bindings = BTreeMap::new();
                bind_params(&function.sig.inputs, schema, &mut bindings);
                visit_stmts(&function.block.stmts, schema, &mut bindings, read);
            }
            syn::Item::Impl(block) => {
                let self_type = match &*block.self_ty {
                    syn::Type::Path(path) => path
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string()),
                    _ => None,
                };
                for entry in &block.items {
                    let syn::ImplItem::Fn(function) = entry else {
                        continue;
                    };
                    let mut bindings = BTreeMap::new();
                    if let Some(name) = &self_type
                        && schema.structs.contains_key(name)
                    {
                        bindings.insert("self".to_string(), name.clone());
                    }
                    bind_params(&function.sig.inputs, schema, &mut bindings);
                    visit_stmts(&function.block.stmts, schema, &mut bindings, read);
                }
            }
            _ => {}
        }
    }
}

fn bind_params(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
    schema: &ConfigSchema,
    bindings: &mut BTreeMap<String, String>,
) {
    for input in inputs {
        let syn::FnArg::Typed(pat) = input else {
            continue;
        };
        let syn::Pat::Ident(ident) = &*pat.pat else {
            continue;
        };
        if let Some(name) = config_type_name(&pat.ty, schema) {
            bindings.insert(ident.ident.to_string(), name);
        }
    }
}

fn config_type_name(ty: &syn::Type, schema: &ConfigSchema) -> Option<String> {
    // Both `cfg: &Config` and `cfg: config::Config` (by value) are used here.
    let name = config_type_of(ty)?.0;
    schema.structs.contains_key(&name).then_some(name)
}

fn visit_stmts(
    stmts: &[syn::Stmt],
    schema: &ConfigSchema,
    bindings: &mut BTreeMap<String, String>,
    read: &mut BTreeSet<(String, String)>,
) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Local(local) => {
                // The initialiser must be walked even when the pattern is not a
                // plain identifier: `let Some(x) = cfg.legacy.take()` reads the
                // field in the initialiser, not in the binding.
                if let Some(init) = &local.init {
                    visit_expr(&init.expr, schema, bindings, read);
                }
                let syn::Pat::Ident(ident) = &local.pat else {
                    continue;
                };
                if let Some(init) = &local.init
                    && let Some(name) = struct_of_expr(&init.expr, schema, bindings)
                {
                    bindings.insert(ident.ident.to_string(), name);
                }
            }
            syn::Stmt::Expr(expr, _) => visit_expr(expr, schema, bindings, read),
            syn::Stmt::Macro(mac) => visit_macro(&mac.mac, schema, bindings, read),
            _ => {}
        }
    }
}

/// Macros such as `tracing::warn!(x = %cfg.server.bind)` embed expressions in
/// their token stream, which `syn` does not parse into an `Expr`. Re-parse the
/// token stream as an expression list and walk whatever parses.
fn visit_macro(
    mac: &syn::Macro,
    schema: &ConfigSchema,
    bindings: &BTreeMap<String, String>,
    read: &mut BTreeSet<(String, String)>,
) {
    let tokens = mac.tokens.to_string();
    for chunk in split_top_level_commas(&tokens) {
        if let Ok(expr) = syn::parse_str::<syn::Expr>(&chunk) {
            visit_expr(&expr, schema, bindings, read);
        }
    }
}

fn split_top_level_commas(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in source.chars() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn visit_expr(
    expr: &syn::Expr,
    schema: &ConfigSchema,
    bindings: &BTreeMap<String, String>,
    read: &mut BTreeSet<(String, String)>,
) {
    match expr {
        syn::Expr::Field(field) => {
            if let syn::Member::Named(name) = &field.member
                && let Some(base) = struct_of_expr(&field.base, schema, bindings)
            {
                read.insert((base, name.to_string()));
            }
            visit_expr(&field.base, schema, bindings, read);
        }
        syn::Expr::ForLoop(loop_expr) => {
            let mut inner = bindings.clone();
            if let Some(name) = element_struct_of(&loop_expr.expr, schema, bindings) {
                bind_pattern(&loop_expr.pat, &name, &mut inner);
            }
            visit_expr(&loop_expr.expr, schema, bindings, read);
            visit_stmts(&loop_expr.body.stmts, schema, &mut inner, read);
        }
        syn::Expr::Block(block) => {
            let mut inner = bindings.clone();
            visit_stmts(&block.block.stmts, schema, &mut inner, read);
        }
        syn::Expr::Closure(closure) => {
            // `.iter().map(|resource| ...)`: the closure parameter carries the
            // element type of the collection being iterated.
            visit_expr(&closure.body, schema, bindings, read);
        }
        syn::Expr::MethodCall(call) => {
            // A method on a config field still reads that field:
            // `cfg.identity_provider.take()` consumes it.
            if let syn::Expr::Field(field) = &*call.receiver
                && let syn::Member::Named(name) = &field.member
                && let Some(base) = struct_of_expr(&field.base, schema, bindings)
            {
                read.insert((base, name.to_string()));
            }
            // `.map`/`.for_each`/`.filter` receive the element type, so bind
            // their closure parameter before walking the closure body.
            if matches!(
                call.method.to_string().as_str(),
                "map" | "for_each" | "filter" | "filter_map" | "retain" | "find"
            ) && let Some(name) = element_struct_of(&call.receiver, schema, bindings)
            {
                for arg in &call.args {
                    let syn::Expr::Closure(closure) = arg else {
                        continue;
                    };
                    let mut inner = bindings.clone();
                    bind_pattern(&closure.inputs[0], &name, &mut inner);
                    visit_expr(&closure.body, schema, &inner, read);
                }
            }
            visit_expr(&call.receiver, schema, bindings, read);
            for arg in &call.args {
                visit_expr(arg, schema, bindings, read);
            }
        }
        syn::Expr::Call(call) => {
            for arg in &call.args {
                visit_expr(arg, schema, bindings, read);
            }
        }
        syn::Expr::Match(match_expr) => {
            visit_expr(&match_expr.expr, schema, bindings, read);
            for arm in &match_expr.arms {
                visit_expr(&arm.body, schema, bindings, read);
            }
        }
        syn::Expr::If(if_expr) => {
            visit_expr(&if_expr.cond, schema, bindings, read);
            {
                let mut inner = bindings.clone();
                visit_stmts(&if_expr.then_branch.stmts, schema, &mut inner, read);
            }
            if let Some((_, otherwise)) = &if_expr.else_branch {
                visit_expr(otherwise, schema, bindings, read);
            }
        }
        syn::Expr::Binary(binary) => {
            visit_expr(&binary.left, schema, bindings, read);
            visit_expr(&binary.right, schema, bindings, read);
        }
        syn::Expr::Try(inner) => visit_expr(&inner.expr, schema, bindings, read),
        syn::Expr::Paren(inner) => visit_expr(&inner.expr, schema, bindings, read),
        syn::Expr::Reference(inner) => visit_expr(&inner.expr, schema, bindings, read),
        syn::Expr::Unary(inner) => visit_expr(&inner.expr, schema, bindings, read),
        syn::Expr::Cast(inner) => visit_expr(&inner.expr, schema, bindings, read),
        syn::Expr::Await(inner) => visit_expr(&inner.base, schema, bindings, read),
        syn::Expr::Struct(struct_expr) => {
            for field in &struct_expr.fields {
                visit_expr(&field.expr, schema, bindings, read);
            }
        }
        syn::Expr::Array(array) => {
            for element in &array.elems {
                visit_expr(element, schema, bindings, read);
            }
        }
        syn::Expr::Tuple(tuple) => {
            for element in &tuple.elems {
                visit_expr(element, schema, bindings, read);
            }
        }
        syn::Expr::Index(index) => {
            visit_expr(&index.expr, schema, bindings, read);
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) = &*index.index
                && let Ok(position) = lit.base10_parse::<usize>()
                && let Some(base) = struct_of_expr(&index.expr, schema, bindings)
                && base == "Config"
                && let Some(field) = schema
                    .structs
                    .get("Config")
                    .and_then(|fields| fields.get(position))
            {
                read.insert(("Config".to_string(), field.clone()));
            }
        }
        _ => {}
    }
}

/// Binds every identifier in a pattern to a struct name. Handles the tuple form
/// used by `enumerate()`: `for (index, idp) in ...`.
fn bind_pattern(pat: &syn::Pat, struct_name: &str, bindings: &mut BTreeMap<String, String>) {
    match pat {
        syn::Pat::Ident(ident) => {
            bindings.insert(ident.ident.to_string(), struct_name.to_string());
        }
        syn::Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                bind_pattern(element, struct_name, bindings);
            }
        }
        syn::Pat::TupleStruct(tuple) => {
            for element in &tuple.elems {
                bind_pattern(element, struct_name, bindings);
            }
        }
        syn::Pat::Reference(reference) => bind_pattern(&reference.pat, struct_name, bindings),
        syn::Pat::Paren(inner) => bind_pattern(&inner.pat, struct_name, bindings),
        _ => {}
    }
}

/// The config struct an expression evaluates to, when inferable.
fn struct_of_expr(
    expr: &syn::Expr,
    schema: &ConfigSchema,
    bindings: &BTreeMap<String, String>,
) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => {
            let name = path.path.segments.last()?.ident.to_string();
            bindings.get(&name).cloned()
        }
        syn::Expr::Field(field) => {
            let syn::Member::Named(name) = &field.member else {
                return None;
            };
            let base = struct_of_expr(&field.base, schema, bindings)?;
            schema
                .field_target(&base, &name.to_string())
                .map(ToString::to_string)
        }
        syn::Expr::Try(inner) => struct_of_expr(&inner.expr, schema, bindings),
        syn::Expr::Paren(inner) => struct_of_expr(&inner.expr, schema, bindings),
        syn::Expr::Reference(inner) => struct_of_expr(&inner.expr, schema, bindings),
        _ => None,
    }
}

/// The config struct yielded by iterating an expression, e.g. `&cfg.connectors`.
fn element_struct_of(
    expr: &syn::Expr,
    schema: &ConfigSchema,
    bindings: &BTreeMap<String, String>,
) -> Option<String> {
    match expr {
        syn::Expr::Reference(inner) => element_struct_of(&inner.expr, schema, bindings),
        syn::Expr::Paren(inner) => element_struct_of(&inner.expr, schema, bindings),
        syn::Expr::Try(inner) => element_struct_of(&inner.expr, schema, bindings),
        syn::Expr::MethodCall(call) if call.method == "iter" || call.method == "iter_mut" => {
            element_struct_of(&call.receiver, schema, bindings)
        }
        syn::Expr::MethodCall(call) if call.method == "enumerate" => {
            element_struct_of(&call.receiver, schema, bindings)
        }
        syn::Expr::Field(field) => {
            let syn::Member::Named(name) = &field.member else {
                return None;
            };
            let base = struct_of_expr(&field.base, schema, bindings)?;
            schema
                .field_target(&base, &name.to_string())
                .map(ToString::to_string)
        }
        _ => None,
    }
}

/// Fields that are documented as unimplemented, each with a tracked issue.
///
/// Empty today: `upstream_inflight_bytes` was the last entry and is now wired
/// through `ByteBudget` (INV-RES-01). Adding an entry is a deliberate act.
const CONFIG_FIELDS_NOT_YET_USED: &[&str] = &[];

/// Splits §8.2/§8.3 (implemented) from §8.4 (planned) and extracts backticked
/// snake_case identifiers from the first column of each table row.
fn split_error_code_sections(doc: &str) -> (Vec<String>, Vec<String>) {
    let mut implemented = Vec::new();
    let mut planned = Vec::new();
    let mut in_planned = false;
    for line in doc.lines() {
        if line.starts_with("### 8.4") {
            in_planned = true;
        } else if line.starts_with("## 9.") {
            break;
        } else if line.starts_with("### 8.2") || line.starts_with("### 8.3") {
            in_planned = false;
        }
        if !line.starts_with('|') {
            continue;
        }
        // Only the first cell names the code; later cells contain prose.
        let Some(cell) = line.trim_start_matches('|').split('|').next() else {
            continue;
        };
        for candidate in cell.split('`').skip(1).step_by(2) {
            let name = candidate.trim();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                continue;
            }
            if in_planned {
                planned.push(name.to_string());
            } else {
                implemented.push(name.to_string());
            }
        }
    }
    (implemented, planned)
}

/// Strips line comments and string literals so a rule about identifiers is not
/// tripped by prose that merely mentions the name.
///
/// Deliberately simple: this is a lint over our own source, not a Rust parser.
fn code_without_comments_or_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while let Some(c) = chars.next() {
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push('\n');
            }
            continue;
        }
        if in_block_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_string {
            if c == '\\' {
                // Skip the escaped character so `\"` does not close the string.
                chars.next();
                continue;
            }
            if c == '"' {
                in_string = false;
                out.push('"');
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push('"');
            continue;
        }
        out.push(c);
    }
    out
}

/// Double-quoted literals that contain Han characters, with their line numbers.
///
/// Comments and char literals are skipped: Chinese comments are the norm here and
/// `'"'` must not start a string. Raw strings are read as ordinary strings, which
/// is enough for the files this gate covers.
fn han_string_literals(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut chars = text.chars().peekable();
    let mut line = 1;
    let mut in_block = false;
    while let Some(c) = chars.next() {
        if c == '\n' {
            line += 1;
        }
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if c == '/' {
            match chars.peek() {
                Some('/') => {
                    for next in chars.by_ref() {
                        if next == '\n' {
                            line += 1;
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    in_block = true;
                }
                _ => {}
            }
            continue;
        }
        if c == '\'' {
            let mut ahead = chars.clone();
            match ahead.next() {
                Some('\\') => {
                    chars.next();
                    chars.next();
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    }
                }
                Some(_) if ahead.next() == Some('\'') => {
                    chars.next();
                    chars.next();
                }
                _ => {}
            }
            continue;
        }
        if c != '"' {
            continue;
        }
        let start = line;
        let mut literal = String::new();
        let mut escaped = false;
        for next in chars.by_ref() {
            if next == '\n' {
                line += 1;
            }
            if escaped {
                literal.push(next);
                escaped = false;
            } else if next == '\\' {
                escaped = true;
            } else if next == '"' {
                break;
            } else {
                literal.push(next);
            }
        }
        if literal.chars().any(is_han) {
            found.push((start, literal));
        }
    }
    found
}

fn is_han(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c)
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Drops `#[cfg(test)] mod ... { ... }` blocks so test-only code is not policed.
fn without_test_modules(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(index) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..index]);
        let after = &rest[index + "#[cfg(test)]".len()..];
        let Some(brace) = after.find('{') else {
            return out;
        };
        out.push_str(&after[..brace]);
        let mut depth = 0usize;
        let mut closed_at = None;
        for (offset, c) in after[brace..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        closed_at = Some(brace + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match closed_at {
            Some(end) => rest = &after[end..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Every `cfg` / `cfg!` predicate in `code` that switches on the `test` flag and
/// is not the annotation of a module.
///
/// `#[cfg(test)] mod tests` is where test-only code belongs and is deliberately
/// allowed. Everything else is a switch: a `#[cfg(test)]` on a function, the
/// inverse `#[cfg(not(test))]` (a production-only definition, the sharpest form
/// of the problem), or a runtime `cfg!(test)`.
fn test_flag_predicates(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    // `cfg!(` first so the attribute scan below cannot walk into an expression.
    for (marker, is_attribute) in [("cfg!(", false), ("cfg(", true)] {
        let mut search = 0;
        while let Some(at) = code[search..].find(marker) {
            let at = search + at;
            let open = at + marker.len() - 1;
            let Some(close) = matching_paren(code, open) else {
                break;
            };
            search = close;
            let predicate = &code[open + 1..close];
            if !mentions_identifier(predicate, "test") {
                continue;
            }
            if is_attribute && annotates_a_module(code, close) {
                continue;
            }
            found.push(predicate.trim().to_string());
        }
    }
    found
}

/// Index of the `)` matching the `(` at `open`.
fn matching_paren(code: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, c) in code[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether the attribute closing at `close` annotates a `mod` item.
fn annotates_a_module(code: &str, close: usize) -> bool {
    let mut rest = &code[close + 1..];
    loop {
        rest = rest.trim_start();
        // The closing `]` of this attribute, then any further attributes.
        if let Some(after) = rest.strip_prefix(']') {
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix("#[") {
            let Some(end) = after.find(']') else {
                return false;
            };
            rest = &after[end + 1..];
            continue;
        }
        break;
    }
    for visibility in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(after) = rest.strip_prefix(visibility) {
            rest = after.trim_start();
            break;
        }
    }
    match rest.strip_prefix("mod") {
        Some(after) => !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        None => false,
    }
}

/// Checks whether `needle` appears as a whole identifier in `code`.
fn mentions_identifier(code: &str, needle: &str) -> bool {
    let bytes = code.as_bytes();
    let mut start = 0;
    while let Some(found) = code[start..].find(needle) {
        let at = start + found;
        let before_ok =
            at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
        let end = at + needle.len();
        let after_ok =
            end >= bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

#[test]
fn the_value_layers_stay_free_of_shared_ownership() {
    // `re0auth-domain` is pure computation over values: no I/O, no clocks, no
    // trait objects. Holding an `Arc` there would mean it had gained state that
    // outlives one call, which is the first step towards the layer needing a
    // runtime. Keeping it value-shaped is what lets every domain test run
    // synchronously.
    //
    // `re0auth-api` is the contract layer. Its ports necessarily name
    // `Arc<dyn _>` for callers to share, so those few files are exempt; the
    // rest of it must stay value-shaped too.
    let allowed: &[&str] = &["connector.rs", "secret.rs", "idp.rs", "ports.rs"];
    for crate_dir in ["crates/re0auth-domain/src", "crates/re0auth-api/src"] {
        let mut files = Vec::new();
        rust_files(&root().join(crate_dir), &mut files);
        assert!(!files.is_empty(), "{crate_dir} contains no sources");
        for path in files {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .expect("file name");
            if allowed.contains(&name) {
                continue;
            }
            let text = fs::read_to_string(&path).expect("source");
            let code = without_test_modules(&code_without_comments_or_strings(&text));
            assert!(
                !mentions_identifier(&code, "Arc"),
                "{} must stay free of `Arc`: this layer holds values, and shared \
                 ownership means it has started carrying state",
                rel(&path)
            );
        }
    }
}

#[test]
fn every_crate_forbids_unsafe_code() {
    // A `forbid` cannot be overridden by an inner `allow`, so this is the
    // compile-time guarantee. The test catches a crate that forgot to declare
    // it at all — a missing attribute is silent, a present one is not.
    for crate_name in REGISTERED_CRATES {
        let lib = root().join(format!("crates/{crate_name}/src/lib.rs"));
        let path = if lib.exists() {
            lib
        } else {
            // Binary-only crates keep the attribute in `main.rs`.
            root().join(format!("crates/{crate_name}/src/main.rs"))
        };
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{crate_name} has neither lib.rs nor main.rs"));
        assert!(
            text.contains("#![forbid(unsafe_code)]"),
            "{crate_name} must declare #![forbid(unsafe_code)] at its root"
        );
    }
}

#[test]
fn the_copy_scan_detects_a_planted_string_and_skips_comments() {
    // Self-verification: a gate that cannot fail is not a gate.
    let text = r#"
// 中文注释
const A: &str = "批准";
let quote = '"';
const B: &str = "approve";
"#;
    let found = han_string_literals(text);
    assert_eq!(found.len(), 1, "only the Chinese literal may match");
    assert_eq!(found[0].1, "批准");
}

#[test]
fn user_facing_copy_lives_in_one_module() {
    // One home per surface keeps a wording change to one edit and makes the
    // eventual locale switch a single seam. Protocol text (`error_description`,
    // problem `detail`), audit targets and logs are not copy and stay put.
    let dir = root().join("crates/re0auth-http/src");
    let mut sources = Vec::new();
    rust_sources(&dir, &mut sources);
    let mut offenders = Vec::new();
    for path in sources {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name == "copy.rs" || name == "tests.rs" {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read Rust file");
        for (line, literal) in han_string_literals(&text) {
            offenders.push(format!("{}:{line}: {literal}", path.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "user-facing copy must live in copy.rs; found:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn request_path_logs_are_absent_and_would_be_redacted() {
    // 甲 + 丙：请求路径当前无日志，将来加了必须复核且不得记录凭据
    const REQUEST_PATH: &[&str] = &["crates/re0auth-http/", "crates/re0auth-app/"];
    const SENSITIVE: &[&str] = &[
        "access_token",
        "refresh_token",
        "client_secret",
        "code_verifier",
        "authorization_code",
        "master_key",
        "password",
    ];
    // 宏调用到参数常跨行，向后看固定窗口
    const WINDOW: usize = 6;

    let mut call_sites = 0_usize;
    for path in production_rust_files() {
        let rel_path = rel(&path);
        if !REQUEST_PATH
            .iter()
            .any(|prefix| rel_path.starts_with(prefix))
        {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read Rust file");
        let code = code_without_comments_or_strings(&text);
        let lines: Vec<&str> = code.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains("tracing::") || !line.contains('!') {
                continue;
            }
            call_sites += 1;
            let end = (index + WINDOW).min(lines.len());
            let window = lines[index..end].join(" ").to_ascii_lowercase();
            for needle in SENSITIVE {
                assert!(
                    !window.contains(needle),
                    "{rel_path}:{}: log call mentions `{needle}`. Tokens and secrets must \
                     never reach logs; log an opaque id (jti, family) instead of the value.",
                    index + 1
                );
            }
        }
    }

    assert_eq!(
        call_sites, 0,
        "the request path now has {call_sites} `tracing::*!` call site(s); this guard was \
         written when there were none. Re-read each site for token or secret \
         interpolation, then update the expected count here."
    );
}
