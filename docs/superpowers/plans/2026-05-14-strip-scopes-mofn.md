# Strip plan: scopes + M-of-N + execute infrastructure

**Date:** 2026-05-14
**Branch:** `feat/mac-integrity`
**Goal:** roll back 0.2.1 feature set (scopes, M-of-N authorisation, `pam-certauth execute`, CMS work-orders, approver chain, policy DSL, gc retention) while preserving:

- Base PAM cert auth from 0.1.x (USB + X.509 + host-binding + user-binding)
- MAC integrity feature added on `feat/mac-integrity` (29 commits, depends on monitord IPC + audit pipeline + `Stage2VerifiedChain`)
- The `pam_certauth_monitord` → `pam_certauth_cli` crate rename (renamed daemon binary stays; only the new subcommands are removed)

---

## 1. Summary stats

- **0.2.1 range:** `8edb923..518ee4e` (4 commits, 139 files changed, +11102 / −424 LOC).
- **To remove:**
  - Whole crate `pam_certauth_policy` (≈300 LOC + Cargo.toml + 1 test).
  - `pam_certauth_core` modules: `cms.rs` (≈1700 LOC), `cert_claims.rs` (≈200 LOC), `x509/scopes_ext.rs` (≈250 LOC), `x509/test_utils.rs` (only for cms_* tests).
  - `pam_certauth_cli` subcommand modules: `execute/*` (8 files, ≈1500 LOC), `policy_cmd/`, `gc_cmd/`, `hooks/` (≈300 LOC each).
  - 9 `cms_*` tests + `config_approver_trust.rs` + execute/gc/policy CLI tests (≈1931 LOC).
  - Docs: `work-order.md`, `execute.md`, `policy.md`, `migration.md`, `ipc.md` (≈1060 LOC) + sections in `x509-extensions.md`, `cert-issuance.md`, `configuration.md`, `threat-model.md`, `architecture.md`, `changelog.md`, `install.md`, `operations.md`, `development.md`.
  - Vagrant: `setup-mof-n-scenario.sh`, `test-happy.sh`, `test-negative.sh`, `test-gost.sh` (≈810 LOC).
  - `tests/scripts/install-and-test.sh` — strip M-of-N section.
  - systemd `pam-certauth-gc.{service,timer}` units.
  - `dist/config/config.toml.example` policy/scope/approver fragments (none currently — verify).
- **Estimated removed:** ≈8,500 LOC code + ≈2,000 LOC tests + ≈1,500 LOC docs + ≈900 LOC scripts ≈ **~12.9k LOC net removal**.
- **Files fully deleted (estimate):** ~45. **Files modified:** ~25.

### Key finding — MAC integrity IS decoupable

The MAC module (`crates/pam_certauth_core/src/mac/`) does **not** import any 0.2.1 items (`cms`, `cert_claims`, `scopes_ext`, `pam_certauth_policy`). `AuthContext` (`crates/pam_certauth_core/src/pam_data.rs`) carries only base fields + MAC fields (`cert_max_integrity`, `cert_ident`, `home_dir`) — there are no scope/approver/work_order fields to strip from the struct. Phase 2 (originally "strip AuthContext fields") therefore collapses to a no-op.

The remaining couplings are narrow and well-defined:
1. `flow.rs::session_open_extras()` calls `CertClaims::from_cert()` to build the v2 IPC `OpenSessionInfo` (`engineer_ski`, `engineer_cert_sha256`, `scopes`). Action: keep the IPC plumbing, replace `CertClaims` with an inline `SubjectKeyIdentifier + sha256(DER)` computation, drop `scopes`.
2. `entry.rs` has a `require_scope` PAM-argument gate (≈30 LOC). Action: remove that block + drop `required_scopes`/`scope_match` from `pam_args.rs`.
3. `flow.rs::FlowOutcome.cert_scopes` field. Action: remove the field; callers only use it to log.
4. `proto::SessionOpen.{engineer_ski, engineer_cert_sha256, scopes}` v2 IPC fields. **Decision: keep `engineer_ski` + `engineer_cert_sha256` (cheap, MAC audit may want them later), drop `scopes`.** This avoids a proto-version bump on the rollback. If preferred, see Risk #1 for the alternative "revert IPC to v1".

---

## 2. Phased removal

### Phase 1 — orphan removable items (no incoming refs)

Goal: delete code that nothing outside its own subtree imports. After this phase the workspace still compiles unchanged callers (because the items are unused outside).

Pre-check (verifies orphan status):
```
rg "pam_certauth_policy::" crates/  # only pam_certauth_cli/Cargo.toml dep
rg "use .*::cms::" crates/          # only cms_* tests
rg "use .*::cert_claims" crates/    # only flow.rs::session_open_extras
rg "use .*::scopes_ext" crates/     # only cert_claims.rs + flow.rs
```

**Files to delete:**

| File | Reason |
|------|--------|
| `crates/pam_certauth_policy/` (whole crate) | M-of-N policy engine. No consumer except `pam_certauth_cli` (removed in Phase 5). |
| `crates/pam_certauth_cli/src/execute/` (all 8 .rs files) | `pam-certauth execute` work-order runner. |
| `crates/pam_certauth_cli/src/policy_cmd/mod.rs` | `pam-certauth policy` subcommand. |
| `crates/pam_certauth_cli/src/gc_cmd/mod.rs` | `pam-certauth gc` retention for execute logs. |
| `crates/pam_certauth_cli/src/hooks/mod.rs` | Hook executor used only by `execute`. Pre-auth `[hooks]` config is in `pam_certauth_core::hooks` (separate, unaffected). |
| `crates/pam_certauth_cli/tests/execute_child_timeout.rs` | |
| `crates/pam_certauth_cli/tests/execute_cli.rs` | |
| `crates/pam_certauth_cli/tests/execute_e2e.rs` | |
| `crates/pam_certauth_cli/tests/gc_cli.rs` | |
| `crates/pam_certauth_cli/tests/policy_cli.rs` | |
| `crates/pam_certauth_core/tests/cms_argv_pattern.rs` | |
| `crates/pam_certauth_core/tests/cms_eku.rs` | |
| `crates/pam_certauth_core/tests/cms_happy.rs` | |
| `crates/pam_certauth_core/tests/cms_helpers_smoke.rs` | |
| `crates/pam_certauth_core/tests/cms_host_check.rs` | |
| `crates/pam_certauth_core/tests/cms_scope_check.rs` | |
| `crates/pam_certauth_core/tests/cms_shared_anchor.rs` | |
| `crates/pam_certauth_core/tests/cms_signing_time.rs` | |
| `crates/pam_certauth_core/tests/cms_tsa.rs` | |
| `crates/pam_certauth_core/tests/config_approver_trust.rs` | Test for `[approver_trust]` config block. |
| `crates/pam_certauth_core/tests/fixtures/cms_helpers.rs` | Helper for `cms_*` tests only. |
| `crates/pam_certauth_core/tests/fixtures/policy_required_mac.toml` | **VERIFY** — name suggests MAC. Likely keep; check via `git log -- <path>` whether added by MAC branch or 0.2.1. |

**Sources to modify (drop module mounts only):**

| File | Change |
|------|--------|
| `crates/pam_certauth_cli/src/lib.rs` | Remove `pub mod execute; pub mod gc_cmd; pub mod hooks; pub mod policy_cmd;`. |
| `crates/pam_certauth_cli/src/main.rs` | Drop `Execute/Policy/Gc` subcommands from clap enum + dispatch; leave only `Daemon`. |

**Commit:** `revert: remove execute/policy/gc/hooks subcommands and pam_certauth_policy crate`

---

### Phase 2 — strip core 0.2.1 modules

Goal: remove `cms`, `cert_claims`, `scopes_ext` from `pam_certauth_core`. Required call-site fix is one function in `flow.rs`.

**Pre-edits in `crates/pam_certauth/src/flow.rs`:**

In `session_open_extras()` replace the `CertClaims::from_cert()` call with direct openssl extraction:

```rust
// before: out.engineer_ski = c.subject_key_identifier; out.scopes = c.scopes…
// after:
let ski = cert.x509()
    .subject_key_id()
    .and_then(|s| Some(hex::encode(s.as_slice())))
    .unwrap_or_default();
let cert_sha256 = {
    let der = cert.x509().to_der().unwrap_or_default();
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&der))
};
out.engineer_ski = ski;
out.engineer_cert_sha256 = cert_sha256;
// scopes field removed (see Phase 3).
```

(Alternative: keep helper functions inline in `flow.rs`.)

Drop `cert_scopes` from `FlowOutcome` and from `entry.rs` callers (the two `FlowOutcome { … cert_scopes }` constructions and the destructure in `entry.rs:266`).

Drop `require_scope` PAM-argument gate in `entry.rs` (lines ≈275–290) and the related fields in `pam_args.rs` (`ScopeMatch` enum, `required_scopes`, `scope_match`, the doc-comments + `satisfies_required_scopes()` helper).

**Files to delete:**

| File | Reason |
|------|--------|
| `crates/pam_certauth_core/src/cms.rs` | CMS signing/verifying. |
| `crates/pam_certauth_core/src/cert_claims.rs` | Thin wrapper combining SKI + sha256 + scopes. |
| `crates/pam_certauth_core/src/x509/scopes_ext.rs` | `pam_cert_scopes` extension parser. |
| `crates/pam_certauth_core/src/x509/test_utils.rs` | Used only by `cms_*` tests (verify with `rg`). |

**Sources to modify:**

| File | Change |
|------|--------|
| `crates/pam_certauth_core/src/lib.rs` | Remove `pub mod cert_claims; pub mod cms;`. |
| `crates/pam_certauth_core/src/x509/mod.rs` | Remove `pub mod scopes_ext;`. |
| `crates/pam_certauth_core/src/x509/oids.rs` | Remove `pam_cert_scopes` and `approver_eku` OID constants. Keep host-binding + user-binding + MAX_INTEGRITY OIDs. |
| `crates/pam_certauth/src/flow.rs` | Inline SKI/sha256 in `session_open_extras`; drop `scopes` field of `SessionOpenExtras`; drop `cert_scopes` from `FlowOutcome`. |
| `crates/pam_certauth/src/entry.rs` | Remove `require_scope` block + `cert_scopes` destructuring. |
| `crates/pam_certauth/src/pam_args.rs` | Drop `ScopeMatch`, `required_scopes`, `scope_match`, `satisfies_required_scopes()`; keep `config_path` + `extra`. |

**Commit:** `revert: drop CMS/cert_claims/scopes_ext from core; inline SKI/sha256 in flow`

---

### Phase 3 — strip config sections + IPC scopes field

**`crates/pam_certauth_core/src/config/raw.rs`:**
- Remove field `approver_trust: Option<RawTrust>` (line 76).
- Remove field `policy: RawPolicySection` + the `RawPolicySection` struct (line 422-ish).
- Verify whether `[hooks]` is shared with base auth: `crates/pam_certauth_core/src/hooks/` is the executor module; the `hooks: Vec<RawHook>` field at line 97 is consumed by the **pre-auth hook executor** (kept). **Keep.**
- Confirm no `[execute]` or `[gc]` raw sections (grep shows none).

**`crates/pam_certauth_core/src/config/validated.rs`:**
- Remove `approver_trust: Option<TrustSection>` field + its `let approver_trust = …` plumbing (lines 68, 376, 436).
- Remove `policy: PolicySection` field + struct definition (line 74).
- Keep `hooks: Vec<HookConfig>` (pre-auth).

**`crates/pam_certauth_core/src/ipc/mod.rs`:**
- Remove `scopes: &'a [&'a str]` from `OpenSessionInfo`. Keep `engineer_ski`, `engineer_cert_sha256` (cheap + may be useful for MAC audit).

**`crates/pam_certauth_proto/src/{client.rs,server.rs,version.rs}`:**
- Remove `scopes: Vec<String>` from `SessionOpen` v2 payload (client + server side).
- Keep `engineer_ski`, `engineer_cert_sha256`.
- Bump v2 → v2.1 OR keep v2 and document the field removal (zero on-wire effect; the deserializer ignores absent optional fields). **Recommendation: bump payload schema rev but not protocol version; daemon and module are built together.**
- `crates/pam_certauth_proto/tests/v2_messages.rs` — drop scope assertions.

**`crates/pam_certauth_cli/src/server.rs`, `state.rs`, `registry.rs`:**
- Drop `scopes` field + its persistence in the active-session registry.

**`dist/config/config.toml.example`:**
- No `[policy]`/`[approver_trust]`/`[scopes]` sections currently exist in the example (grep confirms). Verify and skip if clean.

**Commit:** `revert(config,ipc): drop policy/approver_trust sections and scopes from SessionOpen`

---

### Phase 4 — docs, fixtures, scripts, packaging

**Docs — fully delete:**
- `docs/work-order.md`
- `docs/execute.md`
- `docs/policy.md`
- `docs/migration.md` (0.1.x → 0.2.1 migration only)
- `docs/ipc.md` (introduced for v2/scopes; the v1 IPC is documented in `architecture.md`)

**Docs — partial strip:**
- `docs/x509-extensions.md` — fully delete; only base extensions (host_binding, user_binding) are described, but they are already covered elsewhere. Action: delete file, ensure host/user-binding remain documented in `cert-issuance.md`. If they are not, move the host_binding + user_binding sections into `cert-issuance.md` first.
- `docs/cert-issuance.md` — remove scope-issuance examples + approver-EKU examples; keep MAX_INTEGRITY section.
- `docs/configuration.md` — remove `[policy]`/`[approver_trust]` blocks; keep `[mac]`.
- `docs/threat-model.md` — strip §9.X scope/approver attacks (verify section numbers); keep §9.1.6 categories-above-32bit (MAC).
- `docs/architecture.md` — drop M-of-N workflow diagram; keep monitord + MAC + base auth pipeline.
- `docs/operations.md` — strip execute/gc operations sections.
- `docs/development.md` — strip references to `pam_certauth_policy`.
- `docs/install.md` — strip M-of-N install steps; keep MAC sections.
- `docs/changelog.md` — remove the 0.2.1 entries; bump version note (see Phase 5).
- `README.md`, `README.ru.md` — strip scopes / M-of-N feature bullets.

**Test fixtures:**
- `crates/pam_certauth_core/tests/fixtures/cms_helpers.rs` — delete (in Phase 1).
- `crates/pam_certauth_core/tests/fixtures/policy_required_mac.toml` — **VERIFY origin.** If MAC-era, keep. If 0.2.1, delete. Likely MAC (filename pattern matches MAC config fixtures `tests/fixtures/policy-*.toml`).
- `tests/fixtures/policy-{required,optional,optional-fallback,ignore}.toml` — MAC `[mac]` fragments (commit `4a9671c`). **Keep.**
- `tests/fixtures/leaf-l*.cnf`, `leaf-malformed.cnf`, `leaf-no-ext.cnf`, `setup-mac-fixtures.sh` — MAC leaf fixtures. **Keep.**

**Scripts:**
- `vagrant/scripts/setup-mof-n-scenario.sh` — delete.
- `vagrant/scripts/test-happy.sh` — delete (entirely M-of-N happy path).
- `vagrant/scripts/test-negative.sh` — delete (entirely M-of-N negative scenarios).
- `vagrant/scripts/test-gost.sh` — delete (M-of-N RSA+GOST mixed-signer test). If a non-M-of-N GOST chain test is desired, rewrite from scratch later.
- `vagrant/scripts/test-mac.sh`, `bench-mac.sh` — **keep** (MAC).
- `vagrant/Vagrantfile` — remove the `mof-n` box stanza; keep MAC + base boxes. Verify what the README references.
- `tests/scripts/install-and-test.sh` — strip the M-of-N install/test block; keep base build/install + MAC integration.

**Debian packaging:**
- `debian/install` — drop `pam-certauth-gc.service`/`.timer`, `policy.toml.example`, any `execute` man pages.
- `debian/pam-certauth.dirs` — drop `/var/log/pam_certauth/exec` if listed.
- `debian/pam-certauth.manpages` — drop execute(8), policy(8), gc(8) man pages if listed.
- `debian/postinst`, `debian/prerm` — drop gc timer enable/disable.
- `debian/rules` — drop systemd unit installs for gc.
- `dist/systemd/pam-certauth-gc.service`, `pam-certauth-gc.timer` — delete files.
- No `debian/sudoers.d/pam-certauth-mof-n` exists today (verified). Skip.

**Commit:** `revert(docs,scripts,deb): drop work-order/execute/policy material and gc timer`

---

### Phase 5 — workspace deps + version bump + compile gate

**`Cargo.toml` (workspace root):**
- Remove `"crates/pam_certauth_policy"` from `members`.
- Bump `workspace.package.version` per release strategy. Suggested: stay at `0.2.1` and re-cut as `0.3.0-pre` since the scopes/M-of-N artefacts are removed but MAC is on the way. Coordinate with `docs/changelog.md`.

**`crates/pam_certauth_cli/Cargo.toml`:**
- Remove `pam_certauth_policy = { path = "../pam_certauth_policy", version = "0.2.1" }`.
- Remove deps that were only used by `execute`/`policy_cmd`/`gc_cmd`: candidates are `wildmatch`, `unicode-normalization`. Run `cargo udeps` (or visual inspection after Phase 1) to confirm. Keep openssl/sha2/hex (used by `flow.rs` inline SKI/sha256 after Phase 2 — but these are in `pam_certauth_core` deps, not CLI).

**`crates/pam_certauth_core/Cargo.toml`:**
- The 0.2.1 commit didn't add core deps that are exclusive to CMS — `openssl`/`hex`/`sha2` are all used elsewhere. Verify with `cargo tree` after Phase 2. No removal expected.

**`crates/pam_certauth_proto/Cargo.toml`:**
- Verify no extra deps added for scope-related serde derives. Likely clean.

**`Cargo.lock`:**
- Regenerate via `cargo build` or `cargo update --workspace` after edits.

**Build/test acceptance gate:**
```
cargo build --workspace --all-targets
cargo test  --workspace --no-fail-fast
cargo test  -p pam_certauth_core --features mac-tests mac_
cargo clippy --workspace --all-targets -- -D warnings
```
Then on the Astra VM:
```
vagrant up base
vagrant ssh base -c "/vagrant/tests/scripts/install-and-test.sh"
vagrant ssh base -c "sudo /vagrant/vagrant/scripts/test-mac.sh"
```

**Commit:** `revert: remove pam_certauth_policy from workspace; clean unused deps`

---

## 3. Risk callouts

### Risk 1 — IPC schema rev vs MAC daemon stability (HIGH)

**Problem:** Removing the `scopes` field from `SessionOpen` v2 changes the serde shape. If a partially-upgraded host has an old daemon (with `scopes`) and a new module (without), serde rejects the unknown field unless `#[serde(default)]` / `deny_unknown_fields = false` is in effect. The MAC feature is being built on top of the SAME `SessionOpen` payload (via `engineer_ski`/`engineer_cert_sha256` reuse).

**Mitigations:**
- Audit `pam_certauth_proto/src/{client,server}.rs` for `#[serde(deny_unknown_fields)]` — if present, removing a field is breaking. Keep the field as `#[serde(default, skip_serializing_if = "Vec::is_empty")]` and always populate with an empty Vec for at least one release cycle.
- Alternative: keep `scopes` in the wire format as `Vec<String>` but always send empty; treat as deprecated. Drop in next major. **Recommended** unless the user explicitly wants a clean schema.

### Risk 2 — `test_utils.rs` may be used by MAC tests (MEDIUM)

`crates/pam_certauth_core/src/x509/test_utils.rs` was added by the 0.2.1 commit. Need to verify it isn't used by MAC test files (`mac_ext_parse.rs`, `mac_orchestrator.rs`, etc.) before deletion. Pre-flight check:
```
rg "x509::test_utils|use .*test_utils" crates/pam_certauth_core/tests/ crates/pam_certauth_core/src/mac/
```
If any MAC test uses it, keep the file and only strip its CMS-specific helpers.

### Risk 3 — `pam_cert_scopes` / `approver_eku` OID consumers (LOW but easy to miss)

After deletion, the OID constants in `x509/oids.rs` are gone, but search-replace might miss string-form OIDs in fixtures (`tests/fixtures/leaf-*.cnf`), CLI examples (`docs/cert-issuance.md`), or Vagrant cert-gen scripts. The `setup-mof-n-scenario.sh` (deleted in Phase 4) embeds raw OIDs; the MAC fixture generator (`tests/fixtures/setup-mac-fixtures.sh`) should not — verify.

### Risk 4 — Workspace version 0.2.1 vs `Cargo.toml` `path` deps (LOW)

`pam_certauth_cli/Cargo.toml` has `pam_certauth_core = { path = "...", version = "0.2.1" }`. After the bump in Phase 5, the version constraint must match. `cargo build` will catch this immediately.

### Risk 5 — `pam_certauth_proto` v2 protocol marker (LOW)

`crates/pam_certauth_proto/src/version.rs` documents v2 = "added engineer_ski/sha256/scopes/uid". If we keep all four (only scopes hollowed), the comment can stay; if we remove scopes entirely, update the doc and the version constant if numeric.

---

## 4. Acceptance criteria

1. **Stub build:** `cargo build --workspace --all-targets` green on dev macOS (without astra-mac).
2. **Unit + integration tests:** `cargo test --workspace --no-fail-fast` green; MAC suite (`mac_*.rs`) all pass.
3. **No dangling references:**
   ```
   rg "pam_certauth_policy|cms::|cert_claims|scopes_ext|work_order|approver_chain|execute::" crates/ docs/ debian/ dist/
   ```
   returns zero hits outside changelog history.
4. **PAM module:** `cargo build -p pam_certauth --release` produces `libpam_certauth.so` that loads under `auth = pam_certauth.so` in the base VM's `/etc/pam.d/sudo` (verify via `sudo -K && sudo whoami` happy path).
5. **MAC E2E:** `vagrant/scripts/test-mac.sh` T1–T12 still pass on the Astra VM.
6. **Base e2e:** `tests/scripts/install-and-test.sh` happy path (USB + X.509 + host-binding) succeeds end-to-end without invoking any removed `pam-certauth execute` step.
7. **Clippy clean:** `cargo clippy --workspace --all-targets -- -D warnings`.
8. **Changelog:** `docs/changelog.md` carries a single `## 0.3.0-pre — strip 0.2.1` (or similar) entry naming the revert; no leftover 0.2.1 entries advertising scopes/M-of-N.

---

## 5. Out of scope (do later)

- Re-numbering of `pam_certauth_proto` to v1 (currently advertised v2). Keep v2 but emptied of `scopes`; full revert risks breaking the renamed daemon binary that's already on disk via the 0.2.1 release.
- Decision on whether `pam-certauth` binary keeps the `daemon` subcommand surface or reverts to `pam-certauth-monitord` invocation. Recommendation: keep `pam-certauth daemon` (the rename is orthogonal to scopes/M-of-N and the systemd unit already invokes the new binary).
- Re-introducing host_binding + user_binding documentation as their own short note in `docs/cert-issuance.md` if `x509-extensions.md` is deleted.
