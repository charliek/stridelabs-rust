# Parity with Python `stridelabs-mcp` 0.4.0

Every test of the Python package's suite — stridelabs-python at `1a9bd00`
(`chore(version): bump to 0.4.0`), `packages/mcp/tests/`, 122 test functions,
parameterized cases expanded to 151 rows — mapped to the Rust test that keeps
its assertion, or to a difference with its reason.

Where the Rust tests live:

| Short name | File |
|---|---|
| `tool::`, `principal::`, `verifier::`, `auth::`, `metadata::`, `resource::`, `limits::`, `pat::`, `redis::` (unit), `image_fetch::` (unit), `test_support::`, `tools_json::` | `crates/mcp/src/<module>.rs`, `#[cfg(test)]` |
| `mcp_http::` | `crates/mcp/tests/mcp_http.rs` (v0.6.0's end-to-end suite) |
| `rate_limit_http::`, `pat_credential::`, `redis_backed::`, `redis_live::`, `image_fetch::` (suite), `cors::`, `tools_freshness::` | `crates/mcp/tests/<name>.rs` |
| `http ssrf::…`, `http ssrf_pinning::…` | stridelabs-http: `crates/http/src/ssrf/*.rs` unit tests, `crates/http/tests/ssrf_pinning.rs` — the SSRF core lives there |
| `auth jwks::…`, `redis live::…` | stridelabs-auth `crates/auth/src/jwks.rs`, stridelabs-redis `crates/redis/tests/live.rs` |

**Difference** marks a row whose Python assertion has no Rust counterpart,
with the reason. The recurring ones:

- **D1 — no per-call DB session or user resolution in the boundary.** The
  Python decorator opened a session, committed or rolled back, and resolved
  the principal to the app's user. Here the app owns its pool, its
  transactions and its user mapping (README, "What stays in the app"), so
  commit/rollback/resolver assertions have nothing to bind to.
- **D2 — no decorator, no signature rewriting.** rmcp's `#[tool]` derives the
  schema from the `Parameters<T>` argument; `RequestContext` is never a schema
  field, so there is nothing to strip, no string annotations to resolve, and
  a wrongly shaped tool fails to compile.
- **D3 — the rate class is declared, not derived.** `ToolCall::rate_limit(limiter,
  class)` names the class per tool; Python's `resolve_rate_class(scopes,
  override, write_scopes)` is not ported.
- **D4 — limits are a table.** `MemoryLimiter::new` / `RedisRateLimiter::new`
  take `(RateClass, u32)` pairs; a dynamic lookup (Python's callable `limits`)
  is a custom `RateLimiter`.
- **D5 — audit vocabulary.** v0.6.0's audit line: target `stridelabs.mcp.tool`,
  snake_case fields, scope lists space-joined, outcome `internal` for
  unexpected errors (Python: `error`), and the error classes `ScopeError`,
  `RateLimited`, `Timeout`, `ToolError::User`, the internal error's type name,
  `panic` (Python: the exception's class name, e.g. `RateLimitError`,
  `TimeoutError`, `HTTPException`).
- **D6 — PAT principals.** `auth_method` is `token` (Python `pat`) and
  `client_id` is absent (Python `"pat"`): v0.6.0's `AuthMethod` and
  `Principal`.
- **D7 — no ASGI middleware.** The `401`/`503` challenges are built by
  `McpAuthLayer` itself, once, from the `ProtectedResource`; Python rewrote
  FastMCP's `WWW-Authenticate` after the fact, and passed the outage reason
  into the `503` body (here the description is fixed and the reason logged).
- **D8 — no lazy import.** A Rust crate has no import-time side effects; what
  Python's lazy `__init__` kept out of `sys.modules` is kept out of the build
  by features (`image-fetch`, `redis`, `cors`) and CI's dependency guards.

## `test_boundary.py`

| Python test | Rust | Note |
|---|---|---|
| `test_injected_params_hidden_and_annotations_resolved` | `tools_freshness::a_fresh_file_passes_whatever_order_the_router_lists` (the schema is the `Parameters` type's: `prompt` present) | D2 |
| `test_wrong_leading_params_rejected_at_decoration` | — | D2: a tool of the wrong shape does not compile |
| `test_tool_name_override` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (the audit `tool` is `ToolCall::new`'s name) | Registration names are rmcp's (`#[tool(name = …)]`) |
| `test_success_commits_resolves_user_and_rate_limits` | `mcp_http::legacy_clients_initialize_list_and_call_statelessly` (one audit line: tool, outcome `ok`, sub, auth_method, scopes, client_id, required_scopes, duration; no `error_class`; no email logged); `rate_limit_http::the_limit_is_checked_after_the_scopes_so_a_denial_consumes_nothing` (the limiter is asked with the subject and class) | D1 for commit and the resolver; D5 |
| `test_write_scoped_tool_uses_write_bucket` | `rate_limit_http::the_limit_is_checked_after_the_scopes_so_a_denial_consumes_nothing` (the write tool's checks are `(alice, write)`) | D3 |
| `test_rate_class_override_wins` | `rate_limit_http::limits_are_per_user_and_per_class` (the `generate` tool counts and refuses as `generate`) | D3: every class is an "override" |
| `test_needs_username_passed_to_resolver` | — | D1 |
| `test_needs_user_false_skips_resolver_and_session` | `rate_limit_http::the_limiter_state_is_shared_by_the_per_request_handler_instances` (a scope-less tool is still rate limited) | D1 for the resolver and session |
| `test_missing_scope_denied_with_actionable_message` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (the ScopeError text, `denied`/`ScopeError`); `rate_limit_http::the_limit_is_checked_after_the_scopes_so_a_denial_consumes_nothing` (no limiter call, the body never ran); `principal::the_message_matches_the_python_boundary` | |
| `test_rate_limited_call_is_classified_ratelimited` | `rate_limit_http::an_exceeded_limit_is_pythons_text_and_a_ratelimited_audit_line` (outcome `ratelimited`, the body never ran) | D5: `error_class` is `RateLimited` |
| `test_timeout_rolls_back_and_returns_clean_error` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`slow`: the fixed text, `timeout`/`Timeout`, `WARN`) | D1 (rollback); D5 |
| `test_per_tool_timeout_overrides_default` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`slow`'s `.timeout(50 ms)` against the 30 s default); `rate_limit_http::a_hanging_limiter_is_bounded_by_the_tool_deadline` | |
| `test_timeout_default_callable_read_at_call_time` | — | `ToolCall` is built per call, so `.timeout(settings.timeout())` is read at call time by construction; there is no bound default to re-read |
| `test_http_exception_translated_and_rolled_back` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`find_note`: `ToolError::user`'s message, outcome `error`) | D1; no `HTTPException`: the app's `impl From<AppError> for ToolError` is the translation; D5 |
| `test_unexpected_error_is_generic_to_client` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`explode`: "Internal server error.", the private message never logged); `tool::internal_errors_keep_their_type_and_never_their_message` | D5: outcome `internal`; D1 (rollback) |
| `TestPaginationHelpers::test_clamp_limit_bounds` | `tool::limits_clamp_into_range` | |
| `TestPaginationHelpers::test_clamp_offset_bounds` | `tool::offsets_clamp_to_non_negative` | |
| `TestPaginationHelpers::test_page_shape` | `tool::a_page_knows_whether_more_remain` | |

## `test_errors.py`

| Python test | Rust | Note |
|---|---|---|
| `test_tool_error_passes_through_unchanged` | `tool::user_and_denied_messages_are_shown_as_written` | |
| `test_timeout_error_subclass_passes_through` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`slow`'s text) | |
| `test_http_exception_detail_becomes_tool_error` | `tool::user_and_denied_messages_are_shown_as_written` | No `HTTPException`; an app error maps to `ToolError::user` through the app's `From` |
| `test_non_string_detail_becomes_generic_request_failed` | — | A `ToolError::user` message is a `String` by type: there is no non-string detail to fall back from |
| `test_unexpected_error_becomes_generic_and_keeps_cause` | `tool::internal_errors_keep_their_type_and_never_their_message` | The "cause" kept is the type name (`error_class`), the error itself is dropped unread |
| `test_unexpected_error_logs_class_and_frames_never_message` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (`error_class` = `std::io::error::Error`; `hunter2` appears nowhere in the capture) | No stack frames are logged (no traceback to format) |

## `test_fetch.py` → `ImageFetcher`

Python's server side is an `httpx.MockTransport`; every https row below goes
over a real TLS connection to a local server admitted by stridelabs-http's
`ssrf-test-support` (see the suite's module docs).

| Python test | Rust | Note |
|---|---|---|
| `TestUrlPolicy::test_http_rejected` | `image_fetch::http_other_schemes_and_garbage_are_refused_naming_https` | Exact message, not a fragment |
| `TestUrlPolicy::test_other_schemes_rejected` (ftp, file, gopher) | same | |
| `TestUrlPolicy::test_garbage_rejected` | same (`not a url at all`) | |
| `TestUrlPolicy::test_embedded_credentials_rejected` | `image_fetch::embedded_credentials_are_refused` | |
| `TestUrlPolicy::test_metadata_hostname_rejected` | `image_fetch::metadata_hosts_are_refused` | |
| `TestUrlPolicy::test_metadata_hostname_trailing_dot_rejected` | same | |
| `TestUrlPolicy::test_metadata_subdomain_rejected` | same | |
| `TestUrlPolicy::test_metadata_short_alias_rejected` | same | |
| `TestLiteralIpPolicy::test_non_public_literal_rejected[127.0.0.1]` | `image_fetch::non_public_ip_literals_are_refused` (all 19, in Python's order); also `http ssrf::pythons_nineteen_literal_hosts_are_rejected` | |
| `…[10.1.2.3]` | same | |
| `…[172.16.0.1]` | same | |
| `…[192.168.1.1]` | same | |
| `…[169.254.169.254]` | same | |
| `…[169.254.0.10]` | same | |
| `…[0.0.0.0]` | same | |
| `…[224.0.0.1]` | same | |
| `…[240.0.0.1]` | same | |
| `…[100.64.0.1]` | same | |
| `…[[::1]]` | same | |
| `…[[fc00::1]]` | same | |
| `…[[fd12:3456::1]]` | same | |
| `…[[fe80::1]]` | same | |
| `…[[ff02::1]]` | same | |
| `…[[::]]` | same | |
| `…[[::ffff:127.0.0.1]]` | same | |
| `…[[::ffff:169.254.169.254]]` | same | |
| `…[[::ffff:10.0.0.1]]` | same | |
| `TestLiteralIpPolicy::test_public_literal_allowed` | `image_fetch::an_ip_literal_host_is_fetched_as_itself` (a literal host is connected to as itself, no DNS, no SNI); `http ssrf::a_public_literal_passes_and_skips_dns` (`93.184.216.34` passes the policy) | A public address cannot be served offline, so the fetched literal is the test server's admitted loopback one |
| `TestDnsPolicy::test_resolution_failure_is_clean_error` | `image_fetch::a_resolution_failure_or_an_empty_answer_is_a_clean_error` | |
| `TestDnsPolicy::test_empty_resolution_is_clean_error` | same | |
| `TestDnsPolicy::test_non_public_resolution_rejected[addresses0: 10.0.0.5]` | `image_fetch::any_non_public_answer_poisons_the_resolution` (all 9 sets); also `http ssrf::any_non_public_answer_poisons_the_set` | |
| `…[addresses1: 127.0.0.1]` | same | |
| `…[addresses2: 169.254.169.254]` | same | |
| `…[addresses3: fe80::1]` | same | |
| `…[addresses4: fd00::1]` | same | |
| `…[addresses5: ::ffff:192.168.0.9]` | same | |
| `…[addresses6: public, 10.0.0.5]` | same | |
| `…[addresses7: 10.0.0.5, public]` | same | |
| `…[addresses8: public v6, ::1]` | same | |
| `TestDnsPinning::test_connects_to_resolved_ip_with_sni_and_host_preserved` | `image_fetch::an_image_comes_from_the_pinned_address_with_sni_host_and_accept_on_the_name` (SNI and `Host` on the name; the name resolves nowhere, so reaching the server proves the pin); `http ssrf_pinning::the_request_reaches_the_pinned_address_under_the_original_host_name` | Proven on a real connection, where Python inspected the request it handed `MockTransport` |
| `TestDnsPinning::test_prefers_ipv4_and_pins_a_validated_address` | `image_fetch::ipv4_is_preferred_and_a_validated_address_pinned` (a public IPv6 first: pinning it would fail the fetch); `http ssrf::ipv4_is_preferred_and_the_resolver_order_otherwise_stands` | |
| `TestResponsePolicy::test_redirect_rejected` | `image_fetch::a_redirect_is_refused` | |
| `TestResponsePolicy::test_non_200_rejected` | `image_fetch::a_non_200_is_refused_with_its_status` | |
| `TestResponsePolicy::test_non_image_content_type_rejected` | `image_fetch::a_content_type_that_is_not_a_raster_image_is_refused` (`text/html`, and more) | Also a missing `Content-Type`: `image_fetch::a_missing_content_type_is_refused` |
| `TestResponsePolicy::test_svg_content_type_rejected` | same (`image/svg+xml`, upper case with parameters, `image/foo+xml`) | |
| `TestResponsePolicy::test_lying_image_content_type_fails_magic_sniff` | `image_fetch::a_lying_content_type_fails_the_magic_sniff` | |
| `TestResponsePolicy::test_svg_body_with_png_content_type_rejected` | same (the SVG body) | |
| `TestResponsePolicy::test_declared_oversize_rejected_before_body` | `image_fetch::a_declared_oversize_is_refused_before_the_body` | |
| `TestResponsePolicy::test_streaming_cap_aborts_despite_lying_content_length` | `image_fetch::the_streaming_cap_aborts_a_body_that_keeps_going` (a chunked body past the cap); `http ssrf::a_lying_content_length_is_cut_by_the_stream_cap` (the lying header, on a raw stream) | Over real HTTP/1.1 an understated `Content-Length` truncates the body (hyper frames by it), so the over-the-wire case is chunked (stridelabs-http README) |
| `TestResponsePolicy::test_wall_clock_timeout` | `image_fetch::the_wall_clock_budget_is_enforced` | The budget is shortened with `ImageFetcher::with_timeout`, not a module global |
| `TestResponsePolicy::test_network_error_is_clean_message` | `image_fetch::a_network_error_is_a_clean_message` (connection refused, and a certificate for another name; no address in the message) | |
| `TestDataUris::test_happy_path_png` | `image_fetch::a_data_uri_decodes_and_its_scheme_is_case_insensitive` | |
| `TestDataUris::test_scheme_is_case_insensitive` | same (`DATA:`, `DaTa:`) | |
| `TestDataUris::test_whitespace_wrapped_payload_ok` | `image_fetch::a_whitespace_wrapped_payload_decodes` (newline, CRLF, space, tab, and `\x1c`, which Python's `str.split()` also strips); `image_fetch::whitespace_is_pythons` (unit) | |
| `TestDataUris::test_non_base64_data_uri_rejected` | `image_fetch::malformed_data_uris_are_refused_with_pythons_messages` | Exact message |
| `TestDataUris::test_missing_comma_rejected` | same | |
| `TestDataUris::test_non_image_media_type_rejected` | same (`text/plain`) | |
| `TestDataUris::test_svg_media_type_rejected` | same (`image/svg+xml`, and `image/x-xml`) | |
| `TestDataUris::test_invalid_base64_payload_rejected` | same (`!!!not-base64!!!`, and bad padding); `image_fetch::base64_is_as_strict_as_pythons_validate_true` (unit, CPython-checked rows) | |
| `TestDataUris::test_empty_payload_rejected` | same | |
| `TestDataUris::test_oversize_rejected_before_decode` | `image_fetch::an_oversize_data_uri_is_refused_before_and_after_decoding` (before decoding, and after: the decoded cap, exactly at the cap) | |
| `TestDataUris::test_payload_lying_about_media_type_fails_sniff` | `image_fetch::a_payload_lying_about_its_media_type_fails_the_sniff` | |
| `TestMagicSniff::test_accepted_formats_pass_sniff[prefix0: JPEG]` | `image_fetch::the_four_formats_pass_the_sniff`; `image_fetch::the_sniff_accepts_the_four_formats_only` (unit) | GIF87a as well as GIF89a |
| `…[prefix1: PNG]` | same | |
| `…[prefix2: GIF89a]` | same | |
| `…[prefix3: WebP]` | same | |
| `TestMagicSniff::test_riff_without_webp_rejected` | `image_fetch::riff_without_webp_fails_the_sniff` | |

Added, with no Python row: `image_fetch::a_compressed_response_is_refused_not_decoded`
(the SSRF core's `identity`-only difference), `…::the_content_type_is_read_case_insensitively_without_its_parameters`,
`…::the_media_type_and_parameters_are_read_as_python_reads_them`,
`…::a_refusal_is_a_user_error_for_the_model`, `image_fetch::the_policy_is_the_image_policy_and_the_setters_cannot_weaken_it`,
`image_fetch::every_refusal_becomes_a_user_error_with_its_message`.

## `test_lazy_import.py`

| Python test | Rust | Note |
|---|---|---|
| `test_import_ssrf_submodule_does_not_import_fastmcp` | — | Not applicable (D8) |
| `test_lazy_attr_access_ssrf_names_do_not_import_fastmcp` | — | Not applicable (D8) |
| `test_lazy_attr_access_fastmcp_names_still_work` | — | Not applicable (D8) |
| `test_unknown_attribute_raises_attribute_error` | — | Not applicable (D8): an unknown name does not compile |
| `test_dir_lists_public_api_without_importing_it` | — | Not applicable (D8) |
| `test_all_names_resolve_and_match_mapping` | — | Not applicable (D8): the re-exports are checked by the compiler |

## `test_limits.py`

| Python test | Rust | Note |
|---|---|---|
| `TestResolveRateClass::test_maps_scopes_to_buckets` | — | D3 |
| `TestResolveRateClass::test_override_wins_regardless_of_scopes` | — | D3 |
| `TestResolveRateClass::test_multiple_write_scopes` | — | D3 |
| `TestEnforceRateLimit::test_trips_after_limit_with_retry_hint` | `limits::trips_after_the_limit_with_pythons_text_and_retry_hint` (the whole text, the retry exact); `redis_live::the_limit_trips_with_pythons_text`; `rate_limit_http::an_exceeded_limit_is_pythons_text_and_a_ratelimited_audit_line` | |
| `TestEnforceRateLimit::test_per_user_buckets` | `limits::buckets_are_per_subject_and_per_class`; `rate_limit_http::limits_are_per_user_and_per_class`; `redis_live::the_limit_trips_with_pythons_text` (Bob's window) | |
| `TestEnforceRateLimit::test_per_class_buckets` | same | |
| `TestEnforceRateLimit::test_window_resets_when_minute_rolls_over` | `limits::the_window_resets_when_the_minute_rolls_over`; `limits::the_window_is_the_wall_clock_minute_not_a_sliding_one`; `redis_live::a_new_minute_is_a_new_window` | |
| `TestEnforceRateLimit::test_first_hit_sets_window_ttl` | `redis_live::the_window_key_and_its_ttl_are_pythons` (60 s on the first hit, untouched by the next); `redis live::the_first_hit_counts_one_and_sets_the_window_ttl` | Against a real Redis, not a fake |
| `TestEnforceRateLimit::test_zero_limit_disables_bucket` | `limits::a_zero_or_absent_limit_never_limits_and_counts_nothing`; `redis_live::a_limit_of_zero_writes_nothing`; `redis_backed::an_unlimited_class_never_touches_redis`; `rate_limit_http::a_zero_limit_is_off` | |
| `TestEnforceRateLimit::test_unset_class_disables_bucket` | `limits::a_zero_or_absent_limit_never_limits_and_counts_nothing` (an absent class); `redis_backed::an_unlimited_class_never_touches_redis` | |
| `TestEnforceRateLimit::test_callable_limits_lookup` | — | D4 |
| `TestEnforceRateLimit::test_fails_open_when_redis_down` | `redis_backed::a_dead_redis_fails_open_with_a_warning` (allowed past a limit of 1, one `warn` per hit, no URL logged) | |
| `TestEnforceRateLimit::test_key_prefix_isolates_apps` | `redis_live::prefixes_isolate_limiters`; `redis_live::the_window_key_and_its_ttl_are_pythons` (the exact key) | |

Added, with no Python row: `limits::refused_calls_count_too`,
`limits::expired_entries_are_dropped_when_the_window_rolls_over`,
`limits::concurrent_calls_never_over_admit`,
`limits::a_check_stalled_reading_the_clock_cannot_reopen_the_previous_minute`,
`limits::a_clock_stepped_backwards_counts_against_the_newest_window`,
`limits::even_a_limit_of_u32_max_refuses_the_call_after_it`,
`redis_live::concurrent_hits_are_counted_atomically`, and the boundary rows of
`rate_limit_http` (the hanging, panicking and cancelled limiter; state shared
across the per-request handler instances).

## `test_metadata.py`

| Python test | Rust | Note |
|---|---|---|
| `test_bare_well_known_path_serves_document` | `metadata::the_document_is_served_at_both_origin_root_paths`; `mcp_http::the_metadata_document_is_served_at_the_origin_root_without_auth` | |
| `test_path_suffixed_variant_serves_same_document` | same | |
| `test_suffix_derives_from_resource_url_path` | `resource::a_port_and_a_nested_path_carry_into_the_metadata_url` (`/v1/mcp`); `resource::everything_derives_from_the_one_url` | |
| `test_root_resource_url_serves_only_bare_path` | `metadata::a_root_resource_is_served_at_the_bare_path_only`; `resource::a_resource_at_the_origin_root_has_one_metadata_path` | |

## `test_principal.py`

| Python test | Rust | Note |
|---|---|---|
| `TestGetPrincipal::test_no_access_token_raises` | `mcp_http::a_tool_served_without_the_auth_layer_is_not_authenticated` ("Not authenticated.", `denied`/`NotAuthenticated`, no `sub`) | |
| `TestGetPrincipal::test_token_without_auth_method_raises` | same | A `Principal` exists only where `McpAuthLayer` put one, and always has an `AuthMethod`: there is no half-built token to refuse |
| `TestGetPrincipal::test_token_without_sub_raises` | `verifier::an_empty_or_missing_subject_is_invalid`; `verifier::prefixed_credentials_go_to_the_app_and_are_tokens` (an empty credential subject) | Refused at verification (a `401`), not at the tool |
| `TestGetPrincipal::test_jwt_claims_populate_principal` | `verifier::identity_claims_are_optional_and_client_id_falls_back_to_azp`; `verifier::scopes_come_from_scope_scp_or_both` | |
| `TestGetPrincipal::test_azp_falls_back_for_client_id` | `verifier::identity_claims_are_optional_and_client_id_falls_back_to_azp` | |
| `TestGetPrincipal::test_pat_principal_has_no_email` | `pat_credential::a_valid_pat_is_its_identity_with_exactly_the_ceiling` (no email, name or client id) | D6 |
| `TestCheckScopes::test_passes_when_all_granted` | `principal::granted_scopes_pass` | |
| `TestCheckScopes::test_missing_scope_names_it_and_lists_granted` | `principal::the_message_matches_the_python_boundary` | |
| `TestCheckScopes::test_no_scopes_granted_reads_none` | `principal::a_scopeless_credential_grants_none` | |
| `TestCheckScopes::test_scope_error_is_tool_error` | `mcp_http::every_failure_is_a_tool_error_with_one_audit_line` (the ScopeError text reaches the client as an `isError` result) | |
| `TestRequireScopes::test_returns_principal_on_success` | `principal::granted_scopes_pass`; `mcp_http::the_2026_07_28_lifecycle_works_without_initialize` (`add_note`'s scope passes, the body gets the principal) | No `require_scopes()`: `ToolCall::scopes` / `Principal::check_scopes` |
| `TestRequireScopes::test_raises_on_missing` | `principal::the_message_matches_the_python_boundary` | same |

## `test_server.py`

| Python test | Rust | Note |
|---|---|---|
| `TestReconcileDisabledTools::test_disabled_tool_hidden_sibling_unaffected` | — | The kill switch is rmcp's `ToolRouter::disable_route` (README, "Not included"); imgmcp's own suite tests it over HTTP |
| `TestReconcileDisabledTools::test_removed_from_set_is_reenabled_on_next_reconcile` | — | Python reconciled a module-level singleton across reloads; a Rust router is built once per process from config |
| `TestReconcileDisabledTools::test_reconcile_is_idempotent` | — | same |
| `TestReconcileDisabledTools::test_swapping_the_disabled_tool` | — | same |
| `TestBuildMcpHttpApp::test_sets_auth_and_reconciles` | `mcp_http::legacy_clients_initialize_list_and_call_statelessly` (the assembled `router` serves authenticated calls) | No lifespans to combine: `router` returns an axum `Router` |
| `TestBuildMcpHttpApp::test_unauthenticated_request_gets_challenge_with_scope_hint` | `mcp_http::an_unauthenticated_request_gets_the_discovery_challenge`; `auth::no_credential_is_a_401_with_no_error_code` | |

## `test_ssrf_pinning_contract.py`

| Python test | Rust | Note |
|---|---|---|
| `test_https_socket_connects_to_pinned_ip_with_sni_on_original_host` | `http ssrf_pinning::the_request_reaches_the_pinned_address_under_the_original_host_name`; `http ssrf_pinning::a_certificate_for_another_name_fails_the_fetch`; `image_fetch::an_image_comes_from_the_pinned_address_with_sni_host_and_accept_on_the_name` | A real TLS server: the connection, SNI and certificate check are observed, not instrumented |
| `test_http_socket_connects_to_pinned_ip` | `http ssrf::the_pinned_resolver_answers_only_the_pinned_name`; `http ssrf::the_port_defaults_by_scheme` | The plain-http path shares the pinned resolver; an image fetch never uses it (https only) |

## `test_verifier.py`

| Python test | Rust | Note |
|---|---|---|
| `TestPatBranch::test_valid_pat_gets_ceiling_scopes_via_injected_validator` | `pat_credential::a_valid_pat_is_its_identity_with_exactly_the_ceiling`; `pat_credential::behind_the_verifier_a_pat_is_a_token_principal`; `pat_credential::pats_work_end_to_end_and_refusals_keep_their_status` | D6; `SlauthPatCredential` against a wiremock slauth, where Python injected a stub |
| `TestPatBranch::test_invalid_pat_is_none` | `pat_credential::every_validation_outcome_maps_to_invalid_or_unavailable` (unknown, revoked, malformed → `Invalid`); `pat_credential::pats_work_end_to_end_and_refusals_keep_their_status` (→ `401 invalid_token`) | |
| `TestPatBranch::test_pat_slauth_outage_raises_unavailable` | same (erroring, slow, unreachable → `Unavailable`; → `503`) | |
| `TestPatBranch::test_non_pat_token_never_hits_the_pat_seam` | `verifier::prefixed_credentials_go_to_the_app_and_are_tokens` (a non-matching token takes the JWT path, and a prefixed one never reaches the JWKS) | |
| `TestJwtBranch::test_valid_jwt_with_scp_array` | `verifier::scopes_come_from_scope_scp_or_both` | Scopes are the union of `scope` and `scp` |
| `TestJwtBranch::test_valid_jwt_with_scope_string` | same | |
| `TestJwtBranch::test_wrong_audience_rejected` | `verifier::a_token_for_another_audience_or_issuer_is_invalid`; `mcp_http::refused_tokens_get_invalid_token_whatever_the_reason` | |
| `TestJwtBranch::test_expired_jwt_rejected` | same (`expires_in(-3600)`) | jsonwebtoken's 60 s leeway (README, "Testing a consumer") |
| `TestJwtBranch::test_bad_signature_rejected` | `test_support::the_rejection_shapes_are_rejected` (`signed_by_untrusted_key`); `mcp_http::refused_tokens_get_invalid_token_whatever_the_reason` | |
| `TestJwtBranch::test_jwks_outage_raises_unavailable_not_none` | `verifier::a_jwks_outage_is_unavailable_not_invalid`; `mcp_http::a_jwks_outage_is_a_503_not_a_sign_out` | |
| `TestJwtBranch::test_fetch_jwks_wraps_transport_error` | `auth jwks::an_unreachable_endpoint_is_a_jwks_error` (a refused connection is `AuthError::Jwks`), which `verifier`'s `From<AuthError>` makes `Unavailable` (`verifier::a_jwks_outage_is_unavailable_not_invalid`) | |
| `TestResourceUrlAndMiddleware::test_resource_url_is_canonical_never_suffixed` | `resource::everything_derives_from_the_one_url`; `resource::non_canonical_urls_are_rejected_naming_the_canonical_form` | Non-canonical input is refused, not normalized |
| `TestResourceUrlAndMiddleware::test_boundary_middleware_is_outermost` | — | D7: one layer, no middleware stack to order |
| `TestAuthBoundaryMiddleware::test_appends_scope_hint_to_401_challenge` | `auth::every_refused_token_gets_the_same_invalid_token_challenge`; `auth::no_credential_is_a_401_with_no_error_code` | D7 |
| `TestAuthBoundaryMiddleware::test_does_not_duplicate_an_existing_scope` | `auth::an_empty_scope_hint_omits_the_scope_parameter` | D7: the challenge is built once, so there is no second `scope` to avoid |
| `TestAuthBoundaryMiddleware::test_non_401_untouched` | `auth::a_valid_token_reaches_the_service_with_its_principal` | |
| `TestAuthBoundaryMiddleware::test_slauth_unavailable_maps_to_503` | `auth::a_jwks_outage_is_a_503_that_keeps_the_token`; `mcp_http::a_jwks_outage_is_a_503_not_a_sign_out` | D7: the `503` description is fixed, the reason logged |

Added, with no Python row (the PAT cache was imgmcp's, not this package's):
`pat_credential::a_hit_skips_slauth_and_the_key_is_the_digest`,
`…::the_ttl_can_be_shortened`, `…::rejections_and_outages_are_never_cached`,
`…::the_ceiling_is_applied_fresh_on_a_hit`,
`…::a_malformed_cached_value_falls_through_to_slauth`,
`…::a_cache_read_failure_falls_through_to_each_slauth_outcome`,
`…::a_cache_write_failure_still_succeeds_without_a_second_validation`,
`…::a_cache_that_hangs_is_skipped_after_the_bound`,
`…::a_token_not_shaped_like_a_pat_skips_the_cache`,
`…::an_entry_past_its_expiry_is_a_miss_and_is_replaced`,
`…::a_late_write_cannot_extend_validity_past_validation_plus_ttl`,
`pat::the_key_is_pythons_truncated_sha256_hex`,
`pat::a_ttl_is_whole_seconds_rounded_down_from_one_second_to_a_day`,
`redis::an_entry_is_stored_as_uuid_colon_expiry_and_nothing_else_reads_back`,
`redis_backed::a_dead_cache_is_an_error_and_the_credential_falls_through`,
and the `redis_live` PAT-cache rows (round trip of `{uuid}:{expires_at}`
under the prefixed digest with its TTL, the TTL rule, no TTL refresh on a
hit, malformed values including the bare-UUID form, an expired entry,
prefix isolation).
CORS (`cors::*`) and the tools snapshot (`tools_json::*`,
`test_support::*` freshness rows, `tools_freshness::*`) are Rust additions
too: Python's CORS was its consumers' Starlette middleware, and it had no
committed tool list.

## Totals

| File | Functions | Rows (expanded) | Mapped | Difference only | Not applicable |
|---|---|---|---|---|---|
| `test_boundary.py` | 18 | 18 | 15 | 3 | 0 |
| `test_errors.py` | 6 | 6 | 5 | 1 | 0 |
| `test_fetch.py` | 38 | 67 | 67 | 0 | 0 |
| `test_lazy_import.py` | 6 | 6 | 0 | 0 | 6 |
| `test_limits.py` | 13 | 13 | 9 | 4 | 0 |
| `test_metadata.py` | 4 | 4 | 4 | 0 | 0 |
| `test_principal.py` | 12 | 12 | 12 | 0 | 0 |
| `test_server.py` | 6 | 6 | 2 | 4 | 0 |
| `test_ssrf_pinning_contract.py` | 2 | 2 | 2 | 0 | 0 |
| `test_verifier.py` | 17 | 17 | 16 | 1 | 0 |
| **Total** | **122** | **151** | **132** | **13** | **6** |
