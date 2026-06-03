# Silent Payments — migrate to the official embit `feat/sp-phase2` branch

**Date:** 2026-06-03
**Branch:** `sp`
**Status:** Approved design, ready for implementation planning

## Summary

SeedSigner currently carries a partial BIP-352 Silent Payments (SP) integration built
against a personal embit fork (`notTanveer/embit@god`). A dedicated, better-tested embit
branch now exists upstream: `diybitcoinhardware/embit@feat/sp-phase2`. This work migrates
SeedSigner onto that branch, makes the SP signing path actually functional (it is dead
code today), removes obsolete code introduced by the earlier attempt, and adds test
coverage.

**Scope:** make SP signing work end-to-end + cleanup + tests. **No new SP UI features**
beyond what already exists (the SP address export view stays). Remaining UI phases — SP
indicator in PSBT review, address-explorer SP mode, on-device SP address verification, and
label-selection UI — are explicitly deferred.

## Background: why the current implementation does not work

The `sp` branch added SP code across `seed.py`, `psbt_parser.py`, `psbt_views.py`,
`seed_views.py`, `settings_definition.py`, `embit_utils.py`, and `decode_qr.py`. Review of
that code against both the old `god` fork and the target `feat/sp-phase2` branch found it
non-functional:

1. **SP fields are never parsed.** `decode_qr.get_psbt()` parses with vanilla
   `embit.psbt.PSBT.parse()`. Vanilla PSBT outputs are `OutputScope`, which have no
   `sp_data`. So `PSBTParser.has_sp_outputs` (`getattr(out, "sp_data", None)`) is always
   `False`, and the entire SP signing path is dead.
2. **`sign_sp()` imports a removed symbol.** It does
   `from embit.silent_payments import populate_silent_payment_send_data`. That high-level
   entry point exists in **neither** `god` nor `feat/sp-phase2` (it was dropped). The call
   would `ImportError` if ever reached.
3. **`trim()` cannot carry SP fields.** It builds a vanilla `psbt.PSBT(tx.tx)` and then
   tries to copy SP attributes onto it; the vanilla scopes have no slots for them.
4. **Dead helpers.** `Seed.get_sp_keys` is never called; `decode_silent_payment_address`
   is imported in `psbt_parser.py` but unused.

## Target API: how `feat/sp-phase2` does Silent Payments

Key facts established by reading the branch (`src/embit/silent_payments/`) and its tests
(`tests/tests/test_psbt_signer_sp.py`):

- **`SilentPaymentsPSBT` is a drop-in superset of `PSBT`.** It subclasses `PSBT`, only
  overriding `PSBTIN_CLS`/`PSBTOUT_CLS` (to `SPInputScope`/`SPOutputScope`) and adding
  SP global fields. `parse()` is inherited. All SP behavior is gated on `version == 2` and
  `sp_data is not None`, so parsing a normal v0 or v2 (non-SP) PSBT with it behaves
  identically to vanilla `PSBT`.
- **Signing is a single call.** `SilentPaymentsPSBT.sign_with(root)` internally:
  signs regular inputs (`super().sign_with`), then if SP outputs are present calls
  `_sign_with_sp(root)`, then `_sign_sp_spends(root)`. There is no separate
  populate/validate/derive sequence to orchestrate from the caller.
- **The signer contributes shares + proofs, not output scripts.** `_sign_with_sp` computes
  per-**input** ECDH shares (`inp.sp_ecdh_shares`) and DLEQ proofs (`inp.sp_dleq_proofs`).
  It does **not** fill output `script_pubkey` — deriving the final SP output scripts is the
  coordinator's job in the BIP-375 hardware-signer model. SeedSigner therefore does not
  derive output scripts.
- **Entropy is internal.** `aux_rand` defaults to `None`, in which case embit uses
  `embit.misc.urandom` (→ `/dev/urandom`, backed by the RPi hardware RNG). The caller does
  not pass `aux_rand`. (Krux mixes a wallet nonce because the K210 has weak entropy;
  SeedSigner on RPi does not need this.)
- **Address helpers are API-compatible.** `generate_silent_payment_address(scan_privkey,
  spend_pubkey, label=None, network="main", version=0)` is unchanged from what `seed.py`
  already calls. `feat/sp-phase2` also ships `embit.descriptor.sp` and `finalize_sp_spends`,
  so nothing SeedSigner might want is lost by leaving `god` behind.

Reference: the Krux integration (`selfcustody/krux@feat/silent-payments`) confirms the
"always parse with `SilentPaymentsPSBT`" pattern. Its multi-stage signing reflects an older
embit; we follow the simpler single-`sign_with()` flow of `feat/sp-phase2`.

## Decisions (from brainstorming)

1. **Scope:** make signing work + cleanup + tests; no new SP UI features.
2. **embit pin:** `requirements.txt` pins `diybitcoinhardware/embit` at commit
   `36e60e41f7cf7e4ea24efd2e379e337b1f0a1db9` (tip of `feat/sp-phase2` as of 2026-06-03).
   The local editable install at `/home/sahil/dev/embit` is checked out to the **same
   commit** so tests run against production code. (The local `perf-sp` branch has 2 extra
   commits — audit fixes + a NUMS refactor — that are intentionally **not** included.)
3. **SP setting:** collapse to a plain Enabled/Disabled toggle. Remove
   `OPTION__ENABLED_WITH_LABELS` and `OPTIONS__SILENT_PAYMENTS`; re-add a labels option only
   when label UI is actually built.

## Architecture decision: how to wire in `SilentPaymentsPSBT`

**Chosen: one tiny indirection (Approach B).** Add a single resolver
`get_psbt_cls()` (in `helpers/embit_utils.py`) that returns `SilentPaymentsPSBT` when the
embit SP package is importable, else falls back to vanilla `PSBT`:

```python
def get_psbt_cls():
    try:
        from embit.silent_payments import SilentPaymentsPSBT
        return SilentPaymentsPSBT
    except ImportError:
        from embit.psbt import PSBT
        return PSBT
```

Every site that constructs or parses a PSBT imports the class from this one place. This
replaces the stray `_SP_AVAILABLE` flag in `psbt_parser.py` with a single source of truth,
is trivially mockable in tests, and matches SeedSigner's `helpers/` convention.

Rejected alternative (Approach A): direct `SilentPaymentsPSBT` substitution with a
`try/except` guard repeated at each call site. Simpler per-site, but scatters the
availability logic across `decode_qr`, `psbt_parser`, `encode_qr`, and `controller`.

## Detailed changes

### `requirements.txt`
- `embit==0.8.0` / `notTanveer/embit@god` → `embit @ git+https://github.com/diybitcoinhardware/embit.git@36e60e41f7cf7e4ea24efd2e379e337b1f0a1db9`.

### `helpers/embit_utils.py`
- Add `get_psbt_cls()` resolver (above).
- Keep the existing SP derivation path branch in `get_standard_derivation_path()`.

### `models/decode_qr.py`
- `get_psbt()` and the validation parses (`is_*` checks at lines ~462, ~472) use
  `get_psbt_cls().parse(...)` instead of `psbt.PSBT.parse(...)`.
- Keep the `sp1`/`tsp1` address regex addition as-is.

### `models/psbt_parser.py`
- Remove the local `_SP_AVAILABLE` try/except and the unused
  `decode_silent_payment_address` import.
- **Delete `sign_sp()`** entirely.
- Keep `has_sp_outputs` and the SP branch in `_parse_outputs()` (these now fire because the
  PSBT is parsed as `SilentPaymentsPSBT`). Gate `has_sp_outputs` on
  `getattr(out, "sp_data", None)` so it is safe when SP is unavailable.
- Keep `_get_sp_address()` (manual bech32m encode of `sp_data.scan_key` + `sp_data.spend_key`).
- **Fix `trim()`:** construct the trimmed PSBT via `get_psbt_cls()`. Preserve the fields a
  BIP-375 coordinator needs back: per-input `sp_ecdh_shares` / `sp_dleq_proofs`, and output
  `sp_data` / `sp_label`. Do **not** attempt to derive or fill output scripts.

### `views/psbt_views.py` — `PSBTFinalizeView.run()`
- Remove the `if psbt_parser.has_sp_outputs:` branch and the `import os` / `os.urandom(32)`
  / `aux_rand` plumbing.
- Restore a single signing path: `psbt.sign_with(psbt_parser.root)` then `trim()`. Because
  `psbt` is now a `SilentPaymentsPSBT`, `sign_with()` transparently handles both regular and
  SP signing.
- Wrap the sign call so `SPValidationError` (ineligible SP inputs, non-SIGHASH_ALL) routes
  to the existing `PSBTSigningErrorView` rather than crashing. The existing
  "sig count unchanged → error" check is retained.

### `models/seed.py`
- **Delete the unused `get_sp_keys`** convenience method.
- Keep `_build_bip352_path`, the scan/spend derivation methods,
  `generate_bip352_silent_payment_address`, and `get_sp_address` (these are correct against
  `feat/sp-phase2`).

### `models/settings_definition.py`
- Remove `OPTION__ENABLED_WITH_LABELS` and `OPTIONS__SILENT_PAYMENTS`.
- Change the `SETTING__SILENT_PAYMENTS` entry to the standard feature-flag toggle:
  `type=SettingsConstants.TYPE__ENABLED_DISABLED` (which auto-populates
  `OPTIONS__ENABLED_DISABLED` via `SettingsEntry.__post_init__`), drop the explicit
  `selection_options`, keep `default_value=OPTION__DISABLED` and advanced visibility.
- Keep `SILENT_PAYMENT = "sp"` policy-type constant.

### `views/seed_views.py`
- Update `_sp_enabled()` to the simple enabled/disabled check.
- Keep `SeedExportXpubSigTypeView` SP option routing and `SeedSPAddressExportView`.

## Testing

- **`tests/test_silent_payments.py`** (new) or extensions to existing suites:
  - SP key + address derivation for mainnet/testnet (`Seed.get_sp_address`, BIP-352 path).
  - `has_sp_outputs` + SP-output classification (`destination_addresses`,
    `destination_amounts`) against a real SP PSBT fixture.
  - End-to-end: parse SP PSBT as `SilentPaymentsPSBT`, `sign_with(root)` produces per-input
    ECDH shares + DLEQ proofs + a partial sig. Adapt embit's BIP-375 vectors /
    `test_psbt_signer_sp.py`.
  - `trim()` round-trip: SP fields preserved and the trimmed PSBT re-serializes/re-parses.
  - Error path: an SP PSBT with an ineligible input surfaces as `PSBTSigningErrorView`.
- **`get_psbt_cls()`** resolver test (returns SP class when available; vanilla on
  ImportError, e.g. via mock).
- **Flow test** for the SP finalize path through `PSBTFinalizeView`.
- **Regression:** run the full suite; confirm non-SP v0 and v2 flows are unchanged.

## Compatibility concerns and edge cases

- **PSBTv2:** SP PSBTs are v2. `feat/sp-phase2`'s base `PSBT` parses both v0 and v2;
  UR/bytes transport is opaque, so QR encode/decode is unaffected. Include an explicit
  "v0 still signs" regression test.
- **Mixed SP + regular change:** one PSBT may have SP destination outputs plus a normal
  P2WPKH change output. SP outputs are classified as destinations (never change); regular
  change still flows through the existing change-detection logic.
- **Ineligible inputs:** multisig, taproot-NUMS, segwit > v1, or non-SIGHASH_ALL inputs in
  an SP PSBT are rejected by embit (`SPValidationError`); we surface the error view.
- **Output scripts intentionally not derived:** SeedSigner returns the PSBT with empty SP
  output `script_pubkey` (plus `sp_data`, shares, proofs, partial sigs). The coordinator
  (e.g. Sparrow) derives final output scripts. Validate this assumption during Sparrow
  interop before release.
- **No feature loss from leaving `god`:** SeedSigner never imported `god`'s BIP-392
  descriptor or BIP-376 spend code; `feat/sp-phase2` ships equivalents anyway.
- **Entropy:** rely on embit's internal `misc.urandom` (RPi hardware RNG). Do not pass
  `aux_rand` from SeedSigner.

## Out of scope (deferred)

- SP indicator/labeling in `PSBTAddressDetailsView` (PSBT review).
- Address-explorer SP mode.
- On-device SP address verification (direct compare, no brute-force).
- On-device label-selection UI (and the corresponding "Enabled with labels" setting).
