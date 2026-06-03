# Silent Payments → embit `feat/sp-phase2` Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate SeedSigner's Silent Payments (BIP-352/375) support from the personal `notTanveer/embit@god` fork to the official `diybitcoinhardware/embit@feat/sp-phase2` branch, make the SP signing path actually functional (it is dead code today), remove obsolete code, formalize the "Single-Sig SP" receive policy type, and add tests.

**Architecture:** Parse all PSBTs with embit's `SilentPaymentsPSBT` (a drop-in superset of `PSBT`) via a single `get_psbt_cls()` resolver, so SP fields survive parse → sign → serialize. `SilentPaymentsPSBT.sign_with(root)` self-detects SP outputs and handles ECDH/DLEQ internally, so the SP-specific `sign_sp()` orchestration is deleted. `trim()` returns the signed v2 PSBT unchanged when SP outputs are present (SP fields only serialize for v2).

**Tech Stack:** Python 3, embit (`feat/sp-phase2`), pytest, SeedSigner MVC (`models/`, `views/`, `helpers/`), FlowTest harness.

**Spec:** `docs/superpowers/specs/2026-06-03-silent-payments-embit-migration-design.md`

**Conventions used below:**
- Run tests from the repo root `/home/sahil/dev/seedsigner` with the editable `seedsigner` + `embit` installs active.
- The shared test seeds come from `tests/psbt_testing_util.py`:
  - sender: `Seed("model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast".split())`
  - recipient: `Seed("shove album flame dad equal cook spike cheap hollow exit great forest".split())`

---

### Task 1: Switch the embit dependency to `feat/sp-phase2` (pinned)

**Files:**
- Modify: `requirements.txt:1`
- External: `/home/sahil/dev/embit` (editable install checkout)

- [ ] **Step 1: Point the local editable embit at the pinned commit**

The editable install at `/home/sahil/dev/embit` is currently on `perf-sp`. Move it to the pinned `feat/sp-phase2` tip so tests run against production code:

```bash
cd /home/sahil/dev/embit
git fetch upstream feat/sp-phase2
git checkout 36e60e41f7cf7e4ea24efd2e379e337b1f0a1db9
pip install -e .
cd /home/sahil/dev/seedsigner
```

Expected: `git checkout` reports "HEAD is now at 36e60e4 feat: P2TR input support for silent payments send"; `pip install -e .` succeeds.

- [ ] **Step 2: Verify the SP API is importable**

Run:
```bash
python3 -c "from embit.silent_payments import SilentPaymentsPSBT, SilentPaymentData, SPValidationError; from embit.silent_payments.bip352 import generate_silent_payment_address; print('SP API OK')"
```
Expected: prints `SP API OK` with no ImportError.

- [ ] **Step 3: Update `requirements.txt`**

Replace line 1.

Current:
```
embit @ git+https://github.com/notTanveer/embit.git@god
```
New:
```
embit @ git+https://github.com/diybitcoinhardware/embit.git@36e60e41f7cf7e4ea24efd2e379e337b1f0a1db9
```

- [ ] **Step 4: Capture the test baseline**

Run:
```bash
pytest -q 2>&1 | tail -20
```
Expected: the suite runs to completion. Record the pass/fail counts as the baseline (per project memory there are some pre-existing failures unrelated to SP). Subsequent tasks must not introduce *new* failures.

- [ ] **Step 5: Commit**

```bash
git add requirements.txt
git commit -m "deps: pin embit to diybitcoinhardware feat/sp-phase2 (SP support)"
```

---

### Task 2: Add the `get_psbt_cls()` resolver

**Files:**
- Modify: `src/seedsigner/helpers/embit_utils.py` (add function after the module docstring, before `get_standard_derivation_path`)
- Create: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_silent_payments.py`:

```python
# Make GPIO/display/camera-dependent imports safe on non-Raspi (see tests/base.py)
from base import BaseTest

from seedsigner.helpers.embit_utils import get_psbt_cls


class TestGetPsbtCls(BaseTest):
    def test_returns_silent_payments_psbt_when_available(self):
        from embit.silent_payments import SilentPaymentsPSBT
        assert get_psbt_cls() is SilentPaymentsPSBT
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_silent_payments.py::TestGetPsbtCls::test_returns_silent_payments_psbt_when_available -v`
Expected: FAIL with `ImportError: cannot import name 'get_psbt_cls'`.

- [ ] **Step 3: Implement `get_psbt_cls()`**

In `src/seedsigner/helpers/embit_utils.py`, insert immediately after the closing `"""` of the module docstring block (after line 19, before the `# TODO: Refactor` comment / `get_standard_derivation_path`):

```python
def get_psbt_cls():
    """Return the PSBT class to use for parsing and constructing PSBTs.

    Prefers the SP-aware `SilentPaymentsPSBT` — a drop-in superset of embit's
    `PSBT` — so BIP-352 Silent Payment fields survive parse -> sign -> serialize.
    Falls back to vanilla `PSBT` if the installed embit lacks `silent_payments`.
    """
    try:
        from embit.silent_payments import SilentPaymentsPSBT
        return SilentPaymentsPSBT
    except ImportError:
        from embit.psbt import PSBT
        return PSBT
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_silent_payments.py::TestGetPsbtCls::test_returns_silent_payments_psbt_when_available -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/helpers/embit_utils.py tests/test_silent_payments.py
git commit -m "feat: add get_psbt_cls() resolver for SP-aware PSBT parsing"
```

---

### Task 3: Route `decode_qr` PSBT parsing through `get_psbt_cls()`

**Files:**
- Modify: `src/seedsigner/models/decode_qr.py:153`, `:462`, `:472` (and add an import)
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

This test builds an SP PSBT, serializes it, and asserts that parsing through the decode path yields outputs carrying `sp_data`. Add a shared fixture helper plus the test to `tests/test_silent_payments.py`:

```python
from binascii import b2a_base64

from embit import bip32
from embit.networks import NETWORKS
from embit.psbt import DerivationPath
from embit.script import Script, p2wpkh
from embit.transaction import TransactionOutput

from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants


SENDER_SEED = Seed("model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast".split())
RECIPIENT_SEED = Seed("shove album flame dad equal cook spike cheap hollow exit great forest".split())


def _root(seed, network):
    embit_network = SettingsConstants.map_network_to_embit(network)
    return bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS[embit_network]["xprv"])


def build_sp_psbt(sender_seed=SENDER_SEED, recipient_seed=RECIPIENT_SEED,
                  network=SettingsConstants.REGTEST, value=100_000, fee=1_000):
    """Build a minimal PSBTv2: one P2WPKH input controlled by `sender_seed`,
    one Silent Payment output to `recipient_seed`."""
    from embit.silent_payments import SilentPaymentsPSBT, SilentPaymentData
    from embit.silent_payments.psbt import SPInputScope, SPOutputScope

    root = _root(sender_seed, network)
    child = root.derive([0, 0])
    pub = child.get_public_key()

    psbt = SilentPaymentsPSBT.create_v2()

    inp = SPInputScope()
    inp.txid = bytes([0xAA] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=value, script_pubkey=p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    scan_pub = recipient_seed.derive_bip352_scan_privkey(network=network).get_public_key()
    spend_pub = recipient_seed.derive_bip352_spend_privkey(network=network).get_public_key()

    out = SPOutputScope()
    out.value = value - fee
    # Dummy 34-byte P2TR placeholder so `.tx` reconstruction works; the real SP
    # output script is derived by the coordinator, not the signer.
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    psbt.tx_modifiable_flags = 0
    return psbt


class TestDecodeSpPsbt(BaseTest):
    def test_decoded_sp_psbt_retains_sp_data(self):
        from embit.silent_payments import SilentPaymentsPSBT

        raw = build_sp_psbt().serialize()
        parsed = get_psbt_cls().parse(raw)

        assert isinstance(parsed, SilentPaymentsPSBT)
        assert any(getattr(out, "sp_data", None) is not None for out in parsed.outputs)
```

- [ ] **Step 2: Run test to verify it fails**

This test does not yet depend on the `decode_qr` change (it parses directly), so it should PASS once the fixture is correct. Run it to confirm the fixture round-trips before changing `decode_qr`:

Run: `pytest tests/test_silent_payments.py::TestDecodeSpPsbt::test_decoded_sp_psbt_retains_sp_data -v`
Expected: PASS. (If it fails, fix the fixture before proceeding — do not change `decode_qr` to chase a fixture bug.)

- [ ] **Step 3: Update `decode_qr.py` to parse via `get_psbt_cls()`**

Add the import near the other `seedsigner` imports at the top of `src/seedsigner/models/decode_qr.py` (after line 20, `from seedsigner.models.settings import SettingsConstants`):

```python
from seedsigner.helpers.embit_utils import get_psbt_cls
```

Replace the three parse call sites:

`decode_qr.py:153` — in `get_psbt()`:
```python
                    return get_psbt_cls().parse(data)
```

`decode_qr.py:462` — in `is_base64_psbt()`:
```python
                get_psbt_cls().parse(a2b_base64(s))
```

`decode_qr.py:472` — in `is_base43_psbt()`:
```python
            get_psbt_cls().parse(DecodeQR.base43_decode(s))
```

- [ ] **Step 4: Run tests to verify decode still works (SP + non-SP)**

Run: `pytest tests/test_silent_payments.py tests/test_decode_qr.py -q`
Expected: PASS (SP fixture parses; existing decode_qr tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/models/decode_qr.py tests/test_silent_payments.py
git commit -m "feat: parse PSBTs via SP-aware get_psbt_cls() in decode_qr"
```

---

### Task 4: Clean up `PSBTParser` read-side (remove `_SP_AVAILABLE`, fix imports) + SP parsing test

**Files:**
- Modify: `src/seedsigner/models/psbt_parser.py:11-15`, `:74-88`, `:147`
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_silent_payments.py`:

```python
class TestPsbtParserSpReadSide(BaseTest):
    def test_has_sp_outputs_and_destination_address(self):
        from seedsigner.models.psbt_parser import PSBTParser

        network = SettingsConstants.REGTEST
        psbt = build_sp_psbt(network=network)

        parser = PSBTParser(p=psbt, seed=SENDER_SEED, network=network)

        assert parser.has_sp_outputs is True
        assert parser.num_destinations == 1
        # The parsed destination must equal the recipient's BIP-352 SP address.
        assert parser.destination_addresses[0] == RECIPIENT_SEED.get_sp_address(network=network)
        assert parser.destination_amounts[0] == 99_000
        assert parser.spend_amount == 99_000
```

- [ ] **Step 2: Run test to verify current state**

Run: `pytest tests/test_silent_payments.py::TestPsbtParserSpReadSide::test_has_sp_outputs_and_destination_address -v`
Expected: PASS already (the read-side SP branch works once the PSBT is SP-typed). If it fails, the fixture/parse wiring is wrong — fix before the cleanup. This test guards that the cleanup in Step 3 does not regress behavior.

- [ ] **Step 3: Remove `_SP_AVAILABLE` and the unused bip352 import**

In `src/seedsigner/models/psbt_parser.py`:

(a) Delete the try/except block at lines 11-15:
```python
try:
    from embit.silent_payments.psbt import SPOutputScope
    _SP_AVAILABLE = True
except ImportError:
    _SP_AVAILABLE = False
```

(b) Simplify `has_sp_outputs` (lines 74-78) to:
```python
    @property
    def has_sp_outputs(self) -> bool:
        return any(getattr(out, "sp_data", None) is not None for out in self.psbt.outputs)
```

(c) In `_get_sp_address` (lines 81-88), delete the unused import line
`from embit.silent_payments.bip352 import generate_silent_payment_address, decode_silent_payment_address`
(neither name is used — the function bech32m-encodes directly). Result:
```python
    def _get_sp_address(self, out) -> str:
        from embit import bech32
        sp_data = out.sp_data
        payload = sp_data.scan_key.sec() + sp_data.spend_key.sec()
        data = bech32.convertbits(payload, 8, 5)
        hrp = "sp" if self.network == SettingsConstants.MAINNET else "tsp"
        return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [0] + data)
```

(d) In `_parse_outputs`, change the SP guard at line 147 from
`if _SP_AVAILABLE and getattr(out, "sp_data", None) is not None:` to:
```python
            if getattr(out, "sp_data", None) is not None:
```

- [ ] **Step 4: Run test to verify it still passes**

Run: `pytest tests/test_silent_payments.py::TestPsbtParserSpReadSide -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/models/psbt_parser.py tests/test_silent_payments.py
git commit -m "refactor: drop _SP_AVAILABLE flag and unused SP imports in PSBTParser"
```

---

### Task 5: Delete `sign_sp()`, fix `trim()` for v2/SP, + sign/trim test

**Files:**
- Modify: `src/seedsigner/models/psbt_parser.py:261-314`
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_silent_payments.py`:

```python
class TestPsbtParserSpSignAndTrim(BaseTest):
    def _root_for(self, seed, network):
        return _root(seed, network)

    def test_sign_with_populates_sp_fields_and_sig(self):
        from seedsigner.models.psbt_parser import PSBTParser

        network = SettingsConstants.REGTEST
        psbt = build_sp_psbt(network=network)
        root = self._root_for(SENDER_SEED, network)

        before = PSBTParser.sig_count(psbt)
        psbt.sign_with(root)
        after = PSBTParser.sig_count(psbt)

        # A partial signature was added to the P2WPKH input.
        assert after > before
        # Per-input ECDH share + DLEQ proof were populated for the SP output.
        assert len(psbt.inputs[0].sp_ecdh_shares) == 1
        assert len(psbt.inputs[0].sp_dleq_proofs) == 1

    def test_trim_preserves_sp_fields_and_reparses(self):
        from seedsigner.models.psbt_parser import PSBTParser
        from embit.silent_payments import SilentPaymentsPSBT

        network = SettingsConstants.REGTEST
        psbt = build_sp_psbt(network=network)
        root = self._root_for(SENDER_SEED, network)
        psbt.sign_with(root)

        trimmed = PSBTParser.trim(psbt)
        reparsed = SilentPaymentsPSBT.parse(trimmed.serialize())

        # v2 + SP fields survive the trim/serialize round-trip.
        assert reparsed.version == 2
        assert any(getattr(out, "sp_data", None) is not None for out in reparsed.outputs)
        assert len(reparsed.inputs[0].sp_ecdh_shares) == 1
        assert PSBTParser.sig_count(reparsed) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_silent_payments.py::TestPsbtParserSpSignAndTrim -v`
Expected: `test_sign_with_...` PASSES (embit handles it), but `test_trim_preserves_...` FAILS — the current `trim()` rebuilds a v0 PSBT and drops SP fields (`reparsed.version` is `None`, not `2`).

- [ ] **Step 3: Delete `sign_sp()` and rewrite `trim()`**

In `src/seedsigner/models/psbt_parser.py`:

(a) Delete the entire `sign_sp` method (lines 261-284 — from `def sign_sp(self, aux_rand: bytes = None):` through the end of that method, including its docstring and body).

(b) Replace the entire `trim` method (lines 287-314) with:

```python
    @staticmethod
    def trim(tx):
        # Silent Payment (BIP-375) PSBTs are version 2 and carry per-input ECDH shares /
        # DLEQ proofs plus output sp_data. The standard rebuild-from-tx trim below produces
        # a v0 PSBT, and SP fields only serialize for v2 — so it would silently drop them.
        # Return the signed PSBT intact for SP; size-optimized SP trimming is deferred.
        if any(getattr(out, "sp_data", None) is not None for out in tx.outputs):
            return tx

        trimmed_psbt = psbt.PSBT(tx.tx)
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness:
                # Taproot sign; trim to only final_scriptwitness
                # From BIP-371 and BIP-174, once final script witness is populated
                # it contains all necessary signatures
                trimmed_psbt.inputs[i].final_scriptwitness = inp.final_scriptwitness
            else:
                trimmed_psbt.inputs[i].partial_sigs = inp.partial_sigs

        return trimmed_psbt
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_silent_payments.py::TestPsbtParserSpSignAndTrim -v`
Expected: both PASS.

Also confirm non-SP trim is unchanged:
Run: `pytest tests/test_psbt_parser.py -q`
Expected: PASS (no new failures vs Task 1 baseline).

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/models/psbt_parser.py tests/test_silent_payments.py
git commit -m "refactor: delete dead sign_sp(); make trim() preserve v2 SP PSBTs"
```

---

### Task 6: Simplify `PSBTFinalizeView` (single sign path + error handling)

**Files:**
- Modify: `src/seedsigner/views/psbt_views.py:1` (add logger), `:540-561`
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

This test drives the finalize sign path directly (no full flow) for an SP PSBT, asserting the controller ends up with a signed, SP-preserving PSBT. Add to `tests/test_silent_payments.py`:

```python
class TestFinalizeViewSpSigning(BaseTest):
    def test_finalize_signs_sp_psbt(self):
        from unittest.mock import patch
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.views.psbt_views import PSBTFinalizeView, PSBTSignedQRDisplayView

        # BaseTest.setup_method() already configured self.controller (the singleton).
        network = SettingsConstants.REGTEST
        psbt = build_sp_psbt(network=network)
        self.controller.psbt = psbt
        self.controller.psbt_parser = PSBTParser(p=psbt, seed=SENDER_SEED, network=network)
        self.controller.psbt_seed = SENDER_SEED

        # Simulate the user pressing "Approve" (button index 0, not BACK).
        with patch.object(PSBTFinalizeView, "run_screen", return_value=0):
            dest = PSBTFinalizeView().run()

        assert dest.View_cls is PSBTSignedQRDisplayView
        # Controller now holds a signed, SP-preserving PSBT.
        assert PSBTParser.sig_count(self.controller.psbt) >= 1
        assert any(getattr(out, "sp_data", None) is not None for out in self.controller.psbt.outputs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_silent_payments.py::TestFinalizeViewSpSigning -v`
Expected: FAIL — current `PSBTFinalizeView.run()` calls `psbt_parser.sign_sp(...)` (now deleted in Task 5), raising `AttributeError`.

- [ ] **Step 3: Add a module logger and simplify the signing branch**

In `src/seedsigner/views/psbt_views.py`, add at the very top of the file (line 1, before `from gettext import gettext as _`):

```python
import logging
```

And immediately after the existing imports block (after `from seedsigner.views.view import ...` on line 7), add:

```python
logger = logging.getLogger(__name__)
```

Then replace the `else:` signing block in `PSBTFinalizeView.run()` (lines 540-561) with:

```python
        else:
            # Sign PSBT. `psbt` is a SilentPaymentsPSBT (a PSBT superset), so sign_with()
            # transparently handles both standard and Silent Payment signing — for SP it
            # also populates per-input ECDH shares + DLEQ proofs (entropy via embit's
            # internal urandom).
            sig_cnt = PSBTParser.sig_count(psbt)

            try:
                psbt.sign_with(psbt_parser.root)
            except Exception as e:
                # e.g. embit SPValidationError for ineligible SP inputs (multisig,
                # non-SIGHASH_ALL). Surface as the standard signing-error screen.
                logger.error(f"PSBT signing failed: {repr(e)}")
                return Destination(PSBTSigningErrorView)

            trimmed_psbt = PSBTParser.trim(psbt)

            if sig_cnt == PSBTParser.sig_count(trimmed_psbt):
                # Signing failed / didn't do anything
                # TODO: Reserved for Nick. Are there different failure scenarios that we can detect?
                # Would be nice to alter the message on the next screen w/more detail.
                return Destination(PSBTSigningErrorView)

            else:
                self.controller.psbt = trimmed_psbt
                return Destination(PSBTSignedQRDisplayView)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_silent_payments.py::TestFinalizeViewSpSigning -v`
Expected: PASS.

Also run the existing PSBT flow tests to confirm standard signing is unaffected:
Run: `pytest tests/test_flows_psbt.py -q`
Expected: PASS (no new failures vs baseline).

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/views/psbt_views.py tests/test_silent_payments.py
git commit -m "refactor: single sign_with() path in PSBTFinalizeView with SP error handling"
```

---

### Task 7: Remove the dead `Seed.get_sp_keys` helper

**Files:**
- Modify: `src/seedsigner/models/seed.py:205-209`
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the test (guards address derivation, the kept behavior)**

Add to `tests/test_silent_payments.py`:

```python
class TestSeedSpDerivation(BaseTest):
    def test_get_sp_address_mainnet_and_regtest(self):
        addr_main = SENDER_SEED.get_sp_address(network=SettingsConstants.MAINNET)
        addr_regtest = SENDER_SEED.get_sp_address(network=SettingsConstants.REGTEST)
        assert addr_main.startswith("sp1")
        assert addr_regtest.startswith("tsp1")

    def test_get_sp_keys_is_removed(self):
        assert not hasattr(SENDER_SEED, "get_sp_keys")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_silent_payments.py::TestSeedSpDerivation -v`
Expected: `test_get_sp_address_...` PASSES; `test_get_sp_keys_is_removed` FAILS (method still present).

- [ ] **Step 3: Delete `get_sp_keys`**

In `src/seedsigner/models/seed.py`, delete lines 205-209 (the comment + method):

```python
    # Convenience aliases used by PSBTParser
    def get_sp_keys(self, network: str = SettingsConstants.MAINNET):
        scan_privkey = self.derive_bip352_scan_privkey(network=network)
        spend_pubkey = self.derive_bip352_spend_privkey(network=network).get_public_key()
        return scan_privkey, spend_pubkey
```

Leave `get_sp_address` (lines 212-213) and all `derive_bip352_*` / `generate_bip352_*` methods intact.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_silent_payments.py::TestSeedSpDerivation -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/models/seed.py tests/test_silent_payments.py
git commit -m "refactor: remove unused Seed.get_sp_keys helper"
```

---

### Task 8: Collapse the SP setting to a plain Enabled/Disabled toggle

**Files:**
- Modify: `src/seedsigner/models/settings_definition.py:16`, `:300-306`, `:689-697`
- Modify: `tests/test_silent_payments.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_silent_payments.py`:

```python
class TestSilentPaymentsSetting(BaseTest):
    def test_sp_setting_is_enabled_disabled_toggle(self):
        from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition

        entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__SILENT_PAYMENTS)
        assert entry.type == SettingsConstants.TYPE__ENABLED_DISABLED
        assert entry.selection_options == SettingsConstants.OPTIONS__ENABLED_DISABLED
        assert entry.default_value == SettingsConstants.OPTION__DISABLED

    def test_enabled_with_labels_option_removed(self):
        from seedsigner.models.settings_definition import SettingsConstants

        assert not hasattr(SettingsConstants, "OPTION__ENABLED_WITH_LABELS")
        assert not hasattr(SettingsConstants, "OPTIONS__SILENT_PAYMENTS")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_silent_payments.py::TestSilentPaymentsSetting -v`
Expected: FAIL (setting is currently `TYPE__SELECT_1`; the removed constants still exist).

- [ ] **Step 3: Remove the SP-specific options and switch the entry to the standard toggle**

In `src/seedsigner/models/settings_definition.py`:

(a) Delete line 16:
```python
    OPTION__ENABLED_WITH_LABELS = "L"
```

(b) Delete the `OPTIONS__SILENT_PAYMENTS` block (lines 300-306), keeping the `SILENT_PAYMENT` constant:
```python
    # Silent Payments is a separate policy type, not a script type
    SILENT_PAYMENT = "sp"
    OPTIONS__SILENT_PAYMENTS = [
        (OPTION__ENABLED, _mft("Enabled")),
        (OPTION__ENABLED_WITH_LABELS, _mft("Enabled with labels")),
        (OPTION__DISABLED, _mft("Disabled")),
    ]
```
becomes:
```python
    # Silent Payments is a separate policy type, not a script type
    SILENT_PAYMENT = "sp"
```

(c) Replace the `SETTING__SILENT_PAYMENTS` `SettingsEntry` (lines 689-697) with the standard feature-flag form (drop the explicit `type`/`selection_options`; `__post_init__` fills `OPTIONS__ENABLED_DISABLED` for the default `TYPE__ENABLED_DISABLED`):

```python
        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SILENT_PAYMENTS,
                      abbreviated_name="sp",
                      display_name=_mft("Silent Payments"),
                      help_text=_mft("BIP-352 Silent Payments"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_silent_payments.py::TestSilentPaymentsSetting -v`
Expected: PASS.

Also run the settings-definition suite to confirm no schema breakage:
Run: `pytest tests/test_settings_definition.py -q`
Expected: PASS (no new failures vs baseline).

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/models/settings_definition.py tests/test_silent_payments.py
git commit -m "refactor: collapse Silent Payments setting to Enabled/Disabled toggle"
```

---

### Task 9: Rename to "Single-Sig SP" and add the receive-flow test

**Files:**
- Modify: `src/seedsigner/views/seed_views.py:667`, `:670-672`
- Modify: `tests/test_flows_seed.py`

- [ ] **Step 1: Write the failing tests**

Add both to `tests/test_flows_seed.py` (inside `class TestSeedFlows(FlowTest)`). All needed names (`FlowStep`, `Seed`, `SettingsConstants`) are already imported at the top of that file.

```python
    def test_sp_export_button_label_is_single_sig_sp(self):
        from seedsigner.views.seed_views import SeedExportXpubSigTypeView
        assert SeedExportXpubSigTypeView.SILENT_PAYMENT.button_label == "Single-Sig SP"

    def test_single_sig_sp_export_flow(self):
        """With Silent Payments enabled, the export flow offers 'Single-Sig SP'
        and routes straight to the SP address export (no script-type screen).

        Note: `view_args` for the first View are passed via
        `run_sequence(initial_destination_view_args=...)`; `FlowStep` itself has
        no `view_args` parameter."""
        from seedsigner.views.seed_views import SeedExportXpubSigTypeView, SeedSPAddressExportView

        mnemonic = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()
        self.controller.storage.set_pending_seed(Seed(mnemonic=mnemonic))
        self.controller.storage.finalize_pending_seed()

        # Enable single-sig + Silent Payments so both buttons show (no auto-skip).
        self.settings.set_value(SettingsConstants.SETTING__SIG_TYPES, [SettingsConstants.SINGLE_SIG])
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(
            sequence=[
                FlowStep(SeedExportXpubSigTypeView,
                         button_data_selection=SeedExportXpubSigTypeView.SILENT_PAYMENT),
                FlowStep(SeedSPAddressExportView),
            ],
            initial_destination_view_args={"seed_num": 0},
        )
```

- [ ] **Step 2: Run tests to verify the label test fails**

Run: `pytest "tests/test_flows_seed.py::TestSeedFlows::test_sp_export_button_label_is_single_sig_sp" "tests/test_flows_seed.py::TestSeedFlows::test_single_sig_sp_export_flow" -v`
Expected: `test_sp_export_button_label_is_single_sig_sp` FAILS (current label is "Silent Payment"); `test_single_sig_sp_export_flow` PASSES (routing already works via the `SILENT_PAYMENT` attribute). The label test is the red→green guard for the rename.

- [ ] **Step 3: Rename the button label to "Single-Sig SP"**

In `src/seedsigner/views/seed_views.py:667`, change:
```python
    SILENT_PAYMENT = ButtonOption("Silent Payment", return_data=SettingsConstants.SILENT_PAYMENT)
```
to:
```python
    SILENT_PAYMENT = ButtonOption("Single-Sig SP", return_data=SettingsConstants.SILENT_PAYMENT)
```

Confirm `_sp_enabled()` (lines 670-672) already reads correctly against the simplified toggle (it checks `!= OPTION__DISABLED`, which is correct for Enabled/Disabled):
```python
    def _sp_enabled(self) -> bool:
        return self.settings.get_value(SettingsConstants.SETTING__SILENT_PAYMENTS) != SettingsConstants.OPTION__DISABLED
```
No change needed there.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest "tests/test_flows_seed.py::TestSeedFlows::test_sp_export_button_label_is_single_sig_sp" "tests/test_flows_seed.py::TestSeedFlows::test_single_sig_sp_export_flow" -v`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/seedsigner/views/seed_views.py tests/test_flows_seed.py
git commit -m "feat: rename SP policy option to 'Single-Sig SP' + receive-flow test"
```

---

### Task 10: Full regression, update memory, final verification

**Files:**
- Modify: `/home/sahil/.claude/projects/-home-sahil-dev-seedsigner/memory/project_sp_integration.md` and `MEMORY.md` (project memory; not committed to the repo)

- [ ] **Step 1: Run the full test suite**

Run:
```bash
pytest -q 2>&1 | tail -25
```
Expected: no *new* failures compared to the Task 1 baseline; all new `tests/test_silent_payments.py` and the `test_single_sig_sp_export_flow` test pass.

- [ ] **Step 2: Grep for leftover references to removed symbols**

Run:
```bash
grep -rnE "sign_sp|_SP_AVAILABLE|get_sp_keys|OPTION__ENABLED_WITH_LABELS|OPTIONS__SILENT_PAYMENTS|populate_silent_payment_send_data" src/ tests/
```
Expected: no matches (all removed). If any remain, fix them and re-run Step 1.

- [ ] **Step 3: Update project memory**

Update `/home/sahil/.claude/projects/-home-sahil-dev-seedsigner/memory/project_sp_integration.md` to record: migrated from `notTanveer/embit@god` to `diybitcoinhardware/embit@feat/sp-phase2` (pin `36e60e4`); SP PSBTs now parsed via `get_psbt_cls()` → `SilentPaymentsPSBT`; signing is a single `sign_with()`; `sign_sp()` deleted; `trim()` returns signed v2 PSBT for SP; setting collapsed to Enabled/Disabled; export option renamed "Single-Sig SP". Keep the `MEMORY.md` one-line pointer accurate.

- [ ] **Step 4: Final commit (if any tracked files changed in Steps 1-2 cleanup)**

```bash
git add -A
git commit -m "test: full SP migration regression pass" --allow-empty
```

- [ ] **Step 5: Sparrow interop note (manual, pre-release)**

Not automatable here: before release, verify end-to-end with Sparrow on signet/testnet — construct an SP send, scan into SeedSigner, sign, scan back, and confirm Sparrow accepts the returned ECDH shares + DLEQ proofs and derives the final SP output scripts (SeedSigner intentionally does not derive them). Record the result in the spec's compatibility section.

---

## Self-Review

**Spec coverage:**
- Dependency pin + local checkout → Task 1.
- `get_psbt_cls()` resolver (Approach B) → Task 2.
- decode_qr parses via resolver → Task 3.
- `_SP_AVAILABLE` removal, unused-import cleanup, `has_sp_outputs`/`_parse_outputs` kept → Task 4.
- Delete `sign_sp()`, fix `trim()` (v2 preservation) → Task 5.
- `PSBTFinalizeView` single-sign path + error handling → Task 6.
- Delete `Seed.get_sp_keys` → Task 7.
- Collapse SP setting to Enabled/Disabled → Task 8.
- "Single-Sig SP" rename + receive flow → Task 9.
- Tests (derivation, parse, sign, trim, resolver, finalize, flow) distributed across Tasks 2-9; regression → Task 10.
- Send-from-any-policy: no code change required (documented in spec); exercised implicitly by the P2WPKH-input SP fixture which is "any single-sig policy paying an SP recipient."

**Deferred / out of scope (per spec):** PSBT-review SP indicator, Address Explorer SP mode, on-device SP address verification, label UI. No tasks — intentional.

**Placeholder scan:** No TBD/TODO-as-work, no "add error handling" hand-waving — every code step shows complete code. (The retained `# TODO: Reserved for Nick` comment is pre-existing source, not a plan placeholder.)

**Type/name consistency:** `get_psbt_cls()`, `build_sp_psbt()`, `SENDER_SEED`/`RECIPIENT_SEED`, `has_sp_outputs`, `PSBTParser.trim`, `PSBTSigningErrorView`, `SeedSPAddressExportView`, `SeedExportXpubSigTypeView.SILENT_PAYMENT` are used consistently across tasks. Test classes live in `tests/test_silent_payments.py` except the flow test (in `tests/test_flows_seed.py`, matching the existing seed-flow suite).
