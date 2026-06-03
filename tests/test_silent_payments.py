# Make GPIO/display/camera-dependent imports safe on non-Raspi (see tests/base.py)
from base import BaseTest

from seedsigner.helpers.embit_utils import get_psbt_cls

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


class TestGetPsbtCls(BaseTest):
    def test_returns_silent_payments_psbt_when_available(self):
        from embit.silent_payments import SilentPaymentsPSBT
        assert get_psbt_cls() is SilentPaymentsPSBT


class TestDecodeSpPsbt(BaseTest):
    def test_decoded_sp_psbt_retains_sp_data(self):
        from embit.silent_payments import SilentPaymentsPSBT

        raw = build_sp_psbt().serialize()
        parsed = get_psbt_cls().parse(raw)

        assert isinstance(parsed, SilentPaymentsPSBT)
        assert any(getattr(out, "sp_data", None) is not None for out in parsed.outputs)


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


class TestSeedSpDerivation(BaseTest):
    def test_get_sp_address_mainnet_and_regtest(self):
        addr_main = SENDER_SEED.get_sp_address(network=SettingsConstants.MAINNET)
        addr_regtest = SENDER_SEED.get_sp_address(network=SettingsConstants.REGTEST)
        assert addr_main.startswith("sp1")
        assert addr_regtest.startswith("tsp1")

    def test_get_sp_keys_is_removed(self):
        assert not hasattr(SENDER_SEED, "get_sp_keys")


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
