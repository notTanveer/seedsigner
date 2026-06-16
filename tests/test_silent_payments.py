from base import BaseTest, FlowTest, FlowStep

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from sp_testing_util import build_sp_send_psbt, build_sp_spend_psbt, build_sp_send_psbt_realistic


SEED = Seed("obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash".split())


def _decoder_for(psbt):
    """A completed DecodeQR whose raw bytes are the given PSBT."""
    from seedsigner.models.decode_qr import DecodeQR
    d = DecodeQR()
    d.complete = True
    d.get_data_psbt = lambda: psbt.serialize()
    return d


class TestSettingGatedParse(BaseTest):
    def test_get_psbt_sp_enabled_preserves_sp_fields(self):
        from embit.silent_payments import SilentPaymentsPSBT
        decoder = _decoder_for(build_sp_send_psbt(SEED))
        parsed = decoder.get_psbt(sp_enabled=True)
        assert isinstance(parsed, SilentPaymentsPSBT)
        assert any(getattr(o, "sp_data", None) is not None for o in parsed.outputs)

    def test_get_psbt_sp_disabled_returns_vanilla(self):
        from embit.psbt import PSBT
        decoder = _decoder_for(build_sp_send_psbt(SEED))
        parsed = decoder.get_psbt(sp_enabled=False)
        assert type(parsed) is PSBT
        assert all(getattr(o, "sp_data", None) is None for o in parsed.outputs)


class TestPSBTParserSPDetection(BaseTest):
    def _parser(self, psbt):
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.settings_definition import SettingsConstants
        return PSBTParser(psbt, seed=SEED, network=SettingsConstants.MAINNET)

    def test_send_psbt_detected_and_renders_sp_address(self):
        parser = self._parser(build_sp_send_psbt(SEED))
        assert parser.has_sp_outputs is True
        assert parser.has_sp_spend_inputs is False
        assert len(parser.destination_addresses) == 1
        assert parser.destination_addresses[0].startswith("sp1")
        assert parser.destination_is_sp == [True]

    def test_spend_psbt_detected_as_spend_input(self):
        parser = self._parser(build_sp_spend_psbt(SEED))
        assert parser.has_sp_spend_inputs is True
        assert parser.has_sp_outputs is False
        assert parser.destination_is_sp == [False]


class TestSPSendSigning(BaseTest):
    def test_send_fills_output_script_and_signs(self):
        """A BIP-375 send PSBT arrives with the SP output script unresolved
        (script_pubkey is None). The device must derive the taproot output script
        and sign its input without crashing."""
        from seedsigner.helpers import embit_utils
        from embit import bip32
        from embit.silent_payments.validator import BIP375Validator

        psbt = build_sp_send_psbt(SEED, output_script_resolved=False)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        assert psbt.outputs[0].script_pubkey is None

        embit_utils.sign_sp_psbt(psbt, root)

        spk = psbt.outputs[0].script_pubkey
        assert spk is not None
        assert spk.data[:2] == b"\x51\x20" and len(spk.data) == 34
        assert len(psbt.inputs[0].partial_sigs) >= 1
        assert PSBTParser.sp_contribution_count(psbt) >= 1
        BIP375Validator(psbt).validate()

    def test_raw_sign_with_raises_on_unresolved_sp_output(self):
        """Documents the embit limitation the helper works around: calling
        sign_with directly on an unresolved SP send PSBT crashes serializing the
        None output script."""
        from embit import bip32
        psbt = build_sp_send_psbt(SEED, output_script_resolved=False)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        try:
            psbt.sign_with(root)
            raised = False
        except AttributeError:
            raised = True
        assert raised


class TestSPTrim(BaseTest):
    def test_send_psbt_trim_preserves_sp_fields(self):
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.helpers import embit_utils
        from embit.silent_payments import SilentPaymentsPSBT
        from embit import bip32
        psbt = build_sp_send_psbt(SEED)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        trimmed = PSBTParser.trim(psbt)
        assert isinstance(trimmed, SilentPaymentsPSBT)
        assert any(getattr(o, "sp_data", None) is not None for o in trimmed.outputs)
        assert PSBTParser.sp_contribution_count(trimmed) >= 1

    def test_send_psbt_trim_strips_bulky_fields(self):
        """Trim drops non_witness_utxo and input bip32_derivations (the coordinator
        already has them) while keeping the PSBT independently BIP-375 validatable
        — witness_utxo provides eligibility, partial_sigs provide the DLEQ pubkeys."""
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.helpers import embit_utils
        from embit.silent_payments import SilentPaymentsPSBT
        from embit.silent_payments.validator import BIP375Validator
        from embit import bip32
        psbt = build_sp_send_psbt_realistic(SEED)
        assert psbt.inputs[0].non_witness_utxo is not None
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        trimmed = PSBTParser.trim(psbt)
        assert trimmed.inputs[0].non_witness_utxo is None
        assert trimmed.inputs[0].witness_utxo is not None
        assert len(trimmed.inputs[0].bip32_derivations) == 0
        assert len(trimmed.outputs[1].bip32_derivations) == 1
        parsed = SilentPaymentsPSBT.parse(trimmed.serialize())
        assert len(parsed.sp_ecdh_shares) >= 1
        assert len(parsed.inputs[0].partial_sigs) >= 1
        BIP375Validator(parsed).validate(skip_output_scripts=False)

    def test_pure_spend_trim_finalizes_on_device(self):
        from seedsigner.models.psbt_parser import PSBTParser
        from embit import bip32
        psbt = build_sp_spend_psbt(SEED)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        psbt.sign_with(root)
        assert psbt.inputs[0].taproot_key_sig is not None
        trimmed = PSBTParser.trim(psbt)
        assert trimmed.inputs[0].final_scriptwitness is not None
        assert PSBTParser.sig_count(trimmed) == 1


class TestSPFinalizeFlow(FlowTest):
    def _prime(self, psbt):
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.settings_definition import SettingsConstants
        self.controller.psbt = psbt
        self.controller.psbt_seed = SEED
        self.controller.psbt_parser = PSBTParser(psbt, seed=SEED, network=SettingsConstants.MAINNET)

    def test_spend_psbt_signs_and_reaches_signed_qr(self):
        from seedsigner.views import psbt_views
        self._prime(build_sp_spend_psbt(SEED))
        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ])
        assert self.controller.psbt.inputs[0].final_scriptwitness is not None

    def test_send_psbt_signs_and_reaches_signed_qr(self):
        from seedsigner.views import psbt_views
        from seedsigner.models.psbt_parser import PSBTParser
        self._prime(build_sp_send_psbt(SEED))
        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ])
        assert PSBTParser.sp_contribution_count(self.controller.psbt) >= 1


class TestSPDisplayFlow(BaseTest):
    def test_sp_spend_overview_passes_sp_flag_to_screen(self):
        from seedsigner.views import psbt_views
        from seedsigner.models.settings_definition import SettingsConstants
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        parser = PSBTParser(build_sp_spend_psbt(SEED), seed=SEED, network=SettingsConstants.MAINNET)
        self.controller.psbt = parser.psbt
        self.controller.psbt_seed = SEED
        self.controller.psbt_parser = parser

        view = psbt_views.PSBTOverviewView()
        captured = {}

        def capture(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = capture
        view.run()

        assert captured["is_silent_payment_spend"] is True

    def test_sp_destination_address_details_title_includes_sp_marker(self):
        from seedsigner.views import psbt_views
        from seedsigner.models.settings_definition import SettingsConstants
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON

        parser = PSBTParser(build_sp_send_psbt(SEED), seed=SEED, network=SettingsConstants.MAINNET)
        self.controller.psbt_parser = parser
        view = psbt_views.PSBTAddressDetailsView(address_num=0)

        captured = {}
        def capture(screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view.run_screen = capture
        view.run()

        assert captured["title"] == "Will Send (SP)"


class TestSPSigningVariants(BaseTest):
    """Test SP signing with various PSBT configurations coordinators may produce."""

    def _sign_and_validate(self, psbt, root=None):
        from seedsigner.helpers import embit_utils
        from embit import bip32
        from embit.silent_payments.validator import BIP375Validator
        if root is None:
            root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        assert PSBTParser.sp_contribution_count(psbt) >= 1
        assert len(psbt.sp_ecdh_shares) >= 1
        assert len(psbt.sp_dleq_proofs) >= 1
        BIP375Validator(psbt).validate()

    def test_send_with_bip84_derivation_path(self):
        self._sign_and_validate(build_sp_send_psbt_realistic(SEED))

    def test_send_with_non_witness_and_witness_utxo(self):
        psbt = build_sp_send_psbt_realistic(SEED)
        assert psbt.inputs[0].non_witness_utxo is not None
        assert psbt.inputs[0].witness_utxo is not None
        self._sign_and_validate(psbt)

    def test_send_with_sighash_all_set(self):
        psbt = build_sp_send_psbt_realistic(SEED)
        assert psbt.inputs[0].sighash_type == 0x01
        self._sign_and_validate(psbt)

    def test_send_with_change_output(self):
        psbt = build_sp_send_psbt_realistic(SEED)
        assert len(psbt.outputs) == 2
        self._sign_and_validate(psbt)

    def test_send_with_pre_resolved_output_script(self):
        psbt = build_sp_send_psbt_realistic(SEED, output_script_resolved=True)
        assert psbt.outputs[0].script_pubkey is not None
        self._sign_and_validate(psbt)

    def test_send_with_network_versioned_root(self):
        from embit import bip32
        from embit.networks import NETWORKS
        root = bip32.HDKey.from_seed(SEED.seed_bytes, version=NETWORKS["main"]["xprv"])
        self._sign_and_validate(build_sp_send_psbt_realistic(SEED), root=root)

    def test_serialize_roundtrip_preserves_sp_fields(self):
        from seedsigner.helpers import embit_utils
        from embit import bip32
        from embit.silent_payments import SilentPaymentsPSBT
        from embit.silent_payments.validator import BIP375Validator
        psbt = build_sp_send_psbt_realistic(SEED)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        raw = psbt.serialize()
        parsed = SilentPaymentsPSBT.parse(raw)
        assert PSBTParser.sp_contribution_count(parsed) >= 1
        assert len(parsed.inputs[0].partial_sigs) >= 1
        assert len(parsed.sp_ecdh_shares) >= 1
        assert len(parsed.sp_dleq_proofs) >= 1
        BIP375Validator(parsed).validate(skip_output_scripts=False)


class TestSPValidationGuard(FlowTest):

    def _prime(self, psbt):
        from seedsigner.models.settings_definition import SettingsConstants
        self.controller.psbt = psbt
        self.controller.psbt_seed = SEED
        self.controller.psbt_parser = PSBTParser(psbt, seed=SEED, network=SettingsConstants.MAINNET)

    def test_valid_send_reaches_signed_qr(self):
        from seedsigner.views import psbt_views
        self._prime(build_sp_send_psbt(SEED))
        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ])

    def test_valid_realistic_send_reaches_signed_qr(self):
        from seedsigner.views import psbt_views
        self._prime(build_sp_send_psbt_realistic(SEED))
        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ])

    def test_incomplete_sp_send_routes_to_error_view(self):
        """Simulate the Sparrow bug: signing adds partial_sigs + ECDH shares,
        but ECDH shares are stripped post-signing (before validation guard)."""
        from seedsigner.views import psbt_views
        from seedsigner.helpers import embit_utils
        from unittest.mock import patch

        self._prime(build_sp_send_psbt(SEED))

        _real_sign = embit_utils.sign_sp_psbt

        def sign_and_strip_shares(psbt, root):
            cnt = _real_sign(psbt, root)
            psbt.sp_ecdh_shares.clear()
            psbt.sp_dleq_proofs.clear()
            for inp in psbt.inputs:
                inp.sp_ecdh_shares.clear()
                inp.sp_dleq_proofs.clear()
            return cnt

        with patch.object(embit_utils, "sign_sp_psbt", side_effect=sign_and_strip_shares):
            self.run_sequence([
                FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
                FlowStep(psbt_views.PSBTSPValidationErrorView),
            ])

    def test_wrong_seed_routes_to_sp_error_view(self):
        """sign_sp_psbt with a mismatched seed raises the coverage error, which
        PSBTFinalizeView now catches and routes to PSBTSPValidationErrorView."""
        from seedsigner.views import psbt_views
        from seedsigner.models.settings_definition import SettingsConstants
        from embit import bip32

        psbt = build_sp_send_psbt_realistic(SEED)
        wrong_root = bip32.HDKey.from_seed(bytes([0x99] * 32))
        parser = PSBTParser(psbt, seed=SEED, network=SettingsConstants.MAINNET)
        parser.root = wrong_root  # make the parser sign with the wrong key

        self.controller.psbt = psbt
        self.controller.psbt_seed = SEED
        self.controller.psbt_parser = parser

        self.run_sequence([
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSPValidationErrorView),
        ])


class TestSPGlobalShare(BaseTest):
    """Tests focused on the PSBT-global ECDH share + DLEQ proof (Sparrow fix)."""

    def test_global_share_verifies_with_skip_output_scripts_false(self):
        """Global share + proof survive BIP375Validator with skip_output_scripts=False
        (the path Sparrow exercises)."""
        from seedsigner.helpers import embit_utils
        from embit import bip32
        from embit.silent_payments.validator import BIP375Validator
        psbt = build_sp_send_psbt_realistic(SEED)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        BIP375Validator(psbt).validate(skip_output_scripts=False)

    def test_bogus_incoming_share_replaced(self):
        """Pre-seeded bogus per-input share is replaced by a valid one after signing."""
        from seedsigner.helpers import embit_utils
        from embit import bip32
        from embit.silent_payments.validator import BIP375Validator
        from sp_testing_util import SCAN_HEX
        from binascii import unhexlify
        psbt = build_sp_send_psbt_realistic(SEED)
        scan_bytes = unhexlify(SCAN_HEX)
        psbt.inputs[0].sp_ecdh_shares[scan_bytes] = bytes(33)  # bogus
        root = bip32.HDKey.from_seed(SEED.seed_bytes)
        embit_utils.sign_sp_psbt(psbt, root)
        assert psbt.inputs[0].sp_ecdh_shares.get(scan_bytes) != bytes(33)
        BIP375Validator(psbt).validate(skip_output_scripts=False)

    def test_wrong_seed_raises_coverage_error(self):
        """sign_sp_psbt with a mismatched root raises ValueError naming the input."""
        from seedsigner.helpers import embit_utils
        from embit import bip32
        import pytest
        wrong_root = bip32.HDKey.from_seed(bytes([0x99] * 32))
        psbt = build_sp_send_psbt_realistic(SEED)
        with pytest.raises(ValueError, match="Silent Payment signing failed"):
            embit_utils.sign_sp_psbt(psbt, wrong_root)


class TestSPMultiParty(BaseTest):
    def _add_foreign_input(self, psbt):
        """Append an eligible P2WPKH input owned by a different signer, carrying
        that signer's pre-existing ECDH share + DLEQ proof."""
        from binascii import unhexlify
        from embit import bip32, script
        from embit.psbt import DerivationPath
        from embit.transaction import TransactionOutput
        from embit.silent_payments.psbt import SPInputScope
        from sp_testing_util import SCAN_HEX

        foreign_root = bip32.HDKey.from_seed(bytes([0x42] * 32))
        foreign_pub = foreign_root.derive([0, 0]).get_public_key()
        inp = SPInputScope()
        inp.txid = bytes([0xBB] * 32)
        inp.vout = 1
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=50_000, script_pubkey=script.p2wpkh(foreign_pub))
        inp.bip32_derivations[foreign_pub] = DerivationPath(foreign_root.my_fingerprint, [0, 0])
        scan_bytes = unhexlify(SCAN_HEX)
        inp.sp_ecdh_shares[scan_bytes] = bytes(33)
        inp.sp_dleq_proofs[scan_bytes] = bytes(64)
        # Bypass add_input (tx_modifiable_flags=0); fine for an in-memory fixture.
        psbt.inputs.append(inp)
        return scan_bytes

    def test_multiparty_send_raises_and_preserves_foreign_shares(self):
        """A send PSBT with an eligible input we don't control must be refused
        with a multi-party error — not a wrong-seed hint — and the refusal must
        not wipe the cosigner's contribution from the PSBT."""
        from seedsigner.helpers import embit_utils
        from embit import bip32
        import pytest

        psbt = build_sp_send_psbt(SEED)
        scan_bytes = self._add_foreign_input(psbt)
        root = bip32.HDKey.from_seed(SEED.seed_bytes)

        with pytest.raises(ValueError, match="another signer"):
            embit_utils.sign_sp_psbt(psbt, root)

        assert psbt.inputs[1].sp_ecdh_shares.get(scan_bytes) == bytes(33)
        assert psbt.inputs[1].sp_dleq_proofs.get(scan_bytes) == bytes(64)
