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
