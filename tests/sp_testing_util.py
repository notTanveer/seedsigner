from binascii import unhexlify

from embit import bip32, ec, script
from embit.psbt import DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.seed import Seed

# Recipient SP keys borrowed from embit's BIP-375 test vectors.
SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

# A fixed, valid external destination pubkey (not owned by any test seed).
EXTERNAL_PUB = ec.PrivateKey(bytes([0x09] * 32)).get_public_key()


def _root(seed: Seed) -> bip32.HDKey:
    # Mainnet master key; matches PSBTParser._set_root for SettingsConstants.MAINNET.
    return bip32.HDKey.from_seed(seed.seed_bytes)


def build_sp_send_psbt(seed: Seed, value: int = 100_000, output_script_resolved: bool = True):
    """PSBTv2: one P2WPKH input owned by `seed`, one SP output (paying to an
    sp address). Signing contributes ECDH shares + DLEQ proofs (BIP-375).

    A real coordinator hands the signer an *unresolved* SP output (only sp_data; no
    PSBT_OUT_SCRIPT) — the script is derived from the inputs' ECDH shares at signing
    time. Pass ``output_script_resolved=False`` for that realistic arrival state.
    The default keeps a placeholder p2tr script so the PSBT is parseable by vanilla
    embit (used by the parse/QR-detection tests)."""
    from embit.silent_payments import SilentPaymentsPSBT, SilentPaymentData
    from embit.silent_payments.psbt import SPInputScope, SPOutputScope
    root = _root(seed)
    # Simplified fixture path [0, 0]; real BIP-352 spend derivation is m/352h/0h/0h/0/0.
    # The signer follows whatever derivation the PSBT carries, so [0,0] is sufficient here.
    child = root.derive([0, 0])
    pub = child.get_public_key()

    psbt = SilentPaymentsPSBT.create_v2()

    inp = SPInputScope()
    inp.txid = bytes([0xAA] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=value, script_pubkey=script.p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    scan_pub = ec.PublicKey.parse(unhexlify(SCAN_HEX))
    spend_pub = ec.PublicKey.parse(unhexlify(SPEND_HEX))
    out = SPOutputScope()
    out.value = value - 1_000
    # Placeholder p2tr keeps the PSBT vanilla-parseable; None models a real
    # coordinator's unresolved SP output (script derived at signing time).
    out.script_pubkey = script.Script(b"\x51\x20" + bytes(32)) if output_script_resolved else None
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    psbt.tx_modifiable_flags = 0
    return psbt


def build_sp_send_psbt_realistic(seed: Seed, value: int = 100_000,
                                  output_script_resolved: bool = False):
    """Sparrow-realistic PSBTv2: BIP-84 derivation (m/84'/0'/0'/0/0), includes
    both non_witness_utxo and witness_utxo, a change P2WPKH output, and
    sighash_type set to SIGHASH_ALL (0x01)."""
    from embit.silent_payments import SilentPaymentsPSBT, SilentPaymentData
    from embit.silent_payments.psbt import SPInputScope, SPOutputScope
    root = _root(seed)
    deriv_path = [0x80000054, 0x80000000, 0x80000000, 0, 0]
    child = root.derive(deriv_path)
    pub = child.get_public_key()

    change_deriv = [0x80000054, 0x80000000, 0x80000000, 1, 0]
    change_child = root.derive(change_deriv)
    change_pub = change_child.get_public_key()

    psbt = SilentPaymentsPSBT.create_v2()

    inp = SPInputScope()
    inp.txid = bytes([0xCC] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=value, script_pubkey=script.p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, deriv_path)
    inp.sighash_type = 0x01  # SIGHASH_ALL
    prev_tx = Transaction(
        version=2,
        locktime=0,
        vin=[TransactionInput(bytes([0x00] * 32), 0)],
        vout=[TransactionOutput(value=value, script_pubkey=script.p2wpkh(pub))]
    )
    inp.non_witness_utxo = prev_tx
    psbt.add_input(inp)

    scan_pub = ec.PublicKey.parse(unhexlify(SCAN_HEX))
    spend_pub = ec.PublicKey.parse(unhexlify(SPEND_HEX))
    sp_out = SPOutputScope()
    sp_out.value = value - 5_000
    sp_out.script_pubkey = script.Script(b"\x51\x20" + bytes(32)) if output_script_resolved else None
    sp_out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(sp_out)

    change_out = SPOutputScope()
    change_out.value = 4_000
    change_out.script_pubkey = script.p2wpkh(change_pub)
    change_out.bip32_derivations[change_pub] = DerivationPath(root.my_fingerprint, change_deriv)
    psbt.add_output(change_out)

    psbt.tx_modifiable_flags = 0
    return psbt


def build_sp_spend_psbt(seed: Seed, tweak: bytes = bytes([0x11] * 32),
                        value: int = 100_000):
    """PSBTv2: one P2TR input that is a *received* SP output (carries sp_tweak +
    sp_spend_bip32_derivations), one ordinary external P2WPKH destination.
    Signing produces a taproot key signature (BIP-376). No SP outputs => pure-spend."""
    from embit.silent_payments import SilentPaymentsPSBT, SilentPaymentData
    from embit.silent_payments.psbt import SPInputScope, SPOutputScope
    root = _root(seed)
    # Simplified fixture path [0, 0]; real BIP-352 spend derivation is m/352h/0h/0h/0/0.
    # The signer follows whatever derivation the PSBT carries, so [0,0] is sufficient here.
    child = root.derive([0, 0])
    spend_priv = child.key
    spend_pub = child.get_public_key()
    output_xonly = spend_priv.sp_spend_tweak(tweak).xonly()

    psbt = SilentPaymentsPSBT.create_v2()

    inp = SPInputScope()
    inp.txid = bytes([0xCD] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(
        value=value, script_pubkey=script.Script(b"\x51\x20" + output_xonly)
    )
    inp.sp_tweak = tweak
    inp.sp_spend_bip32_derivations[spend_pub.sec()] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    out = SPOutputScope()
    out.value = value - 5_000
    out.script_pubkey = script.p2wpkh(EXTERNAL_PUB)
    psbt.add_output(out)

    psbt.tx_modifiable_flags = 0
    return psbt
