import embit

from binascii import b2a_base64
from hashlib import sha256

from embit import bip32, compact, ec
from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.util import secp256k1


from seedsigner.models.settings_definition import SettingsConstants


"""
    Collection of generic embit-powered util methods.
"""
# TODO: PR these directly into `embit`? Or replace with new/existing methods already in `embit`?


# TODO: Refactor `wallet_type` to conform to our `sig_type` naming convention
def get_standard_derivation_path(network: str = SettingsConstants.MAINNET, wallet_type: str = SettingsConstants.SINGLE_SIG, script_type: str = SettingsConstants.NATIVE_SEGWIT) -> str:
    if network == SettingsConstants.MAINNET:
        network_path = "0'"
    elif network == SettingsConstants.TESTNET:
        network_path = "1'"
    elif network == SettingsConstants.REGTEST:
        network_path = "1'"
    else:
        raise Exception("Unexpected network")

    if wallet_type == SettingsConstants.SINGLE_SIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/44'/{network_path}/0'"
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/49'/{network_path}/0'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/84'/{network_path}/0'"
        elif script_type == SettingsConstants.TAPROOT:
            return f"m/86'/{network_path}/0'"
        else:
            raise Exception("Unexpected script type")

    elif wallet_type == SettingsConstants.MULTISIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/45'" #BIP-45
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/48'/{network_path}/0'/1'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/48'/{network_path}/0'/2'"
        elif script_type == SettingsConstants.TAPROOT:
            raise Exception("Taproot multisig not yet supported")
        else:
            raise Exception("Unexpected script type")
    else:
        raise Exception("Unexpected wallet type")    # checks that all inputs are from the same wallet



def get_xpub(seed_bytes, derivation_path: str, embit_network: str = "main") -> HDKey:
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    xprv = root.derive(derivation_path)
    xpub = xprv.to_public()
    return xpub



def get_single_sig_address(xpub: HDKey, script_type: str = SettingsConstants.NATIVE_SEGWIT, index: int = 0, is_change: bool = False, embit_network: str = "main") -> str:
    if is_change:
        pubkey = xpub.derive([1,index]).key
    else:
        pubkey = xpub.derive([0,index]).key

    if script_type == SettingsConstants.LEGACY_P2PKH:
        return embit.script.p2pkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NESTED_SEGWIT:
        return embit.script.p2sh(embit.script.p2wpkh(pubkey)).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NATIVE_SEGWIT:
        return embit.script.p2wpkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.TAPROOT:
        return embit.script.p2tr(pubkey).address(network=NETWORKS[embit_network])



def get_multisig_address(descriptor: Descriptor, index: int = 0, is_change: bool = False, embit_network: str = "main"):
    if is_change:
        branch_index = 1
    else:
        branch_index = 0

    # Can derive p2wsh, p2sh-p2wsh, and legacy (non-segwit) p2sh
    if descriptor.is_segwit or (descriptor.is_legacy and descriptor.is_basic_multisig):
        return descriptor.derive(index, branch_index=branch_index).script_pubkey().address(network=NETWORKS[embit_network])

    elif descriptor.is_taproot:
        # TODO: Not yet implemented!
        raise Exception("Taproot verification not yet implemented!")

    raise Exception(f"{descriptor.script_pubkey().script_type()} address verification not yet implemented!")



def get_multisig_policy(descriptor: Descriptor) -> tuple:
    """Extract (threshold, n) from a basic multisig descriptor."""
    if not descriptor.is_basic_multisig:
        raise ValueError(f"Expected a basic multisig descriptor, got: {descriptor.brief_policy}")
    return (str(descriptor.miniscript.args[0]), str(len(descriptor.keys)))



def get_embit_network_name(settings_name):
    """ Convert SeedSigner SettingsConstants for `network` to embit's NETWORK key """
    lookup = {
        SettingsConstants.MAINNET: "main",
        SettingsConstants.TESTNET: "test",
        SettingsConstants.REGTEST: "regtest",
    }
    return lookup.get(settings_name)



def parse_derivation_path(derivation_path: str) -> dict:
    """
    Parses a derivation path into its related SettingsConstants equivalents.

    Primarily only supports single sig derivation paths.

    May return None for fields it cannot parse.
    """
    # Support either m/44'/... or m/44h/... style
    derivation_path = derivation_path.replace("'", "h")

    sections = derivation_path.split("/")

    if sections[1] == "48h":
        # So far this helper is only meant for single sig message signing
        raise Exception("Not implemented")

    lookups = {
        "script_types": {
            "44h": SettingsConstants.LEGACY_P2PKH,
            "49h": SettingsConstants.NESTED_SEGWIT,
            "84h": SettingsConstants.NATIVE_SEGWIT,
            "86h": SettingsConstants.TAPROOT,
        },
        "networks": {
            "0h": SettingsConstants.MAINNET,
            "1h": [SettingsConstants.TESTNET, SettingsConstants.REGTEST],
        }
    }

    details = dict()
    details["script_type"] = lookups["script_types"].get(sections[1])
    if not details["script_type"]:
        details["script_type"] = SettingsConstants.CUSTOM_DERIVATION
    details["network"] = lookups["networks"].get(sections[2])

    # Check if there's a standard change path
    if sections[-2] in ["0", "1"]:
        details["is_change"] = sections[-2] == "1"
    else:
        details["is_change"] = None

    # Check if there's a standard address index
    if sections[-1].isdigit():
        details["index"] = int(sections[-1])
    else:
        details["index"] = None

    if details["is_change"] is not None and details["index"] is not None:
        # standard change and addr index; safe to truncate to the wallet level
        details["wallet_derivation_path"] = "/".join(sections[:-2])
    else:
        details["wallet_derivation_path"] = None

    details["clean_match"] = True
    for k, v in details.items():
        if v is None:
            # At least one field couldn't be parsed
            details["clean_match"] = False
            break

    return details



def is_silent_payments_available() -> bool:
    """True if the installed embit build ships the silent_payments module."""
    try:
        import embit.silent_payments  # noqa: F401
        return True
    except ImportError:
        return False


def get_psbt_cls(sp_enabled: bool) -> type:
    """Resolve the PSBT class to parse with. Returns SilentPaymentsPSBT (a strict
    superset of PSBT) only when Silent Payments is enabled AND available, so SP
    fields survive parsing; otherwise vanilla PSBT."""
    from embit.psbt import PSBT
    if sp_enabled and is_silent_payments_available():
        from embit.silent_payments import SilentPaymentsPSBT
        return SilentPaymentsPSBT
    return PSBT


def psbt_has_sp_content(psbt) -> bool:
    """True if an already-parsed PSBT carries Silent Payments fields (SP output
    or SP spend input). Only meaningful on a PSBT parsed with the SP-aware class;
    vanilla-parsed PSBTs never expose these attributes."""
    has_out = any(getattr(o, "sp_data", None) is not None for o in psbt.outputs)
    has_in = any(getattr(i, "sp_tweak", None) is not None for i in psbt.inputs)
    return has_out or has_in



def encode_sp_address(scan_pubkey: ec.PublicKey, spend_pubkey: ec.PublicKey, network: str = SettingsConstants.MAINNET) -> str:
    """Bech32m-encode a silent payment address from the recipient's scan and spend
    public keys (e.g. as carried in a PSBT output's sp_data). Mirrors the encoding
    tail of embit.silent_payments.bip352.generate_silent_payment_address."""
    from embit import bech32
    embit_network = SettingsConstants.map_network_to_embit(network)
    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if embit_network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [0] + data)


def fill_sp_send_output_scripts(psbt, eligible=None) -> bool:
    """BIP-375 "output generator": derive and fill each Silent Payment output's
    taproot scriptPubKey from the ECDH shares already contributed to the PSBT's
    eligible inputs.

    Mirrors ``embit.silent_payments.validator._validate_output_scripts`` but
    *assigns* the derived script instead of comparing it. Returns True only when
    every SP output was resolved (the signing device controls all eligible inputs);
    returns False and fills nothing when the per-input ECDH shares are incomplete
    (a multi-party send this device cannot finish alone).

    Pass ``eligible`` (the already-computed get_eligible_inputs result) to avoid
    a redundant call when the caller has already computed it."""
    from embit.script import Script
    from embit.transaction import COutPoint
    from embit.silent_payments.ecdh import get_eligible_inputs, input_public_key
    from embit.silent_payments.bip352 import (
        get_input_hash,
        derive_silent_payment_outputs,
    )
    from embit.util.secp256k1 import (
        ec_pubkey_parse,
        ec_pubkey_combine,
        ec_pubkey_serialize,
        ec_pubkey_tweak_mul,
        EC_COMPRESSED,
    )

    sp_outputs = [
        (i, o)
        for i, o in enumerate(psbt.outputs)
        if getattr(o, "sp_data", None) is not None
    ]
    if not sp_outputs:
        return True

    if eligible is None:
        eligible = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)
    if not eligible:
        return False

    # BIP-352 input_hash commits to the smallest outpoint over ALL inputs, while A
    # is the sum of the eligible input public keys.
    outpoints = [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in range(len(psbt.inputs))
    ]
    eligible_pubkeys = [input_public_key(psbt.inputs[i]) for i in eligible]
    if any(pk is None for pk in eligible_pubkeys):
        # input_hash must commit to ALL eligible inputs' pubkeys; deriving it from
        # a partial sum would pay an address the recipient can never detect.
        return False
    a_sum = ec_pubkey_parse(eligible_pubkeys[0].sec())
    for pk in eligible_pubkeys[1:]:
        a_sum = ec_pubkey_combine(a_sum, ec_pubkey_parse(pk.sec()))
    input_hash = get_input_hash(outpoints, ec_pubkey_serialize(a_sum, EC_COMPRESSED))

    # Group SP outputs by scan key, preserving output-index order so the per-group
    # derivation counter k matches each output's position (BIP-375).
    groups = {}
    for out_idx, out in sp_outputs:
        groups.setdefault(out.sp_data.scan_key.sec(), []).append((out_idx, out))

    resolved = {}
    for scan_key_bytes, group in groups.items():
        # Sum the per-input ECDH shares for this scan key. Require a share from
        # every eligible input, else the shared secret is incomplete.
        share_sum = None
        contributing = 0
        for i in eligible:
            share = psbt.inputs[i].sp_ecdh_shares.get(scan_key_bytes)
            if share is None:
                continue
            parsed = ec_pubkey_parse(share)
            share_sum = parsed if share_sum is None else ec_pubkey_combine(share_sum, parsed)
            contributing += 1
        if share_sum is None or contributing != len(eligible):
            return False

        ecdh_share = ec_pubkey_serialize(share_sum, EC_COMPRESSED)
        adjusted = bytearray(ec_pubkey_parse(ecdh_share))
        ec_pubkey_tweak_mul(adjusted, input_hash)
        adjusted_share = ec_pubkey_serialize(adjusted, EC_COMPRESSED)

        derived = derive_silent_payment_outputs(
            adjusted_share,
            [(o.sp_data.scan_key, o.sp_data.spend_key, o.sp_label) for _, o in group],
        )
        for pos, (out_idx, _out) in enumerate(group):
            resolved[out_idx] = Script(b"\x51\x20" + derived[pos])

    for out_idx, spk in resolved.items():
        psbt.outputs[out_idx].script_pubkey = spk
    return True


def sign_sp_psbt(psbt, root) -> int:
    """Sign a Silent Payments PSBT that pays *to* one or more SP addresses (BIP-375
    send).

    embit's ``SilentPaymentsPSBT.sign_with`` cannot run unaided here: the SP output
    scripts are derived from the inputs' ECDH shares, yet each input's sighash
    commits to the serialized outputs — so an unresolved SP output (``script_pubkey
    is None``) makes ``sign_with`` crash serializing ``None``. This wrapper performs
    the missing BIP-375 steps in the right order:

      1. Verify ``root`` controls every eligible input, before anything is
         modified. SeedSigner only supports single-signer SP sends: a foreign
         eligible input (multi-party send) and a wrong seed each raise a
         ``ValueError`` that names the actual problem.
      2. Clear coordinator-supplied SP send fields, then contribute our own
         per-input ECDH shares + DLEQ proofs (``_sign_with_sp``). As sole signer
         we recompute everything rather than verify-and-trust incoming data.
      3. Derive and fill the SP output scripts from those shares.
      4. Emit PSBT-global ECDH share + DLEQ proof (required by Sparrow / BIP-375).
      5. Sign ordinary inputs (and any BIP-376 spend inputs) over the now-correct
         outputs.

    If the PSBT carries SP outputs but no eligible input, the output scripts
    can't be derived and we return 0 without signing. Returns embit's
    ``sign_with`` counter (0 when nothing was signed)."""
    from embit.silent_payments.ecdh import (
        compute_global_ecdh_share,
        compute_global_dleq_proof,
        get_eligible_inputs,
    )

    scan_key_objects = {}
    for out in psbt.outputs:
        if getattr(out, "sp_data", None) is not None:
            scan_key_objects[out.sp_data.scan_key.sec()] = out.sp_data.scan_key

    eligible = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)
    fingerprint, _ = psbt._signing_fingerprint(root)
    priv_keys = []
    foreign_inputs = []
    for i in eligible:
        priv = psbt._resolve_input_privkey(psbt.inputs[i], root, fingerprint)
        if priv is None:
            foreign_inputs.append(i)
        else:
            priv_keys.append(priv)
    if foreign_inputs:
        if priv_keys:
            raise ValueError(
                "Silent Payment signing failed: input(s) {} belong to another "
                "signer; multi-party Silent Payment sends are not supported.".format(
                    ", ".join(str(i) for i in foreign_inputs)
                )
            )
        raise ValueError(
            "Silent Payment signing failed: no eligible input is controlled "
            "by this seed (check derivation / fingerprint)."
        )

    psbt.sp_ecdh_shares.clear()
    psbt.sp_dleq_proofs.clear()
    for inp in psbt.inputs:
        inp.sp_ecdh_shares.clear()
        inp.sp_dleq_proofs.clear()
    psbt._sign_with_sp(root)

    if not fill_sp_send_output_scripts(psbt, eligible=eligible):
        return 0

    for sk_bytes, scan_key in scan_key_objects.items():
        global_share = compute_global_ecdh_share(priv_keys, scan_key)
        if global_share is not None:
            psbt.sp_ecdh_shares[sk_bytes] = global_share
            psbt.sp_dleq_proofs[sk_bytes] = compute_global_dleq_proof(
                priv_keys, scan_key, global_share, aux_rand=None
            )

    return psbt.sign_with(root, with_sp_shares=False)


def sign_message(seed_bytes: bytes, derivation: str, msg: bytes, compressed: bool = True, embit_network: str = "main") -> bytes:
    """
        from: https://github.com/cryptoadvance/specter-diy/blob/b58a819ef09b2bca880a82c7e122618944355118/src/apps/signmessage/signmessage.py
    """
    """Sign message with private key"""
    msghash = sha256(
        sha256(
            b"\x18Bitcoin Signed Message:\n" + compact.to_bytes(len(msg)) + msg
        ).digest()
    ).digest()

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    prv = root.derive(derivation).key
    sig = secp256k1.ecdsa_sign_recoverable(msghash, prv._secret)
    flag = sig[64]
    sig = ec.Signature(sig[:64])
    c = 4 if compressed else 0
    flag = bytes([27 + flag + c])
    ser = flag + secp256k1.ecdsa_signature_serialize_compact(sig._sig)
    return b2a_base64(ser).strip().decode()

