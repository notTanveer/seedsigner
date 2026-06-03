# Make GPIO/display/camera-dependent imports safe on non-Raspi (see tests/base.py)
from base import BaseTest

from seedsigner.helpers.embit_utils import get_psbt_cls


class TestGetPsbtCls(BaseTest):
    def test_returns_silent_payments_psbt_when_available(self):
        from embit.silent_payments import SilentPaymentsPSBT
        assert get_psbt_cls() is SilentPaymentsPSBT
