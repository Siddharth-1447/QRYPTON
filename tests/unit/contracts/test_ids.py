from __future__ import annotations

import pytest

from qrypton.contracts.errors import IdDerivationError
from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes

from .conftest import tenant_id


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical_json_bytes({"b": [2, 1], "a": {"z": True}}) == canonical_json_bytes(
        {"a": {"z": True}, "b": [2, 1]}
    )


def test_hmac_ids_are_stable_and_tenant_scoped() -> None:
    deriver = HmacIdDeriver(b"k" * 32)
    payload = canonical_json_bytes({"source": "same"})
    stable = deriver.derive(namespace="evidence", tenant_id=tenant_id(), canonical_payload=payload)
    assert stable == deriver.derive(
        namespace="evidence", tenant_id=tenant_id(), canonical_payload=payload
    )
    other_tenant = f"tenant_{'b' * 52}"
    assert stable != deriver.derive(
        namespace="evidence", tenant_id=other_tenant, canonical_payload=payload
    )
    assert stable.startswith("evidence_")


def test_id_deriver_rejects_short_secret_and_invalid_namespace() -> None:
    with pytest.raises(IdDerivationError):
        HmacIdDeriver(b"short")
    with pytest.raises(IdDerivationError):
        HmacIdDeriver(b"k" * 32).derive(
            namespace="Bad", tenant_id=tenant_id(), canonical_payload=b"x"
        )
