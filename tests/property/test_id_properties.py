from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes
from tests.unit.contracts.conftest import tenant_id


@given(st.dictionaries(st.text(min_size=1, max_size=10), st.integers(), min_size=1, max_size=10))
def test_canonical_json_is_stable_for_equivalent_mappings(payload: dict[str, int]) -> None:
    reversed_payload = dict(reversed(list(payload.items())))
    assert canonical_json_bytes(payload) == canonical_json_bytes(reversed_payload)


@given(st.binary(min_size=1, max_size=64))
def test_id_changes_when_payload_changes(payload: bytes) -> None:
    deriver = HmacIdDeriver(b"s" * 32)
    first = deriver.derive(namespace="evidence", tenant_id=tenant_id(), canonical_payload=payload)
    second = deriver.derive(
        namespace="evidence", tenant_id=tenant_id(), canonical_payload=payload + b"x"
    )
    assert first != second
