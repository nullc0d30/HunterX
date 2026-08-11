# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secret / credential storage tests (Sprint 034.3 §22).

Secrets must never be persisted in plaintext by the TIDB: the security material
entities store masked values and hashes only, and the masking utilities are
used at the storage boundary.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    APIKey,
    Credential,
    IntelligenceEvidenceRecord,
    JSIntelligenceSecret,
    Secret,
    Token,
)
from hunterx.shared.masking import mask_secret, mask_secrets_in_mapping

pytest.importorskip("sqlalchemy")


def test_masking_never_returns_plaintext() -> None:
    secret = "sk-live-0123456789abcdef"
    masked = mask_secret(secret)
    assert masked != secret
    assert secret not in masked
    assert masked.startswith("s") and masked.endswith("f")
    assert "*" in masked

    mapping = {"api_key": "AKIAIOSFODNN7EXAMPLE", "bearer": "eyJhbGciOi"}
    masked_mapping = mask_secrets_in_mapping(mapping)
    assert masked_mapping["api_key"] != mapping["api_key"]
    assert mapping["api_key"] not in masked_mapping["api_key"]
    assert masked_mapping["bearer"] != mapping["bearer"]


def test_secret_entity_stores_masked_value_not_plaintext(sql_factory) -> None:
    repo = sql_factory.repository_for(Secret)
    plaintext = "hunterx-super-secret-token-123456"
    secret = Secret(
        name="stripe_live",
        kind="api_token",
        value_masked=mask_secret(plaintext),
        checksum="sha256:abc123",
        secret_key="secrets/stripe_live",
        owner="certification",
        scope="prod",
    )
    repo.save(secret)

    loaded = repo.get(secret.id)
    assert loaded is not None
    assert plaintext not in loaded.value_masked
    assert loaded.value_masked == mask_secret(plaintext)
    assert loaded.checksum == "sha256:abc123"


def test_api_key_and_token_store_only_hashes(sql_factory) -> None:
    key_repo = sql_factory.repository_for(APIKey)
    token_repo = sql_factory.repository_for(Token)

    key = APIKey(name="ci-key", key_hash="sha256:deadbeef", secret_id="s1")
    token = Token(kind="bearer", token_hash="sha256:cafebabe", secret_id="s1")
    key_repo.save(key)
    token_repo.save(token)

    loaded_key = key_repo.get(key.id)
    loaded_token = token_repo.get(token.id)
    assert loaded_key is not None and loaded_key.key_hash == "sha256:deadbeef"
    assert loaded_token is not None and loaded_token.token_hash == "sha256:cafebabe"
    # No plaintext column exists on these entities.
    assert not hasattr(loaded_key, "key_value")
    assert not hasattr(loaded_token, "token_value")


def test_credential_references_secret_not_plaintext(sql_factory) -> None:
    cred_repo = sql_factory.repository_for(Credential)
    credential = Credential(
        username="svc-account",
        secret_id="s1",
        realm="auth0",
        attrs={"rotation": "90d"},
    )
    cred_repo.save(credential)

    loaded = cred_repo.get(credential.id)
    assert loaded is not None
    assert loaded.secret_id == "s1"
    # No password column; the secret is referenced by id only.
    assert not hasattr(loaded, "password")


def test_javascript_secret_is_masked_and_hashed(sql_factory) -> None:
    repo = sql_factory.repository_for(JSIntelligenceSecret)
    raw = "AKIAIOSFODNN7EXAMPLE"
    record = JSIntelligenceSecret(
        classification="secret",
        masked_value=mask_secret(raw),
        value_hash="sha256:abc",
        location="https://example.com/app.js",
        file="app.js",
        detection_rule="aws-access-key",
        confidence=0.99,
        asset_url="https://example.com/app.js",
        mission_id="mis-1",
    )
    repo.save(record)

    loaded = repo.get(record.id)
    assert loaded is not None
    assert raw not in loaded.masked_value
    assert loaded.value_hash == "sha256:abc"
    assert loaded.mission_id == "mis-1"


def test_evidence_does_not_leak_secrets_into_database(sql_factory) -> None:
    """Evidence records store artifact references and observations, not inline
    credential material; a secret-like string must never be persisted verbatim
    as an evidence value in a documented secret field."""
    repo = sql_factory.repository_for(IntelligenceEvidenceRecord)
    secret_like = "Authorization: Bearer sk-live-0123456789"
    evidence = IntelligenceEvidenceRecord(
        evidence_id="ev-sec",
        target_id="tgt-1",
        mission_id="mis-1",
        what="authentication header observed",
        where="https://example.com/admin",
        how="passive capture",
        source="httpx",
        tool="httpx",
        raw_artifact_ref="artifacts/mis-1/httpx/out.json",
        command_configuration={"redacted": True, "authorization": mask_secret(secret_like)},
    )
    repo.save(evidence)

    loaded = repo.get(evidence.id)
    assert loaded is not None
    assert secret_like not in loaded.command_configuration["authorization"]
