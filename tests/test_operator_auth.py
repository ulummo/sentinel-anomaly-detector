from sentinel.operator_auth import hash_password, verify_password, new_session

def test_password_hash_is_salted_and_verifiable():
    first=hash_password("a-long-password-123")
    second=hash_password("a-long-password-123")
    assert first!=second
    assert verify_password("a-long-password-123",first)
    assert not verify_password("wrong-password",first)

def test_password_minimum_length():
    import pytest
    with pytest.raises(ValueError):
        hash_password("short")

def test_session_token_is_opaque_and_hashable():
    token,digest=new_session()
    import hashlib
    assert len(token)>=32
    assert digest==hashlib.sha256(token.encode()).hexdigest()
    assert token!=digest
