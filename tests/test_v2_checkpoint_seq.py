"""Tests for checkpoint sequence validation."""

import pytest
from sealrun import validate_checkpoint_seq


def test_validate_checkpoint_seq_valid_zero():
    """Test that zero is accepted."""
    assert validate_checkpoint_seq(0) == 0


def test_validate_checkpoint_seq_valid_positive():
    """Test that positive integers are accepted."""
    assert validate_checkpoint_seq(10) == 10


def test_validate_checkpoint_seq_negative_rejected():
    """Test that negative numbers are rejected."""
    with pytest.raises(ValueError, match="Checkpoint sequence must be non-negative"):
        validate_checkpoint_seq(-1)


def test_validate_checkpoint_seq_bool_rejected():
    """Test that bool is rejected."""
    with pytest.raises(ValueError, match="Checkpoint sequence must be an integer"):
        validate_checkpoint_seq(True)
    
    with pytest.raises(ValueError, match="Checkpoint sequence must be an integer"):
        validate_checkpoint_seq(False)


def test_validate_checkpoint_seq_string_rejected():
    """Test that strings are rejected."""
    with pytest.raises(ValueError, match="Checkpoint sequence must be an integer"):
        validate_checkpoint_seq("5")


def test_validate_checkpoint_seq_float_rejected():
    """Test that floats are rejected."""
    with pytest.raises(ValueError, match="Checkpoint sequence must be an integer"):
        validate_checkpoint_seq(1.5)