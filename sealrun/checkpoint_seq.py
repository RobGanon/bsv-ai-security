"""Helper functions for checkpoint sequence validation."""

def validate_checkpoint_seq(value):
    """Validate that the checkpoint sequence is a non-negative integer.
    
    Args:
        value: The value to validate
        
    Returns:
        The value if it is a valid non-negative integer
        
    Raises:
        ValueError: If the value is not a valid non-negative integer
    """
    # Check if it's an integer type (but not bool, since bool is subclass of int)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Checkpoint sequence must be an integer, got {type(value).__name__}")
    
    # Check if it's non-negative
    if value < 0:
        raise ValueError(f"Checkpoint sequence must be non-negative, got {value}")
        
    return value