"""
Serialization utilities for handling MongoDB ObjectId and other data types.
"""

from typing import Any, Dict, List, Union
from bson import ObjectId
from datetime import datetime


def convert_objectid_to_str(obj: Any) -> Any:
    """
    Recursively convert ObjectId instances to strings in a data structure.
    
    Args:
        obj: The object to convert (dict, list, or any other type)
        
    Returns:
        The object with ObjectId instances converted to strings
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj


def prepare_user_response(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare user data for API response by removing sensitive fields and converting ObjectIds.
    
    Args:
        user_data: Raw user data from database
        
    Returns:
        Cleaned user data ready for API response
    """
    # Remove sensitive fields
    sensitive_fields = ["hashed_password", "login_attempts", "locked_until"]
    for field in sensitive_fields:
        user_data.pop(field, None)
    
    # Convert ObjectIds to strings
    user_data = convert_objectid_to_str(user_data)
    
    return user_data


def prepare_credential_response(credential_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare credential data for API response by converting ObjectIds.
    
    Args:
        credential_data: Raw credential data from database
        
    Returns:
        Cleaned credential data ready for API response
    """
    return convert_objectid_to_str(credential_data)


def sanitize_response_data(data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Sanitize response data by converting ObjectIds and handling datetime objects.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data ready for JSON serialization
    """
    return convert_objectid_to_str(data)
