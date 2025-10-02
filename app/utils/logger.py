"""
Logging utility module for CredHub Backend.
Provides structured logging configuration for the application.
"""

import logging
import sys
from typing import Optional


def setup_logger(name: str = "credhub", level: str = "INFO") -> logging.Logger:
    """
    Setup and configure logger for the application.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers if logger already exists
    if logger.handlers:
        return logger
    
    # Set logging level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Optional logger name. If not provided, returns the main app logger.
    
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"credhub.{name}")
    return logging.getLogger("credhub")


# Create default logger
logger = get_logger()
