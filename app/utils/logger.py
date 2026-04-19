"""
Centralized logging configuration.
"""
import logging
import os


def setup_logging():
    """Configure logging for the application."""
    log_level = logging.DEBUG if os.getenv("VPRP_ENV") == "development" else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Quiet noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("streamlit").setLevel(logging.WARNING)
