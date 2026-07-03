import logging
import sys

def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Configures and returns a standardized logger for the recon tool.
    If verbose is True, set level to DEBUG, otherwise set to INFO.
    """
    logger = logging.getLogger("recon_tool")
    
    # Prevent duplicate log messages if logger is initialized multiple times
    if logger.hasHandlers():
        return logger

    # Determine log level based on verbosity flag
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)

    # Create console handler to output logs to terminal
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Define a clean, scannable format: [TIMESTAMP] [LEVEL] MESSAGE
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    # Add handler to the logger
    logger.addHandler(console_handler)
    
    return logger
