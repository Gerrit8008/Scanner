# logging_utils.py
import functools
import logging
import time
import traceback

def log_function_call(func):
    """Decorator to log function calls with parameters and return values"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        
        # Log function entry
        args_repr = [repr(a) for a in args]
        kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
        signature = ", ".join(args_repr + kwargs_repr)
        logger.debug(f"Calling {func.__name__}({signature})")
        
        try:
            # Call the function
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            # Log successful completion
            logger.debug(f"Completed {func.__name__} in {execution_time:.4f} seconds")
            return result
        except Exception as e:
            # Log exception details
            logger.error(f"Exception in {func.__name__}: {str(e)}")
            logger.debug(f"Exception traceback: {traceback.format_exc()}")
            raise  # Re-raise the exception
    
    return wrapper
