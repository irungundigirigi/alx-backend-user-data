#!/usr/bin/env python3
"""
filter_datum function that returns an obfuscated log message
"""

import re



def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Return an obfuscated log message
    Args:
        fields (list): list of strings to obfuscate
        redaction (str): what the field will be obfuscated to
        message (str): log line to obfuscate
        separator (str): fields delimiter
    """
    for field in fields:
        message = re.sub(field+'=.*?'+separator,
                         field+'='+redaction+separator, message)
    return message

