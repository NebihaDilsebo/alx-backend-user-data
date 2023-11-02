#!/usr/bin/env python3
"""Protecting PII."""

from typing import List
import re


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Return the log message obfuscated."""
    temp = message
    for field in fields:
        temp = re.sub(field + "=.*?" + separator,
                      field + "=" + redaction + separator, temp)
    return temp
