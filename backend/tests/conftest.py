"""Pytest configuration — adds the hakuna package root to sys.path."""
import sys
import os

# The `hakuna` package lives one level above backend/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
