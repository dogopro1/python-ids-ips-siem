import sys
import os

# Make project root importable so tests can find core/, utils/, etc.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
