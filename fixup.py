#!/usr/bin/env python3

import sys


if __name__ == "__main__":
    for line in sys.stdin.readlines():
        # take care of escapes
        line = bytes(line, "utf-8").decode("unicode_escape")
        sys.stdout.write(line)
    sys.stdout.write('\n')
