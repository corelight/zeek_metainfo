#!/usr/bin/env python3

import json
import sys


def get_json_records(f):
    records = []
    input_line = 0
    for line in f.readlines():
        input_line += 1
        # I am assuming the message comes on a single line with endlines escaped
        if line[0] == "{":
            # unescape the string
            line = bytes(line, "utf-8").decode("unicode_escape")
            try:
                records.append(json.loads(line))
            except Exception as e:
                sys.stderr.write(f"input line {input_line}: {e}:\n{line}\n")
                raise
    return records


if __name__ == "__main__":
    records = get_json_records(sys.stdin)
    json.dump(records, sys.stdout)
    sys.stdout.write('\n')
