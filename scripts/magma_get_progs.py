#!/usr/bin/env python3
import sys
import re
import os

def main(argv):
	if len(argv) != 2:
		print("Usage: python3 magma_get_progs.py [configrc]", file=sys.stderr)
		return 1
	with open(argv[1], 'r') as fd:
		config = fd.read()
	expr = re.compile("PROGRAMS=\\(([0-9a-zA-Z _\\-\\.]+)\\)")
	arr = []
	for p in re.findall(expr, config):
		arr += filter(lambda s: len(s) > 0, p.split(' '))
	if os.path.basename(os.getenv("TARGET")) == "php":
		arr = map(lambda s : "php-fuzz-" + s, arr)
	print(':'.join(arr))

if __name__ == '__main__':
	exit(main(sys.argv))