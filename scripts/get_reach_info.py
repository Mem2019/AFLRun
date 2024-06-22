#!/usr/bin/env python3
import sys
import os
from parse_temp import read_header

if __name__ == '__main__':
	if len(sys.argv) < 2 or len(sys.argv) > 3:
		print("Usage: python3 get_reach_info.py [temp dir] (-b)", \
			file=sys.stderr)
		exit(1)
	bb = os.path.join(sys.argv[1], "BBreachable.txt")
	func = os.path.join(sys.argv[1], "Freachable.txt")

	t, r = read_header(bb)
	_, fr = read_header(func)

	if len(sys.argv) == 3 and sys.argv[2] == "-b":
		print(("export __AFLRUN_NUM_TARGETS=%u " + \
			"__AFLRUN_NUM_REACHES=%u " + \
			"__AFLRUN_NUM_FREACHES=%u") % (t, r, fr))
	else:
		print(("export __AFLRUN_NUM_TARGETS=%u " + \
			"__AFLRUN_NUM_REACHES=%u " + \
			"__AFLRUN_NUM_FREACHES=%u # %s") % (t, r, fr, sys.argv[1]))

	exit(0)