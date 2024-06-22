#!/usr/bin/env python3

import sys
import os

def parse_file(file):
	lines = []
	with open(file, 'r') as fd:
		while True:
			line = fd.readline()
			if len(line) == 0:
				break
			line = line.strip()
			assert '|' not in line # TODO: weighted targets
			lines.append(line)
	return list(map(lambda l: l + '|' + str(1 / len(lines)), lines))

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: python3 get_dir_targets.py directory BBtargets.txt", \
			file=sys.stderr)
		exit(1)

	output = []
	for file in os.scandir(sys.argv[1]):
		if file.is_file():
			output += parse_file(file.path)

	with open(sys.argv[2], 'w') as fd:
		fd.write('\n'.join(output) + '\n')

	exit(0)