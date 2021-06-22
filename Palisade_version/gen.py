#!/usr/bin/env python3

import sys, os, random

def main():

	n = 4096
	arguments = sys.argv[1:]
	while arguments and arguments[0].startswith("-"):
		arg = arguments.pop(0)
		if arg == '-n':
			n = int(arguments.pop(0))
	

	# Write to plaintext.txt 
	pt = open("plaintext.txt", "w")
	random.seed()
	for _ in range(n):
		pt.write(str(random.randint(0, 2<<28)))
		pt.write("\n")
	pt.close()

if __name__ == '__main__':
	main()
