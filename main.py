#!/usr/bin/env python3

import time
import sys

import bcc

def main(iface):
	prog = bcc.BPF(src_file="prog.c")
	func = prog.load_func("prog", bcc.BPF.XDP)

	try:
		prog.attach_xdp(iface, func, 0)
		print(f"attached to {iface}, wait 60s or ^C")
		time.sleep(60.0)
	finally:
		prog.remove_xdp(iface)

		print("counter state:")
		map = prog[b"counter"]
		for i in range(len(map)):
			if map[i].value != 0:
				print(f"[{i}] = {map[i].value}")


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print(f"usage: {sys.argv[0]} iface")
		sys.exit(1)

	main(sys.argv[1])
