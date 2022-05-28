#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os

def findAllFile(base):
	for root, ds, fs in os.walk(base):
		for f in fs:
			fullname = os.path.join(root, f)
			yield fullname

def parse(content):
	content_list = content.split('\n')
	license_list = [
		'Apache-2.0',
		'BSD-2-Clause',
		'BSD-3-Clause',
		'CDDL-1.0',
		'GCC-exception-2.0',
		'GPL-1.0+',
		'GPL-2.0',
		'GPL-2.0+',
		'GPL-2.0-only',
		'GPL-2.0-or-later',
		'ISC',
		'LGPL-2.0+',
		'LGPL-2.1',
		'LGPL-2.1+',
		'Linux-OpenIB',
		'Linux-syscall-note',
		'MIT',
		'MPL-1.1',
		'X11',
	]

	for i in range(0, len(content_list)):
		if 'SPDX-License-Identifier:' in content_list[i]:
			found = 0
			for j in range(0, len(license_list)):
				if license_list[j] in content_list[i]:
					found = 1
					break

			if found == 0:
				return -1;

	return 0


if __name__ == '__main__':
	base = './kernel/'
	for file in findAllFile(base):
		fd = open(file)
		ret = parse(fd.read())
		fd.close()

		if ret:
			print('%s: license check failed!' %(file))
			exit(1)
