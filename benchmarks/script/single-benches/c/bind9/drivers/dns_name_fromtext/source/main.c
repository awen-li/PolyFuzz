/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "fuzz.h"

static inline void
test_one_file(const char *filename) {
	int fd;
	struct stat st;
	char *data;
	ssize_t n;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", filename,
			strerror(errno));
		return;
	}

	if (fstat(fd, &st) != 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", filename,
			strerror(errno));
		goto closefd;
	}

	data = (char *)malloc(st.st_size);
	n = read(fd, data, st.st_size);
	if (n == st.st_size) {
		printf("testing %zd bytes from %s\n", n, filename);
		fflush(stdout);
		LLVMFuzzerTestOneInput((const uint8_t *)data, n);
		fflush(stderr);
	} else {
		if (n < 0) {
			fprintf(stderr,
				"Failed to read %zd bytes from %s: %s\n",
				(ssize_t)st.st_size, filename, strerror(errno));
		} else {
			fprintf(stderr,
				"Failed to read %zd bytes from %s, got %zd\n",
				(ssize_t)st.st_size, filename, n);
		}
	}
	free(data);
closefd:
	close(fd);
}


int
main(int argc, char **argv) {

    if (argc < 2)
    {
        printf ("@@@Please specify the input path!!\r\n");
        return 0;
    }

    (void)LLVMFuzzerInitialize(&argc, &argv);

    test_one_file (argv[1]);
    return 0;
}


