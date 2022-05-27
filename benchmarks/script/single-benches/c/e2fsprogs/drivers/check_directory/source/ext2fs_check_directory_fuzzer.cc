// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char* fname = "/tmp/ext2_test_file";

  // Write our data to a temp file.
  int fd = open(fname, O_RDWR|O_CREAT|O_TRUNC, 0600);
  write(fd, data, size);
  close(fd);

  ext2_filsys fs;
  errcode_t retval = ext2fs_open(
      fname,
      0, 0, 0,
      unix_io_manager,
      &fs);

  if (!retval) {
    retval = ext2fs_check_directory(fs, EXT2_ROOT_INO);
    ext2fs_close(fs);
  }

  return 0;
}

extern "C" inline void
test_one_file(const char *filename) {
	int fd;
	struct stat st;
	char *data;
	ssize_t n;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		return;
	}

	if (fstat(fd, &st) != 0) {
		goto closefd;
	}

	data = (char *)malloc(st.st_size);
	n = read(fd, data, st.st_size);
	if (n == st.st_size) {
		fflush(stdout);
		LLVMFuzzerTestOneInput((const uint8_t *)data, n);
		fflush(stderr);
	}
	free(data);
closefd:
	close(fd);
}


extern "C" int
main(int argc, char **argv) {

    if (argc < 2)
    {
        printf ("@@@Please specify the input path!!\r\n");
        return 0;
    }

    test_one_file (argv[1]);
    return 0;
}

