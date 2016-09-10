/**
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "path_utils.h"

#include <gflags/gflags.h>

#include <string>
#include <vector>

DEFINE_bool(tc, true, "Use TC implementation");

DEFINE_bool(read, true, "Use TC implementation");

DEFINE_int32(nfiles, 1000, "Number of files");

using std::vector;

const size_t kSizeLimit = (8 << 20);

static off_t GetFileSize(const char *file_path)
{
	struct stat file_status;
	if (tc_stat(file_path, &file_status) < 0) {
		error(1, errno, "Could not get size of %s", file_path);
	}
	return file_status.st_size;
}

static char *GetFilePath(const char *dir, int i)
{
	char *p = (char *)malloc(PATH_MAX);

	if (p) snprintf(p, PATH_MAX, "%s/%04d", dir, i);

	return p;
}

void Run(const char *dir)
{
	void *tcdata;
	if (FLAGS_tc) {
		char buf[PATH_MAX];
		tcdata = tc_init(get_tc_config_file(buf, PATH_MAX),
				 "/tmp/tc-bench-tc.log", 77);
		fprintf(stderr, "Using config file at %s\n", buf);
	} else {
		tcdata = tc_init(NULL, "/tmp/tc-bench-posix.log", 0);
	}

	const size_t file_size = GetFileSize(GetFilePath(dir, 0));
	fprintf(stderr, "Reading files: %zu-byte large\n", file_size);

	size_t files_finished = 0;
	vector<size_t> bytes_finished(FLAGS_nfiles, 0);  // per file
	vector<size_t> bytes_reading(FLAGS_nfiles, 0);  // per file
	const size_t kIoSizeThreshold = 1 << 20;

	char *data = (char *)malloc(kSizeLimit);
	size_t bytes = 0;

	while (files_finished < FLAGS_nfiles) {
		vector<tc_iovec> iovs;

		for (size_t i = files_finished; i < FLAGS_nfiles; ) {
			if (bytes >= kSizeLimit) {
				break;
			}
			if (bytes_finished[i] == file_size) {
				++i;
				continue;
			}
			struct tc_iovec iov;
			size_t iosize = std::min<size_t>(
			    kIoSizeThreshold,
			    file_size - (bytes_finished[i] + bytes_reading[i]));
			iosize = std::min(iosize, kSizeLimit - bytes);

			iov.file = tc_file_from_path(GetFilePath(dir, i));
			iov.offset = bytes_finished[i] + bytes_reading[i];
			iov.length = iosize;
			iov.data = data + bytes;
			iov.is_creation = false;
			iov.is_eof = false;
			iovs.push_back(std::move(iov));

			bytes += iosize;
			bytes_reading[i] += iosize;

			if (bytes_finished[i] + bytes_reading[i] == file_size) {
				++i;
			}
		}

		tc_res tcres;

		if (FLAGS_read) {
			tcres = tc_readv(iovs.data(), iovs.size(), false);
		} else {
			tcres = tc_writev(iovs.data(), iovs.size(), false);
		}

		if (!tc_okay(tcres)) {
			error(1, tcres.err_no, "failed to read %s",
			      iovs[tcres.index].file.path);
		}

		size_t new_files_finished = files_finished;
		for (size_t j = 0; j < iovs.size(); ++j) {
			size_t i = files_finished + j;
			while (bytes_finished[i] == file_size) {
				++i;
			}
			bytes_finished[i] += iovs[j].length;
			if (bytes_finished[i] == file_size &&
			    new_files_finished == i) {
				if (++new_files_finished % 100 == 0) {
					fprintf(stderr, "Finished %zu files\n",
						new_files_finished);
				}
			}
			free((char *)iovs[j].file.path);
			bytes_reading[i] = 0;
		}

		files_finished = new_files_finished;
		bytes = 0;
	}

	free(data);
	tc_deinit(tcdata);
}

int main(int argc, char *argv[])
{
	std::string usage(
	    "This program issues read requests to files.\nUsage: ");
	usage += argv[0];
	usage += "  <dir-path>";
	gflags::SetUsageMessage(usage);
	gflags::ParseCommandLineFlags(&argc, &argv, true);
	Run(argv[1]);
	return 0;
}
