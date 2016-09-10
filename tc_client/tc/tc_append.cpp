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

DEFINE_int32(nfiles, 1000, "Number of files");

DEFINE_string(size, "4K", "Append size");

using std::vector;

const size_t kSizeLimit = (8 << 20);

static off_t ConvertSize(const char *size_str)
{
	double size = atof(size_str);
	char unit = size_str[strlen(size_str) - 1];
	off_t scale = 1;
	if (unit == 'k' || unit == 'K') {
		scale <<= 10;
	} else if (unit == 'm' || unit == 'M') {
		scale <<= 20;
	} else if (unit == 'g' || unit == 'G') {
		scale <<= 30;
	}
	return (off_t)(scale * size);
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
				 "/tmp/tc-append-tc.log", 77);
		fprintf(stderr, "Using config file at %s\n", buf);
	} else {
		tcdata = tc_init(NULL, "/tmp/tc-append-posix.log", 0);
	}

	const size_t iosize = ConvertSize(FLAGS_size.c_str());

	vector<tc_iovec> iovs(FLAGS_nfiles);
	for (size_t i = 0; i < iovs.size(); ++i) {
		tc_iovec &iov = iovs[i];
		iov.file = tc_file_from_path(GetFilePath(dir, i));
		iov.offset = TC_OFFSET_END;
		iov.length = iosize;
		iov.data = (char *)malloc(iosize);
		iov.is_creation = true;
		iov.is_eof = false;
	}

	tc_res tcres = tc_writev(iovs.data(), iovs.size(), false);
	if (!tc_okay(tcres)) {
		error(1, tcres.err_no, "failed to append %s",
		      iovs[tcres.index].file.path);
	}

	for (size_t i = 0; i < iovs.size(); ++i) {
		free((char *)iovs[i].file.path);
		free(iovs[i].data);
	}

	tc_deinit(tcdata);
}

int main(int argc, char *argv[])
{
	std::string usage(
	    "This program issues append requests to files.\nUsage: ");
	usage += argv[0];
	usage += "  <dir-path>";
	gflags::SetUsageMessage(usage);
	gflags::ParseCommandLineFlags(&argc, &argv, true);
	Run(argv[1]);
	return 0;
}
