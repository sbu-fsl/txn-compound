/**
 * Copyright 2014, Stony Brook University
 * by Ming Chen <mchen@cs.stonybrook.edu>
 *
 * Unittest for FileUtils.
 */

#include <string.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utility>
#include <string>
#include <vector>

#include "util/fileutil.h"

constexpr size_t operator"" _b(unsigned long long a) { return a << 12; }

namespace util {
namespace test {

static const char* test_file = "/tmp/file_util_test_file";
static char buf[1_b];

class FileUtilsTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // create a 4KB file
    if (IsFile(test_file)) {
      DeleteFile(test_file);
    }
    memset(buf, '1', 1_b);
    EXPECT_EQ(1_b, WriteToFile(test_file, Slice(buf, 1_b)));
    EXPECT_EQ(1_b, GetFileSize(test_file));
  }

  virtual void TearDown() {
  }
};

TEST_F(FileUtilsTest, ReadFromFileWorks) {
  char buf2[1_b];
  EXPECT_EQ(1_b, ReadFromFile(test_file, 1_b, buf2));
  EXPECT_EQ(0, memcmp(buf, buf2, 1_b));
}

TEST_F(FileUtilsTest, PWriteCanExtendFile) {
  EXPECT_EQ(1_b, PWrite(test_file, 2_b, 1_b, buf));
  EXPECT_EQ(3_b, GetFileSize(test_file));

  EXPECT_EQ(1_b, PWrite(test_file, 5_b, 1_b, buf));
  EXPECT_EQ(6_b, GetFileSize(test_file));
}

TEST_F(FileUtilsTest, GetFileExtentsBasics) {
  std::vector<std::pair<uint64_t, uint64_t>> extents;
  extents.push_back(std::make_pair(0, 1_b));

  std::vector<std::pair<uint64_t, uint64_t>> found;
  EXPECT_EQ(1, GetFileExtents(test_file, &found));
  EXPECT_EQ(extents, found);

  // create a hole at [1_b, 2_b)
  EXPECT_EQ(1_b, PWrite(test_file, 2_b, 1_b, buf));
  extents.push_back(std::make_pair(2_b, 3_b));
  EXPECT_EQ(2, GetFileExtents(test_file, &found));
  EXPECT_EQ(extents, found);

  // create another hole at [3_b, 5_b)
  EXPECT_EQ(1_b, PWrite(test_file, 5_b, 1_b, buf));
  extents.push_back(std::make_pair(5_b, 6_b));
  EXPECT_EQ(3, GetFileExtents(test_file, &found));
  EXPECT_EQ(extents, found);
}

TEST_F(FileUtilsTest, GetFileExtentsWorksWhenFileBeginsWithAHole) {
  const char* hole_file = "/tmp/a-file-begin-with-a-hole";
  EXPECT_EQ(0, CreateFile(hole_file));
  EXPECT_EQ(1_b, PWrite(hole_file, 1_b, 1_b, buf));
  EXPECT_EQ(2_b, GetFileSize(hole_file));

  std::vector<std::pair<uint64_t, uint64_t>> extents;
  EXPECT_EQ(1, GetFileExtents(hole_file, &extents));
  EXPECT_EQ(std::make_pair(1_b, 2_b), extents[0]);
  DeleteFile(hole_file);
}

TEST_F(FileUtilsTest, ListDirectoryWorks) {
  EXPECT_EQ(0, CreateDir("/tmp/fileutil_test_dir/"));
  EXPECT_EQ(0, CreateFile("/tmp/fileutil_test_dir/aa"));
  EXPECT_EQ(0, CreateFile("/tmp/fileutil_test_dir/bb"));
  std::vector<std::string> contents;
  EXPECT_EQ(0, ListDirectory("/tmp/fileutil_test_dir", &contents));
  std::vector<std::string> expected = {"aa", "bb"};
  EXPECT_THAT(contents, ::testing::WhenSorted(expected));
  EXPECT_EQ(0, DeleteDirRecursively("/tmp/fileutil_test_dir"));
}

TEST_F(FileUtilsTest, RecursiveCreateWorks) {
  EXPECT_EQ(0, CreateDirRecursively("/tmp/RecursiveCreateWorks/dir1"));
  EXPECT_EQ(0, CreateDirRecursively("/tmp/RecursiveCreateWorks/dir1/dir2/"));
  std::vector<std::string> contents;
  EXPECT_EQ(0, ListDirectory("/tmp/RecursiveCreateWorks", &contents));
  EXPECT_EQ("dir1", contents[0]);
  EXPECT_EQ(0, ListDirectory("/tmp/RecursiveCreateWorks/dir1", &contents));
  EXPECT_EQ("dir2", contents[0]);

  EXPECT_EQ(0, CreateDirRecursively("/tmp/RecursiveCreateWorks2/1/2/3/4"));
  EXPECT_EQ(0, ListDirectory("/tmp/RecursiveCreateWorks2/1/2/3", &contents));
  EXPECT_EQ("4", contents[0]);
}

TEST_F(FileUtilsTest, PunchHoleBasics) {
  EXPECT_EQ(1_b, PWrite(test_file, 1_b, 1_b, buf));
  EXPECT_EQ(1_b, PWrite(test_file, 2_b, 1_b, buf));

  EXPECT_EQ(0, PunchHole(test_file, 1_b, 1_b));
  std::vector<std::pair<uint64_t, uint64_t>> found;
  EXPECT_EQ(2, GetFileExtents(test_file, &found));
  EXPECT_EQ(std::make_pair(0UL, 1_b), found[0]);
  EXPECT_EQ(std::make_pair(2_b, 3_b), found[1]);
}

// What is the result if we punch hole at the place that is already a hole?
TEST_F(FileUtilsTest, PunchHoleOnFileHoles) {
  std::vector<std::pair<uint64_t, uint64_t>> found;
  EXPECT_EQ(1_b, PWrite(test_file, 1_b, 1_b, buf));
  EXPECT_EQ(1_b, PWrite(test_file, 2_b, 1_b, buf));
  EXPECT_EQ(1, GetFileExtents(test_file, &found));

  EXPECT_EQ(0, PunchHole(test_file, 1_b, 1_b));
  EXPECT_EQ(2, GetFileExtents(test_file, &found));

  EXPECT_EQ(0, PunchHole(test_file, 0_b, 2_b));
  EXPECT_EQ(1, GetFileExtents(test_file, &found));

  EXPECT_EQ(0, PunchHole(test_file, 1_b, 2_b));
  EXPECT_EQ(0, GetFileExtents(test_file, &found));
}

TEST_F(FileUtilsTest, PunchHoleBeyongFileSize) {
  EXPECT_EQ(1_b, GetFileSize(test_file));
  EXPECT_EQ(0, PunchHole(test_file, 0, 2_b));
  EXPECT_EQ(1_b, GetFileSize(test_file));
  std::vector<std::pair<uint64_t, uint64_t>> found;
  EXPECT_EQ(0, GetFileExtents(test_file, &found));
}

TEST_F(FileUtilsTest, NonexistingPathIsNotAFileOrDirectory) {
  EXPECT_FALSE(IsFile("/tmp/some/nonexisting/path"));
  EXPECT_FALSE(IsDirectory("/tmp/some/nonexisting/path"));
}

}  // namespace test
}  // namespace util

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
