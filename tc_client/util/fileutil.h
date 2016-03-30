/*
 * Copyright 2014, Stony Brook University
 * by Ming Chen <mchen@cs.stonybrook.edu>
 *
 * File system related utilities.
 */

#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "util/slice.h"

namespace util {

ssize_t GetFileSize(const Slice& file_path);

int GetFileMode(const Slice& file_path);

inline bool IsFile(const Slice& file_path) {
  int mode = GetFileMode(file_path);
  return mode < 0 ? false : S_ISREG(mode);
}

inline bool IsDirectory(const Slice& file_path) {
  int mode = GetFileMode(file_path);
  return mode < 0 ? false : S_ISDIR(mode);
}

// Returns a vector of extents, each of which is a pair of [lower, upper).
// extents will be cleared first
int GetFileExtents(const Slice& file_path,
                   std::vector<std::pair<size_t, size_t>>* extents);

off_t ConvertSize(const char* size_str);

// Returns the opened file descriptor
int CreateFile(const Slice& file_path, bool keep_open);

int CreateFile(const Slice& file_path);

int SyncFileData(const Slice& file_path);

int DeleteFile(const Slice& file_path);

int PunchHole(const Slice& file_path, off_t offset, off_t len);

bool FileExists(const Slice& file_path);

int CreateDir(const Slice& dirname);

int CreateOrUseDir(const Slice& dirname);

int CreateDirRecursively(const Slice& dirpath);

int DeleteDir(const Slice& dirname);

int DeleteDirRecursively(const Slice& dirname);

// list contents in a directory like "ls" does.
// Special item "." and ".." are ignored.
int ListDirectory(const Slice& dir, std::vector<std::string>* result);

ssize_t PWrite(int fd, size_t offset, size_t buflen, const char* buf);
ssize_t PWriteSync(const Slice& file_path, size_t offset, size_t buflen,
                   const char* buf);
ssize_t PWrite(const Slice& file_path, size_t offset, size_t buflen,
               const char* buf);

ssize_t PRead(int fd, size_t offset, size_t buflen, char* buf);
ssize_t PRead(const Slice& file_path, size_t offset, size_t buflen, char* buf);

ssize_t WriteToFile(const Slice& file_path, const Slice& contents,
                    bool sync = false);

ssize_t ReadFromFile(const Slice& file_path, size_t buflen, char* buf);
ssize_t ReadFromFile(const Slice& file_path, std::string* contents);

}  // namespace util

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
