/*
 * Copyright 2014, Stony Brook University
 * by Ming Chen <mchen@cs.stonybrook.edu>
 *
 * File system related utilities.
 */

#include "util/fileutil.h"

#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <string>
#include <utility>
#include <vector>

namespace util {

namespace {
class FileCloser {
 public:
  explicit FileCloser(int fd) : fd_(fd) {}
  ~FileCloser() { close(fd_); }

 private:
  int fd_;
};
}  // anonymous namespace

int GetFileExtents(const Slice& file_path,
                   std::vector<std::pair<uint64_t, uint64_t>>* extents) {
  ssize_t file_size = GetFileSize(file_path);
  if (file_size < 0) {
    return file_size;
  }

  int fd = open(file_path.data(), O_RDONLY);
  FileCloser closer(fd);

  extents->clear();

  // find the first data extent
  uint64_t scanned = 0;
  int i = 0;
  for (; scanned < file_size; ++i) {
    off_t begin = lseek(fd, scanned, SEEK_DATA);
    if (begin == ((off_t) -1)) {
      if (errno == ENXIO) {
        break;
      } else {
        error(0, errno, "could not seek data of %s", file_path.data());
        return -errno;
      }
    }
    off_t end = lseek(fd, begin, SEEK_HOLE);
    if (end == ((off_t) -1)) {
      if (errno == ENXIO) {
        break;
      } else {
        error(0, errno, "could not seek hole of %s", file_path.data());
        return -errno;
      }
    }
    extents->push_back(std::make_pair(begin, end));
    scanned = end;
  }

  return i;
}

ssize_t GetFileSize(const Slice& file_path) {
  struct stat file_status;
  if (stat(file_path.data(), &file_status) < 0) {
    error(0, errno, "Could not get size of %s", file_path.data());
    return -errno;
  }
  return file_status.st_size;
}

int GetFileMode(const Slice& file_path) {
  struct stat file_status;
  if (stat(file_path.data(), &file_status) < 0) {
    error(0, errno, "Could not stat %s", file_path.data());
    return -errno;
  }
  return file_status.st_mode;
}


off_t ConvertSize(const char* size_str) {
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

ssize_t PWrite(int fd, size_t offset, size_t buflen, const char* buf) {
  size_t written = 0;
  while (written < buflen) {
    ssize_t n = 0;
    if ((n = pwrite(fd, buf + written, buflen - written, offset + written)) <
        0) {
      error(0, errno, "pwrite of file %d failed at [%zu, %zu)", fd,
            offset + written, offset + buflen);
      return n;
    }
    written += n;
  }
  return written;
}

static ssize_t PWriteImpl(const Slice& file_path, size_t offset, size_t buflen,
                          const char* buf, int flags) {
  int fd = open(file_path.data(), flags);
  if (fd < 0) {
    error(0, errno, "cannot open file %s for writing", file_path.data());
    return -errno;
  }
  ssize_t ret = PWrite(fd, offset, buflen, buf);
  if (close(fd) < 0) {
    error(0, errno, "failed to close file %s after writing", file_path.data());
    return -errno;
  }
  return ret;
}

ssize_t PWrite(const Slice& file_path, size_t offset, size_t buflen,
               const char* buf) {
  return PWriteImpl(file_path, offset, buflen, buf, O_WRONLY);
}

ssize_t PWriteSync(const Slice& file_path, size_t offset, size_t buflen, const
                   char* buf) {
  return PWriteImpl(file_path, offset, buflen, buf, O_WRONLY | O_SYNC);
}

int SyncFileData(const Slice& file_path) {
  int fd = open(file_path.data(), O_WRONLY);
  if (fd < 0) {
    error(0, errno, "cannot open %s for fdatasync", file_path.data());
    return -errno;
  }
  FileCloser closer(fd);
  if (fdatasync(fd) < 0) {
    error(0, errno, "fdatasync of %s failed", file_path.data());
    return -errno;
  }
  return 0;
}

int DeleteFile(const Slice& file_path) {
  if (unlink(file_path.data()) != 0) {
    error(0, errno, "could not delete %s", file_path.data());
    return -errno;
  }
  return 0;
}

int PunchHole(const Slice& file_path, off_t offset, off_t len) {
  int fd = open(file_path.data(), O_WRONLY);
  if (fd < 0) {
    error(0, errno, "cannot open %s to punch holes", file_path.data());
    return -errno;
  }
  FileCloser closer(fd);
  if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, len) <
      0) {
    error(0, errno, "failed to punch hole in %s", file_path.data());
    return -errno;
  }
  return 0;
}

int ListDirectory(const Slice& dir, std::vector<std::string>* result) {
  result->clear();
  DIR* d = opendir(dir.data());
  if (d == NULL) {
    error(0, errno, "could not open directory %s", dir.data());
    return -errno;
  }
  struct dirent* entry;
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") !=0 && strcmp(entry->d_name, "..") != 0)
      result->push_back(entry->d_name);
  }
  closedir(d);
  return 0;
}

ssize_t PRead(int fd, size_t offset, size_t buflen, char* buf) {
  size_t nread = 0;
  while (nread < buflen) {
    ssize_t n = 0;
    if ((n = pread(fd, buf + nread, buflen - nread, offset + nread)) <= 0) {
      error(0, errno, "pread of file %d failed at [%zu, %zu)", fd,
            offset + nread, offset + buflen);
      return n;
    }
    nread += n;
  }
  return nread;
}

ssize_t PRead(const Slice& file_path, size_t offset, size_t buflen, char* buf) {
  int fd = open(file_path.data(), O_RDONLY);
  if (fd < 0) {
    error(0, errno, "cannot open file %s for reading", file_path.data());
    return -errno;
  }
  ssize_t ret = PRead(fd, offset, buflen, buf);
  close(fd);
  return ret;
}

int CreateFile(const Slice& file_path, bool keep_open) {
  static const int filemode = S_IRUSR | S_IWUSR | S_IRGRP;
  int fd = open(file_path.data(), O_CREAT | O_RDWR | O_EXCL, filemode);
  if (fd < 0) {
    error(0, errno, "cannot create file %s", file_path.data());
    return -errno;
  }
  if (!keep_open && (close(fd) < 0)) {
    error(1, errno, "cannot close file");
  }
  return fd;
}

int CreateFile(const Slice& file_path) {
  int ret = CreateFile(file_path, false);
  return ret >= 0 ? 0 : ret;
}

bool FileExists(const Slice& file_path) {
  return access(file_path.data(), F_OK) == 0;
}

int CreateDir(const Slice& dirname) {
  int ret = 0;
  if (mkdir(dirname.data(), 0755) != 0) {
    error(0, errno, "cannot create directory %s", dirname.data());
    ret = -errno;
  }
  return ret;
}

int CreateOrUseDir(const Slice& dirpath) {
  int ret = 0;
  if (FileExists(dirpath)) {
     if (!IsDirectory(dirpath)) {
       error(0, EINVAL, "%s is not a directory", dirpath.data());
       ret = -EINVAL;
     }
  } else {
    ret = CreateDir(dirpath);
  }
  return ret;
}

int CreateDirRecursively(const Slice& dirpath) {
  int ret = 0;
  if (dirpath[0] != '/') {
    error(0, EINVAL, "dirpath of CreateDirRecursively not starts with '/': %s",
          dirpath.data());
    return -EINVAL;
  }
  for (size_t i = 1; i < dirpath.size(); ++i) {
    if (dirpath[i] == '/') {
      std::string prefix(dirpath.data(), i);
      if ((ret = CreateOrUseDir(prefix)) != 0) {
        return ret;
      }
    }
  }
  if (dirpath[dirpath.size() - 1] != '/') {
    ret = CreateOrUseDir(dirpath);
  }
  return ret;
}

int DeleteDir(const Slice& dirname) {
  int ret = 0;
  if (rmdir(dirname.data()) != 0) {
    error(0, errno, "cannot delete directory %s", dirname.data());
    ret = -errno;
  }
  return ret;
}

int DeleteDirRecursively(const Slice& dirname) {
  std::vector<std::string> contents;
  int ret = 0;
  if ((ret = ListDirectory(dirname, &contents)) != 0) {
    error(0, -ret, "DeleteDirRecursively: cannot list contents");
    return ret;
  }
  for (const auto& subname : contents) {
    std::string path = dirname.ToString() + "/" + subname;
    if (IsFile(path)) {
      ret = DeleteFile(path);
    } else {
      ret = DeleteDirRecursively(path);
    }
    if (ret != 0) {
      error(0, -ret, "DeleteDirRecursively: cannot delete content");
      return ret;
    }
  }
  return DeleteDir(dirname);
}

ssize_t WriteToFile(const Slice& file_path, const Slice& contents, bool sync) {
  // 1. write to a temp file if the target file already exists
  std::string temp_path = file_path.ToString();
  ssize_t fd;

  while (true) {
    fd = CreateFile(temp_path, true);
    if (fd == -EEXIST) {
      // append with "x" and retry
      temp_path += "x";
    } else if (fd < 0) {
      error(0, -fd, "WriteToFile(): cannot create file %s", file_path.data());
      return fd;
    } else {
      break;
    }
  }

  ssize_t ret = PWrite(fd, 0, contents.size(), contents.data());
  if (ret < 0) {
    close(fd);
    return ret;
  }

  if (sync && fsync(fd) < 0) {
    error(0, errno, "fsync of %s failed", file_path.data());
    close(fd);
    return -errno;
  }

  // Close the file and make it visible.
  if (close(fd) < 0) {
    error(0, errno, "failed to close temp file %s", temp_path.data());
    return -errno;
  }

  if (file_path == temp_path)
    return ret;

  // 2. rename the temp file to the target file
  if (rename(temp_path.data(), file_path.data()) != 0) {
    error(0, errno, "WriteToFile(): cannot rename %s to %s", temp_path.data(),
          file_path.data());
    return -errno;
  }

  return ret;
}

ssize_t ReadFromFile(const Slice& file_path, size_t buflen, char* buf) {
  int fd = open(file_path.data(), O_RDONLY);
  if (fd < 0) {
    error(0, errno, "cannot open file %s for reading", file_path.data());
    return -errno;
  }

  ssize_t ret = PRead(fd, 0, buflen, buf);
  close(fd);
  return ret;
}

ssize_t ReadFromFile(const Slice& file_path, std::string* contents) {
  ssize_t filesize = GetFileSize(file_path.data());
  if (filesize > (1 << 20)) {
    error(0, EIO, "file too large to be loaded efficiently with ReadFromFile");
    return -EIO;
  }

  contents->resize(filesize);
  return ReadFromFile(file_path, filesize, &(*contents)[0]);
}

}  // namespace util

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
