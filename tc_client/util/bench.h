#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * For @count files, generate a sequence of @count values that represent an
 * access locality between [0, 1].  The large @locality is, the files are more
 * likely to be accessed repeated.
 */
void file_dist(int count, int *values, double locality);

#ifdef __cplusplus
}
#endif

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
