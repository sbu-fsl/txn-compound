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

/**
 * Generate a sequence of @count values that follows the zipf distribution.  The
 * frequency of elements of rank k is
 *      f(k; s, N) = \frac{1/k^s}{\sum_{n=1}^{N}{1/n^s}}
 * 
 * s should be larger than 0, and a larger s means higher locality.
 */
void zipf_dist(int N, int s, int count, int *values);

#ifdef __cplusplus
}
#endif

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
