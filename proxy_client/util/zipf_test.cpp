/**
 * Unittest for zipf_distribution.
 */

#include <gtest/gtest.h>

#include "util/zipf.h"

#include <algorithm>

bool is_about_the_same(long a, long b) {
  return a > (b * 0.9) && a < (b * 1.1);
}

TEST(zipf, Basics) {
  const long SEED = 8887;
  const long N = 4;
  zipf_distribution<long, double> z(N, 1, SEED);

  int counts[N] = {0, 0, 0};
  for (int i = 0; i < 2000; ++i) {
    long v = z();
    EXPECT_GE(v, 0);
    EXPECT_LT(v, N);
    ++counts[v];
  }

  // counts[0] should be about the twice of counts[1]
  EXPECT_TRUE(is_about_the_same(counts[0], 2 * counts[1]));

  // counts[0] should be about the thice of counts[2]
  EXPECT_TRUE(is_about_the_same(counts[0], 3 * counts[2]));

  // counts[0] should be about the four times of counts[3]
  EXPECT_TRUE(is_about_the_same(counts[0], 4 * counts[3]));
}

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
