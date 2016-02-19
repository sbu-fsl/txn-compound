/**
 * Unittest for bench.
 */

#include <gtest/gtest.h>

#include "util/bench.h"

#include <unordered_set>

static int count_unique(int count, const int *values) {
  std::unordered_set<int> uniq_val;
  for (int i = 0; i < count; ++i) {
    uniq_val.insert(values[i]);
  }
  return uniq_val.size();
}

static bool is_about_the_same(long a, long b) {
  return a > (b * 0.9) && a < (b * 1.1);
}

TEST(FileDist, LessLocalityMoreFiles) {
  const int N = 1024;
  int low_locality_values[N];
  int mid_locality_values[N];
  int high_locality_values[N];

  file_dist(N, low_locality_values, 0.1);
  file_dist(N, mid_locality_values, 0.5);
  file_dist(N, high_locality_values, 0.9);

  EXPECT_GT(count_unique(N, low_locality_values),
            count_unique(N, mid_locality_values));
  EXPECT_GT(count_unique(N, mid_locality_values),
            count_unique(N, high_locality_values));
}

TEST(ZipfDist, ZipfBasics) {
  const long N = 4;
  const long M = 2048;
  int counts[N] = {0, 0, 0};
  int values[M];

  zipf_dist(N, 1, M, values);

  for (int i = 0; i < M; ++i) {
    ++counts[values[i]];
  }

  // counts[0] should be about the twice of counts[1]
  EXPECT_TRUE(is_about_the_same(counts[0], 2 * counts[1]));

  // counts[0] should be about the thice of counts[2]
  EXPECT_TRUE(is_about_the_same(counts[0], 3 * counts[2]));

  // counts[0] should be about the four times of counts[3]
  EXPECT_TRUE(is_about_the_same(counts[0], 4 * counts[3]));
}

TEST(ZipfDist, ZipfLocality) {
  const long N = 1024;
  int low_locality_values[N];
  int high_locality_values[N];

  zipf_dist(N, 1, N, low_locality_values);      // s = 1 with low locality
  zipf_dist(N, 4, N, high_locality_values);     // s = 4 with high locality

  EXPECT_GT(count_unique(N, low_locality_values),
            count_unique(N, high_locality_values));
}

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
