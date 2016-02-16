/**
 * Unittest for bench.
 */

#include <gtest/gtest.h>

#include "util/bench.h"

#include <unordered_set>

TEST(FileDist, LessLocalityMoreFiles) {
  auto count_unique = [] (int count, int *values) {
    std::unordered_set<int> uniq_val;
    for (int i = 0; i < count; ++i) {
      uniq_val.insert(values[i]);
    }
    return uniq_val.size();
  };

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

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
