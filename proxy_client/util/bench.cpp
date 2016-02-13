#include "util/bench.h"

#include <stdlib.h>

#include <random>
#include <vector>
#include <unordered_set>

const unsigned SEED = 8887;

void file_dist(int count, int *values, double locality) {
  if (locality == 0) {
    for (int i = 0; i < count; ++i) {
      values[i] = i;
    }
  } else if (locality == 1) {
    for (int i = 0; i < count; ++i) {
      values[i] = 0;
    }
  } else {
    std::default_random_engine generator(SEED);
    double stddev = (1 - locality) * count / 10;
    std::normal_distribution<double> distribution(count / 2.0, stddev);
    for (int i = 0; i < count; ++i) {
      values[i] = ((int)abs(distribution(generator))) % count;
    }
  }
}

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
