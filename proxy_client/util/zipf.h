// Zipf-Mandelbrot distribution
//
// Let N, s, and e be num, shift, and exp, respectively.  The
// probability distribution is P(k) = (k + s)^{-e} / H_{N,s,e} where k
// = 1, 2, ..., N, and H_{N,s,e} is generalized harmonic number, that
// is H_{N,s,e} = \sum_{i=1}^N (i+s)^{-e}.
//
// http://en.wikipedia.org/wiki/Zipf-Mandelbrot_law.
// 
// Adapted from:
// http://coderepos.org/share/browser/lang/cplusplus/boost-supplement/trunk/boost_supplement/random/zipf_distribution.hpp

#pragma once

#include <assert.h>

#include <random>
#include <vector>

template<typename IntType = long, typename RealType = double>
class zipf_distribution
{
public:
  typedef RealType input_type;
  typedef IntType result_type;

private:
  result_type num_;
  input_type shift_;
  input_type exp_;
  std::mt19937 eng_;

  typedef typename std::discrete_distribution<IntType> dist_type;
  dist_type dist_;

  dist_type make_dist(result_type num, input_type shift, input_type exp)
    {
      std::vector<input_type> buffer(num);
      for (result_type k = 1; k <= num; ++k)
        buffer[k-1] = std::pow(k + shift, -exp);
      return dist_type(buffer.begin(), buffer.end());
    }

public:
  zipf_distribution(result_type num, input_type exp, result_type seed)
    : zipf_distribution(num, 0, exp, seed) {}

  zipf_distribution(result_type num, input_type shift, input_type exp,
		    result_type seed)
    : num_(num), shift_(shift), exp_(exp),
      dist_(make_dist(num, shift, exp)), eng_(seed) {
        assert(exp > 0);
  }

  result_type num() const { return num_; }

  input_type shift() const { return shift_; }

  input_type exponent() const { return exp_; }

  result_type operator()() { return dist_(eng_); }
};

// vim:sw=2:ts=2:tw=80:expandtab:cinoptions=>2,(0\:0:
