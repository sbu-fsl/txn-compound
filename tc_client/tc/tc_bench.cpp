/**
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "benchmark/benchmark.h"

using namespace benchmark;

static void BM_StringCreation(benchmark::State &state)
{
	  while (state.KeepRunning())
		      std::string empty_string;
}

// Register the function as a benchmark
BENCHMARK(BM_StringCreation);
//
// Define another benchmark
static void BM_StringCopy(benchmark::State &state)
{
	std::string x = "hello";
	while (state.KeepRunning())
		std::string copy(x);
}
BENCHMARK(BM_StringCopy);

BENCHMARK_MAIN();
