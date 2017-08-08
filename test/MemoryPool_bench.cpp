#include "benchmark/benchmark.h"

#include "encfs/MemoryPool.h"

using namespace encfs;

static void BM_MemPoolAllocate(benchmark::State& state) {
  while (state.KeepRunning()) {
    auto block = MemoryPool::allocate(1024);
    MemoryPool::release(block);
  }
}
// Register the function as a benchmark
BENCHMARK(BM_MemPoolAllocate);
