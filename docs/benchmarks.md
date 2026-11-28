---
layout: default
title: Benchmarks - HunterX
description: How to run the HunterX benchmark suite and what the numbers mean.
---

# Benchmarks

These figures come from the benchmark suite in `tests/performance`, run on a
single development machine. They describe internal throughput, not detection
rates, and they will vary with your hardware and workload.

## Running the suite

```bash
python -m pytest tests/performance -q
```

The suite covers mission scale (1, 10 and 100 missions), observation scale
(10k, 100k and 1M observations) and large finding/evidence sets.

## Representative figures

| Operation | Throughput |
| --- | --- |
| Correlation | > 100k ops/s |
| DNS resolution | > 2.5M ops/s |
| Confidence computation | > 8M ops/s |

Treat these as order-of-magnitude context. Measure your own workload before
drawing conclusions about performance.

## Related

- [Quality Gates]({{ '/v7-quality-gates/' | relative_url }})
- [PoC & Validation]({{ '/poc-validation/' | relative_url }})