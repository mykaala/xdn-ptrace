# XDN: Statediff Capture Benchmark

This repository is part of PhD-candidate Fadhil Kurnia's research focusing on improving edge service delivery networks (XDN), specifically targeting the transparent capture of state differences (statediffs) in non-deterministic web services. The goal is to benchmark various approaches for low-overhead statediff capture without requiring changes to existing web services.

## My Contribution
I have contributed to the benchmark by implementing the **ptrace-based** statediff capture approach. This method hooks into a running process, intercepting I/O system calls to capture the data being written to or read from the filesystem by the web service. The captured state is logged and can be used for state replication or analysis. Additionally, I implemented a feature that benchmarks the performance of the target web service with and without the tracer to measure the overhead introduced by this approach.

## Features
- **ptrace-Based Statediff Capture:** The benchmark intercepts write system calls and logs the data being written to the filesystem by the target web service. This is achieved by attaching a tracer to the running process and capturing the necessary state updates.
- **Performance Comparison:** The benchmark measures and compares the execution time of the target web service with the tracer attached versus running the web service without tracing. This helps quantify the overhead introduced by the tracer.
- **Logging & Persistence:** All state updates captured during the benchmark are logged to /tmp/statediff for later analysis.

## Benchmark Result
The following chart shows the execution time comparison between running the web service with and without the tracer. As seen, the tracer introduces a slight overhead, increasing the execution time from 1.847 ms to 3.489 ms.

![Execution Time Comparison](Execution Time (ms).png)
