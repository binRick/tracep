#!/usr/bin/env python3
# Run a command N times; report avg wall, avg CPU (user+sys) and peak
# child RSS via getrusage(RUSAGE_CHILDREN). ru_maxrss is KB on Linux,
# bytes on macOS — normalised here. Used for the one-shot `ca` mode.
import platform, resource, subprocess, sys, time

n = int(sys.argv[1])
cmd = sys.argv[2:]
mac = platform.system() == "Darwin"

t0 = time.monotonic()
r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
maxrss = 0
for _ in range(n):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    maxrss = max(maxrss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
r1 = resource.getrusage(resource.RUSAGE_CHILDREN)

wall = time.monotonic() - t0
cpu = (r1.ru_utime + r1.ru_stime) - (r0.ru_utime + r0.ru_stime)
rss_mb = (maxrss / 1024.0 if mac else maxrss) / 1024.0
print(f"wall_avg={wall / n * 1000:.1f}ms cpu_avg={cpu / n * 1000:.1f}ms "
      f"peak_rss={rss_mb:.1f}MB")
