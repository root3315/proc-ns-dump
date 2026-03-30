# proc-ns-dump

Quick utility to dump Linux process namespace info. I wrote this because I kept forgetting how to inspect what namespaces a process is in without typing out a bunch of `ls -la /proc/$pid/ns/` commands.

## What it does

Reads `/proc/[pid]/ns/` for running processes and shows you:
- Which namespaces each process belongs to
- The inode numbers (useful for finding processes in the same namespace)
- Process name and cmdline for context

## Quick start

```bash
# Show all processes and their namespaces
python3 proc_ns_dump.py

# Check a specific PID
python3 proc_ns_dump.py -p 1234

# Only care about network and PID namespaces
python3 proc_ns_dump.py -n net,pid

# Get a summary of namespace sharing
python3 proc_ns_dump.py -f summary

# JSON output for scripting
python3 proc_ns_dump.py -f json
```

## Output formats

**Table** (default) - Human readable, shows PID, name, namespace type, inode, and symlink target.

**Summary** - Groups processes by namespace, useful for seeing which processes share namespaces (containers, etc).

**JSON** - Parse it yourself, do what you want.

## Finding shared namespaces

Use `--find-shared` to quickly see which namespaces have multiple processes:

```bash
$ python3 proc_ns_dump.py --find-shared
Shared Namespaces:
------------------------------------------------------------
net:4026532045: 3 processes
  PIDs: [1, 502, 1847]
pid:4026532047: 2 processes
  PIDs: [502, 1847]
```

This is handy for debugging container setups or figuring out why two processes can see each other's network/interfaces.

## Namespace types covered

- cgroup
- ipc
- mnt
- net
- pid
- pid_for_children
- time
- time_for_children
- user
- uts

Not all kernels support all types. The script handles missing namespaces gracefully.

## Why I built this

Mainly for debugging container stuff. When you're messing with podman/docker/namespace isolation, it's useful to quickly verify:
- Are these two processes in the same network namespace?
- How many processes share this PID namespace?
- What's the actual inode number (for comparing across systems)?

Also faster than typing `readlink /proc/*/ns/*` every time.

## Requirements

- Python 3.6+
- Linux (obviously, needs /proc)
- Root helps but not required (you'll see what you have permission to see)

## Notes

- Some namespaces might show as unavailable if you don't have permission
- Kernel threads show up with `[kernel thread]` cmdline
- The inode numbers are what matter for determining if processes share a namespace
