#!/usr/bin/env python3
"""
proc-ns-dump: Dump Linux process namespace information.

This utility reads namespace information from /proc/[pid]/ns/
and presents it in a human-readable format.
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

PROC_ROOT = Path("/proc")
NAMESPACE_TYPES = [
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts",
]


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    
    # Namespace-specific colors
    NS_COLORS = {
        "cgroup": BRIGHT_MAGENTA,
        "ipc": BRIGHT_CYAN,
        "mnt": BRIGHT_YELLOW,
        "net": BRIGHT_GREEN,
        "pid": BRIGHT_RED,
        "pid_for_children": RED,
        "time": BRIGHT_BLUE,
        "time_for_children": BLUE,
        "user": MAGENTA,
        "uts": CYAN,
    }
    
    @classmethod
    def disable(cls):
        """Disable all colors."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.BLACK = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BRIGHT_RED = ""
        cls.BRIGHT_GREEN = ""
        cls.BRIGHT_YELLOW = ""
        cls.BRIGHT_BLUE = ""
        cls.BRIGHT_MAGENTA = ""
        cls.BRIGHT_CYAN = ""
        for key in cls.NS_COLORS:
            cls.NS_COLORS[key] = ""


def supports_color():
    """Check if the terminal supports color output."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return True


def get_process_list():
    """Get list of all running process PIDs."""
    pids = []
    try:
        for entry in PROC_ROOT.iterdir():
            if entry.name.isdigit():
                pids.append(int(entry.name))
    except PermissionError:
        pass
    return sorted(pids)


def get_process_cmdline(pid):
    """Read the command line for a given PID."""
    cmdline_path = PROC_ROOT / str(pid) / "cmdline"
    try:
        with open(cmdline_path, "r", encoding="utf-8", errors="replace") as f:
            cmdline = f.read().replace("\x00", " ").strip()
            if not cmdline:
                cmdline = "[kernel thread]"
            return cmdline[:80]
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return "[unavailable]"


def get_process_name(pid):
    """Read the process name from /proc/[pid]/comm."""
    comm_path = PROC_ROOT / str(pid) / "comm"
    try:
        with open(comm_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return "[unknown]"


def get_namespace_inode(pid, ns_type):
    """Get the namespace inode for a specific namespace type."""
    ns_path = PROC_ROOT / str(pid) / "ns" / ns_type
    try:
        stat_info = os.stat(ns_path)
        return stat_info.st_ino
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None


def get_namespace_link(pid, ns_type):
    """Read the namespace symlink target."""
    ns_path = PROC_ROOT / str(pid) / "ns" / ns_type
    try:
        target = os.readlink(ns_path)
        return target
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None


def dump_single_process(pid, show_all_ns=False):
    """Dump namespace information for a single process."""
    result = {
        "pid": pid,
        "name": get_process_name(pid),
        "cmdline": get_process_cmdline(pid),
        "namespaces": {},
    }

    for ns_type in NAMESPACE_TYPES:
        inode = get_namespace_inode(pid, ns_type)
        link = get_namespace_link(pid, ns_type)
        if inode is not None:
            result["namespaces"][ns_type] = {
                "inode": inode,
                "link": link,
            }
        elif show_all_ns:
            result["namespaces"][ns_type] = {
                "inode": None,
                "link": None,
            }

    return result


def group_by_namespace(processes_data, ns_type):
    """Group processes by their namespace inode for a specific namespace type."""
    groups = {}
    for proc in processes_data:
        pid = proc["pid"]
        ns_info = proc["namespaces"].get(ns_type, {})
        inode = ns_info.get("inode")
        if inode is not None:
            if inode not in groups:
                groups[inode] = []
            groups[inode].append(pid)
    return groups


def colorize_ns(ns_type, text):
    """Apply namespace-specific color to text."""
    color = Colors.NS_COLORS.get(ns_type, Colors.WHITE)
    return f"{color}{text}{Colors.RESET}"


def format_output(processes_data, output_format="table", use_color=False):
    """Format the output based on the requested format."""
    if output_format == "json":
        import json
        return json.dumps(processes_data, indent=2)

    if output_format == "table":
        lines = []
        
        header = f"{'PID':<8} {'NAME':<20} {'NAMESPACE':<15} {'INODE':<20} {'LINK'}"
        if use_color:
            header = f"{Colors.BOLD}{header}{Colors.RESET}"
        
        lines.append(f"{Colors.DIM}{'=' * 100}{Colors.RESET}")
        lines.append(header)
        lines.append(f"{Colors.DIM}{'=' * 100}{Colors.RESET}")

        for proc in processes_data:
            pid = proc["pid"]
            name = proc["name"]
            for ns_type, ns_info in sorted(proc["namespaces"].items()):
                inode = ns_info["inode"]
                link = ns_info["link"] or ""
                if inode is not None:
                    inode_str = f"{ns_type}:{inode}"
                    if use_color:
                        ns_colored = colorize_ns(ns_type, ns_type)
                        inode_colored = colorize_ns(ns_type, inode_str)
                        pid_colored = f"{Colors.CYAN}{pid}{Colors.RESET}"
                        line = f"{pid_colored:<8} {name:<20} {ns_colored:<15} {inode_colored:<20} {Colors.DIM}{link}{Colors.RESET}"
                    else:
                        line = f"{pid:<8} {name:<20} {ns_type:<15} {inode_str:<20} {link}"
                    lines.append(line)

        lines.append(f"{Colors.DIM}{'=' * 100}{Colors.RESET}")
        return "\n".join(lines)

    if output_format == "summary":
        lines = []
        title = "Process Namespace Summary"
        if use_color:
            title = f"{Colors.BOLD}{Colors.BRIGHT_BLUE}{title}{Colors.RESET}"
        lines.append(title)
        lines.append(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")

        for ns_type in NAMESPACE_TYPES:
            groups = group_by_namespace(processes_data, ns_type)
            if use_color:
                ns_colored = colorize_ns(ns_type, ns_type.upper())
                lines.append(f"\n{ns_colored} Namespaces:")
            else:
                lines.append(f"\n{ns_type.upper()} Namespaces:")
            
            for inode, pids in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
                if len(pids) > 1:
                    ns_inode = f"{ns_type}:{inode}"
                    if use_color:
                        ns_inode_colored = colorize_ns(ns_type, ns_inode)
                        pids_colored = f"{Colors.YELLOW}{pids}{Colors.RESET}"
                        suffix = f"{Colors.DIM}...{Colors.RESET}" if len(pids) > 5 else ""
                        lines.append(f"  {ns_inode_colored} -> {len(pids)} processes: {pids_colored[:5]}{suffix}")
                    else:
                        suffix = "..." if len(pids) > 5 else ""
                        lines.append(f"  {ns_inode} -> {len(pids)} processes: {pids[:5]}{suffix}")

        return "\n".join(lines)

    return str(processes_data)


def filter_by_namespace_type(processes_data, ns_filter):
    """Filter processes to only show specific namespace types."""
    filtered = []
    for proc in processes_data:
        new_proc = {
            "pid": proc["pid"],
            "name": proc["name"],
            "cmdline": proc["cmdline"],
            "namespaces": {},
        }
        for ns_type in ns_filter:
            if ns_type in proc["namespaces"]:
                new_proc["namespaces"][ns_type] = proc["namespaces"][ns_type]
        if new_proc["namespaces"]:
            filtered.append(new_proc)
    return filtered


def find_shared_namespaces(processes_data):
    """Find processes that share namespaces."""
    shared = {}
    for ns_type in NAMESPACE_TYPES:
        groups = group_by_namespace(processes_data, ns_type)
        for inode, pids in groups.items():
            if len(pids) > 1:
                key = f"{ns_type}:{inode}"
                shared[key] = pids
    return shared


def main():
    parser = argparse.ArgumentParser(
        description="Dump Linux process namespace information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Dump all process namespaces
  %(prog)s -p 1234              Dump namespaces for PID 1234
  %(prog)s -n net,pid           Only show net and pid namespaces
  %(prog)s -f summary           Show namespace sharing summary
  %(prog)s -f json              Output in JSON format
        """
    )

    parser.add_argument(
        "-p", "--pid",
        type=int,
        help="Specific PID to inspect"
    )

    parser.add_argument(
        "-n", "--namespace",
        type=str,
        help="Comma-separated list of namespace types to show"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["table", "json", "summary"],
        default="table",
        help="Output format (default: table)"
    )

    parser.add_argument(
        "-s", "--shared",
        action="store_true",
        help="Show only processes that share namespaces"
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show all namespace types even if inaccessible"
    )

    parser.add_argument(
        "--find-shared",
        action="store_true",
        help="Find and display shared namespaces"
    )

    parser.add_argument(
        "--color",
        action="store_true",
        help="Enable colored output"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    if not PROC_ROOT.exists():
        print("Error: /proc filesystem not available", file=sys.stderr)
        sys.exit(1)

    if args.pid:
        pids = [args.pid]
        if not (PROC_ROOT / str(args.pid)).exists():
            print(f"Error: Process {args.pid} not found", file=sys.stderr)
            sys.exit(1)
    else:
        pids = get_process_list()

    if not pids:
        print("No processes found", file=sys.stderr)
        sys.exit(1)

    processes_data = []
    for pid in pids:
        data = dump_single_process(pid, show_all_ns=args.all)
        if data["namespaces"]:
            processes_data.append(data)

    if args.namespace:
        ns_filter = [ns.strip() for ns in args.namespace.split(",")]
        processes_data = filter_by_namespace_type(processes_data, ns_filter)

    if args.find_shared:
        shared = find_shared_namespaces(processes_data)
        print("Shared Namespaces:")
        print("-" * 60)
        for ns_key, pids in sorted(shared.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"{ns_key}: {len(pids)} processes")
            print(f"  PIDs: {pids[:10]}{'...' if len(pids) > 10 else ''}")
        return

    use_color = args.color or (supports_color() and not args.no_color)
    
    if not use_color:
        Colors.disable()

    output = format_output(processes_data, args.format, use_color=use_color)
    print(output)


if __name__ == "__main__":
    main()
