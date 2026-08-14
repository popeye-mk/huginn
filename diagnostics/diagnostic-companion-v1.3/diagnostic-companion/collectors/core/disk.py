"""Disk collector: free space per real mounted volume (spec §4.1)."""

import shutil

PSEUDO_FSTYPES = {
    "proc", "sysfs", "devtmpfs", "tmpfs", "devpts", "cgroup", "cgroup2",
    "overlay", "squashfs", "mqueue", "debugfs", "tracefs", "securityfs",
    "pstore", "bpf", "autofs", "hugetlbfs", "fusectl", "configfs", "binfmt_misc",
}


def _real_mounts():
    mounts = []
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                if fstype in PSEUDO_FSTYPES:
                    continue
                if not device.startswith("/dev/") and device != "overlay":
                    continue
                mounts.append((device, mountpoint, fstype))
    except FileNotFoundError:
        pass
    return mounts


def collect():
    volumes = []
    min_free_percent = 100.0

    for device, mountpoint, fstype in _real_mounts():
        try:
            usage = shutil.disk_usage(mountpoint)
        except OSError:
            continue
        free_percent = round(100 * usage.free / usage.total, 1) if usage.total else 0.0
        min_free_percent = min(min_free_percent, free_percent)
        volumes.append({
            "device": device,
            "mountpoint": mountpoint,
            "fstype": fstype,
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "free_percent": free_percent,
        })

    return {
        "volumes": volumes,
        "min_free_percent": min_free_percent if volumes else None,
    }
