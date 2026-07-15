#!/usr/bin/env python3
# Copyright (c) 2026 Wind River Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""
DPLL Pin Topology Viewer

Uses pynetlink (Netlink DPLL API) to query DPLL pin information and visualize:
  - Which NIC complex's SDP output is connected to the shared CGU
  - Which NIC complex receives TIME_REF/CLKREF from the shared CGU
  - Maps clock_id to PCI bus address / network interfaces

Supported platforms/NICs:
  - Intel E825-C (PCI IDs 0x579C-0x579F) — integrated in Xeon 6 SoC
  - Intel E830 (PCI IDs 0x12D3-0x12DE) — discrete OCP 3.0 NIC
  - Microchip ZL3073x timing module (shared DPLL / CGU)

Example platform topology (GNRD - Granite Rapids-D):
  - GNSS receiver (u-blox) feeds ZL3073x as clock source
  - ZL3073x distributes timing to E825-C and/or E830 NICs

  CGU pin labels encode which NIC they connect to:
      ETH0x_SDP_TIMESYNC_n  -> NIC complex on ETH0x
      NAC0/NAC1_*           -> NIC complex 0 or 1 (NAC = Network Adapter Complex)
  - NIC "1588-TIME_REF" output -> ZL3073x "ETH0x_SDP_TIMESYNC_n" input
  - ZL3073x "ETH0x_SDP_TIMESYNC_n" output -> NIC "1588-TIME_SYNC" input
  - ZL3073x "156M25_NACx_TIMEREF_SYNC" output -> NIC frequency reference
  - ZL3073x "156M25_NACx_CLKREF_SYNC" output -> NIC clock reference
"""

import glob
import os
import re
import subprocess

from pynetlink import NetlinkDPLL
from pynetlink import PinDirection
from pynetlink import PinState
from pynetlink import DeviceType


# E825-C and E830 PCI Device ID ranges from ice driver:
# Ref: https://github.com/gregkh/linux/blob/master/drivers/net/ethernet/intel/ice/ice_devids.h
#
# Identification method:
#   cat /sys/class/net/<interface>/device/uevent
#   PCI_ID=8086:XXXX
#
# E830 uses 0x12Dx/0x12Ex range (e.g., 0x12D3-0x12DE)
# E825-C uses 0x579x range (0x579C-0x579F)
# Other known ice NICs:
#   0x12D3 = Connorsville (E830)
#   0x1591 = Silicom STS2
#   0x1592 = Logan Beach
#   0x1593 = Salem Channel/Westport Channel
E825C_DEV_IDS = range(0x579C, 0x579F + 1)
E830_DEV_IDS = range(0x12D3, 0x12DE + 1)

# PCI Device ID to NIC family name mapping
NIC_FAMILY = {
    0x12D3: "Connorsville",
    0x1591: "Silicom STS2",
    0x1592: "Logan Beach",
    0x1593: "Salem Channel/Westport Channel",
}
# E810 family device IDs (not E825-C or E830)
E810_DEV_IDS = {0x1591, 0x1592, 0x1593}


def _get_pci_device_id(uevent_content):
    """Extract PCI device ID from uevent content.

    Looks for PCI_ID=8086:XXXX line and returns the device ID portion.
    Returns device ID as int, or None if not found.
    """
    for line in uevent_content.splitlines():
        if line.startswith("PCI_ID="):
            # Format: PCI_ID=8086:XXXX
            parts = line.split("=", 1)[1].split(":")
            if len(parts) == 2:
                try:
                    return int(parts[1], 16)
                except ValueError:
                    pass
    return None


def _nic_type_from_device_id(device_id):
    """Determine NIC type from PCI device ID.

    Returns "E825-C", "E830", "E810", or "unknown".
    """
    if device_id is None:
        return "unknown"
    if device_id in E825C_DEV_IDS:
        return "E825-C"
    if device_id in E830_DEV_IDS:
        return "E830"
    if device_id in E810_DEV_IDS:
        return "E810"
    return "unknown"


def _nic_family_from_device_id(device_id):
    """Get NIC family/board name from PCI device ID.

    Returns family name or None if not in known list.
    """
    if device_id is None:
        return None
    return NIC_FAMILY.get(device_id)


def get_cgu_input_priorities(cgu_devices, cgu_pins):
    """Get CGU input pin priorities and active source.

    Tries:
    1. pynetlink pin.pin_priority attribute (if available)
    2. 'dpll pin show' command output (iproute2 dpll tool)

    Returns list of dicts: [{"pin_id": N, "label": str, "state": str,
                             "prio_eec": int|None, "prio_pps": int|None}]
    sorted by priority (lowest = highest priority).
    """
    input_pins = [p for p in cgu_pins if p.pin_direction == PinDirection.INPUT]

    # Deduplicate by pin_id (same pin appears for EEC and PPS devices)
    seen_ids = set()
    unique_pins = []
    for pin in input_pins:
        if pin.pin_id not in seen_ids:
            seen_ids.add(pin.pin_id)
            unique_pins.append(pin)

    results = []
    for pin in unique_pins:
        entry = {
            "pin_id": pin.pin_id,
            "label": pin.pin_board_label or "(none)",
            "state": pin.pin_state.value,
            "prio_eec": None,
            "prio_pps": None,
        }
        # Try reading priority from pynetlink object
        prio = getattr(pin, 'pin_priority', None)
        if prio is not None:
            entry["prio_eec"] = prio
        results.append(entry)

    # Fallback: parse 'dpll pin show' for priority info
    prio_from_tool = _parse_dpll_pin_priorities(cgu_devices)
    if prio_from_tool:
        for entry in results:
            pid = entry["pin_id"]
            if pid in prio_from_tool:
                if entry["prio_eec"] is None:
                    entry["prio_eec"] = prio_from_tool[pid].get("prio_eec")
                if entry["prio_pps"] is None:
                    entry["prio_pps"] = prio_from_tool[pid].get("prio_pps")

    return results


def _parse_dpll_pin_priorities(cgu_devices):
    """Parse 'dpll pin show' output to extract pin priorities.

    Example output format:
      pin 7 id 7 board-label GNSS_1PPS_IN ...
        device 0 prio 1 state connected
        device 1 prio 3 state connected

    Returns dict: {pin_id: {"prio_eec": int, "prio_pps": int}}
    """
    priorities = {}

    # Determine which dev_id is EEC vs PPS
    eec_dev_id = None
    pps_dev_id = None
    for dev in cgu_devices:
        if dev.dev_type == DeviceType.EEC:
            eec_dev_id = dev.dev_id
        elif dev.dev_type == DeviceType.PPS:
            pps_dev_id = dev.dev_id

    try:
        result = subprocess.run(
            ["dpll", "pin", "show"],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return priorities

        current_pin_id = None
        for line in result.stdout.splitlines():
            # Match pin header line
            m = re.match(r'.*pin\s+(\d+)\s+', line)
            if m and 'id' in line:
                # Extract pin id
                id_m = re.search(r'id\s+(\d+)', line)
                if id_m:
                    current_pin_id = int(id_m.group(1))
                    if current_pin_id not in priorities:
                        priorities[current_pin_id] = {}

            # Match device priority line
            if current_pin_id is not None:
                dev_m = re.search(r'device\s+(\d+).*prio\s+(\d+)', line)
                if dev_m:
                    dev_id = int(dev_m.group(1))
                    prio = int(dev_m.group(2))
                    if dev_id == eec_dev_id:
                        priorities[current_pin_id]["prio_eec"] = prio
                    elif dev_id == pps_dev_id:
                        priorities[current_pin_id]["prio_pps"] = prio

    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    return priorities


def detect_cgu_mode():
    """Detect primary/secondary CGU mode from dmesg for ice NICs.

    On GNRD, primary and secondary E830s are SEPARATE physical NICs on
    different PCI buses. The primary owns the CGU and has TIMEREF wired;
    the secondary only receives 1PPS via board-level wire.

    The ice driver logs lines like:
      ice 0000:13:00.0: PF is configured in primary mode with IP instance ID 0
      ice 0000:1b:00.0: PF is configured in secondary mode with IP instance ID 1

    Returns dict: {pci_addr: {"mode": "primary"|"secondary", "instance_id": int}}
    """
    cgu_modes = {}
    pattern = re.compile(
        r'ice\s+(\S+):\s+PF is configured in (primary|secondary) mode '
        r'with IP instance ID (\d+)'
    )
    # Try dmesg first
    try:
        result = subprocess.run(
            ["dmesg"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            m = pattern.search(line)
            if m:
                pci_addr = m.group(1)
                mode = m.group(2)
                instance_id = int(m.group(3))
                cgu_modes[pci_addr] = {"mode": mode, "instance_id": instance_id}
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    # Fallback: try /var/log/dmesg or journalctl if dmesg was empty
    if not cgu_modes:
        for log_path in ["/var/log/dmesg", "/var/log/kern.log"]:
            try:
                with open(log_path, 'r') as f:
                    for line in f:
                        m = pattern.search(line)
                        if m:
                            pci_addr = m.group(1)
                            mode = m.group(2)
                            instance_id = int(m.group(3))
                            cgu_modes[pci_addr] = {
                                "mode": mode, "instance_id": instance_id
                            }
                if cgu_modes:
                    break
            except (IOError, PermissionError):
                continue

    # Fallback: try journalctl
    if not cgu_modes:
        try:
            result = subprocess.run(
                ["journalctl", "-k", "--no-pager", "-g", "primary mode|secondary mode"],
                capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                m = pattern.search(line)
                if m:
                    pci_addr = m.group(1)
                    mode = m.group(2)
                    instance_id = int(m.group(3))
                    cgu_modes[pci_addr] = {"mode": mode, "instance_id": instance_id}
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

    # Heuristic fallback: infer primary/secondary from sysfs evidence
    # Primary E830 has: tspll_cfg present + PTP device
    # Secondary E830 has: no tspll_cfg + no PTP device
    if not cgu_modes:
        e830_candidates = []
        for net_path in sorted(glob.glob("/sys/class/net/*/device/uevent")):
            try:
                with open(net_path, 'r') as f:
                    uevent = f.read()
                if "DRIVER=ice" not in uevent:
                    continue
                iface = net_path.split("/")[4]
                device_link = os.path.realpath(f"/sys/class/net/{iface}/device")
                pci_addr = os.path.basename(device_link)
                if not pci_addr.endswith(".0"):
                    continue
                # Identify E830 via PCI Device ID from uevent
                device_id = _get_pci_device_id(uevent)
                if _nic_type_from_device_id(device_id) != "E830":
                    continue
                # Check indicators of primary
                tspll_path = f"/sys/class/net/{iface}/device/tspll_cfg"
                has_tspll = os.path.exists(tspll_path)
                has_ptp = bool(glob.glob(
                    f"/sys/class/net/{iface}/device/ptp/ptp*/"))
                # Also check ethtool -T if sysfs ptp path missing
                if not has_ptp:
                    try:
                        r = subprocess.run(
                            ["ethtool", "-T", iface],
                            capture_output=True, text=True, timeout=5)
                        for line in r.stdout.splitlines():
                            if "PTP Hardware Clock:" in line:
                                val = line.split(":", 1)[1].strip()
                                if val.isdigit() and int(val) >= 0:
                                    has_ptp = True
                                break
                    except Exception:
                        pass
                e830_candidates.append({
                    "pci_addr": pci_addr,
                    "has_tspll": has_tspll,
                    "has_ptp": has_ptp,
                })
            except (IOError, ValueError):
                continue

        if e830_candidates:
            for nic in e830_candidates:
                # Primary indicator: has tspll_cfg (TIMEREF trace from CGU)
                # Secondary: has PTP but no tspll_cfg (only gets 1PPS wire)
                if nic["has_tspll"]:
                    cgu_modes[nic["pci_addr"]] = {
                        "mode": "primary", "instance_id": -1}
                elif nic["has_ptp"] and not nic["has_tspll"]:
                    cgu_modes[nic["pci_addr"]] = {
                        "mode": "secondary", "instance_id": -1}

    return cgu_modes


def discover_ice_nics():
    """Discover all ice NICs and their capabilities before configuration.

    Returns list of dicts with interface info, firmware, PCI, NIC type,
    tspll_cfg availability, PTP pin support, and CGU mode.
    """
    nics = []
    seen_pci = set()
    cgu_modes = detect_cgu_mode()

    for net_path in sorted(glob.glob("/sys/class/net/*/device/uevent")):
        try:
            with open(net_path, 'r') as f:
                uevent = f.read()
            if "DRIVER=ice" not in uevent:
                continue

            iface = net_path.split("/")[4]
            device_link = os.path.realpath(f"/sys/class/net/{iface}/device")
            pci_addr = os.path.basename(device_link)

            # Only report function 0 of each PCI device (base port)
            if not pci_addr.endswith(".0"):
                continue
            # Deduplicate by PCI slot (without function)
            pci_slot = pci_addr.rsplit(".", 1)[0]
            if pci_slot in seen_pci:
                continue
            seen_pci.add(pci_slot)

            # Get firmware version
            fw_version = ""
            try:
                result = subprocess.run(
                    ["ethtool", "-i", iface],
                    capture_output=True, text=True, timeout=5)
                for line in result.stdout.splitlines():
                    if "firmware-version" in line:
                        fw_version = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass

            # Determine NIC type from PCI Device ID
            # cat /sys/class/net/<interface>/device/uevent -> PCI_ID=8086:XXXX
            device_id = _get_pci_device_id(uevent)
            nic_type = _nic_type_from_device_id(device_id)
            nic_family = _nic_family_from_device_id(device_id)

            # Detect CGU mode (primary/secondary) from dmesg
            cgu_mode_info = cgu_modes.get(pci_addr, {})
            cgu_mode = cgu_mode_info.get("mode", "")

            # Check tspll_cfg
            tspll_path = f"/sys/class/net/{iface}/device/tspll_cfg"
            tspll_cfg = ""
            if os.path.exists(tspll_path):
                try:
                    with open(tspll_path, 'r') as f:
                        tspll_cfg = f.read().strip()
                except IOError:
                    pass

            # Check PTP device and pins
            ptp_pins = []
            ptp_dirs = glob.glob(f"/sys/class/net/{iface}/device/ptp/ptp*/pins/")
            for ptp_dir in ptp_dirs:
                if os.path.isdir(ptp_dir):
                    for pin_name in sorted(os.listdir(ptp_dir)):
                        pin_file = os.path.join(ptp_dir, pin_name)
                        pin_cfg = ""
                        try:
                            with open(pin_file, 'r') as f:
                                pin_cfg = f.read().strip()
                        except IOError:
                            pass
                        ptp_pins.append({"name": pin_name, "cfg": pin_cfg})

            # Check for PTP device via sysfs path or ethtool -T
            has_ptp = len(ptp_dirs) > 0
            ptp_clock_id = -1
            if not has_ptp:
                # Fallback: check ethtool -T for PTP Hardware Clock
                try:
                    r = subprocess.run(
                        ["ethtool", "-T", iface],
                        capture_output=True, text=True, timeout=5)
                    for line in r.stdout.splitlines():
                        if "PTP Hardware Clock:" in line:
                            val = line.split(":", 1)[1].strip()
                            if val.isdigit():
                                ptp_clock_id = int(val)
                                has_ptp = True
                            break
                except Exception:
                    pass
                # If found via ethtool, try reading pins from /sys/class/ptp/
                if ptp_clock_id >= 0:
                    ptp_sys_pins = f"/sys/class/ptp/ptp{ptp_clock_id}/pins/"
                    if os.path.isdir(ptp_sys_pins):
                        for pin_name in sorted(os.listdir(ptp_sys_pins)):
                            pin_file = os.path.join(ptp_sys_pins, pin_name)
                            pin_cfg = ""
                            try:
                                with open(pin_file, 'r') as f:
                                    pin_cfg = f.read().strip()
                            except IOError:
                                pass
                            ptp_pins.append({"name": pin_name, "cfg": pin_cfg})

            nics.append({
                "iface": iface,
                "pci_addr": pci_addr,
                "pci_device_id": device_id,
                "fw_version": fw_version,
                "nic_type": nic_type,
                "nic_family": nic_family,
                "cgu_mode": cgu_mode,
                "tspll_cfg": tspll_cfg,
                "has_ptp": has_ptp,
                "ptp_pins": ptp_pins,
            })

        except (IOError, ValueError):
            continue

    return nics


def clock_id_to_pci_info(clock_id):
    """Resolve an ice NIC clock_id to PCI address and interface names."""
    target_hex = format(clock_id, '016x')
    results = []
    seen_pci = set()

    for net_path in sorted(glob.glob("/sys/class/net/*/phys_switch_id")):
        try:
            with open(net_path, 'r') as f:
                switch_id = f.read().strip()
            if not switch_id:
                continue
            if switch_id == target_hex or int(switch_id, 16) == clock_id:
                iface = net_path.split("/")[4]
                device_link = os.path.realpath(f"/sys/class/net/{iface}/device")
                pci_addr = os.path.basename(device_link)
                if pci_addr not in seen_pci:
                    seen_pci.add(pci_addr)
                    results.append({"iface": iface, "pci_addr": pci_addr})
        except (IOError, ValueError):
            continue
    return results


def cgu_to_pci_info(module_name):
    """Resolve CGU module (zl3073x) to its PCI parent device.

    The zl3073x is an auxiliary device on the same PCI card as the ice NIC.
    Check /sys/bus/auxiliary/devices/ or /sys/module/<module>/drivers/
    """
    results = []

    # Method 1: Check auxiliary bus for dpll devices bound to this module
    aux_path = "/sys/bus/auxiliary/devices/"
    if os.path.exists(aux_path):
        for dev in sorted(os.listdir(aux_path)):
            if module_name in dev or "dpll" in dev:
                real = os.path.realpath(os.path.join(aux_path, dev))
                # Walk up to find PCI parent
                path = real
                while path and path != "/":
                    if re.match(r'.*[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$', path):
                        pci_addr = os.path.basename(path)
                        if pci_addr not in [r.get('pci_addr') for r in results]:
                            results.append({"pci_addr": pci_addr, "aux_dev": dev})
                        break
                    path = os.path.dirname(path)

    # Method 2: Check /sys/module/zl3073x if available
    mod_path = f"/sys/module/{module_name}/drivers/"
    if os.path.exists(mod_path):
        for bus_type in os.listdir(mod_path):
            driver_path = os.path.join(mod_path, bus_type)
            if os.path.isdir(driver_path):
                for entry in os.listdir(driver_path):
                    link = os.path.join(driver_path, entry)
                    if os.path.islink(link):
                        real = os.path.realpath(link)
                        path = real
                        while path and path != "/":
                            if re.match(r'.*[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$', path):
                                pci_addr = os.path.basename(path)
                                if pci_addr not in [r.get('pci_addr') for r in results]:
                                    results.append({"pci_addr": pci_addr, "driver": bus_type})
                                break
                            path = os.path.dirname(path)

    return results


def main():
    print("Querying DPLL pin info via Netlink API (pynetlink)...\n")

    dpll = NetlinkDPLL()
    devices = dpll.get_all_devices()
    pins = dpll.get_all_pins()

    if not devices:
        print("ERROR: No DPLL devices found. Ensure ice/zl3073x drivers are loaded.")
        return

    # Separate by module
    ice_devices = sorted([d for d in devices if d.dev_module_name == "ice"],
                         key=lambda d: d.dev_id)
    cgu_devices = sorted([d for d in devices if d.dev_module_name != "ice"],
                         key=lambda d: d.dev_id)

    ice_clock_ids = set(d.dev_clock_id for d in ice_devices)
    cgu_clock_ids = set(d.dev_clock_id for d in cgu_devices)

    # Resolve NIC clock_ids to PCI
    clock_to_pci = {}
    for clk in ice_clock_ids:
        clock_to_pci[clk] = clock_id_to_pci_info(clk)

    # Resolve CGU PCI info
    cgu_pci_info = {}
    for dev in cgu_devices:
        if dev.dev_module_name not in cgu_pci_info:
            cgu_pci_info[dev.dev_module_name] = cgu_to_pci_info(dev.dev_module_name)

    # Print devices
    print("=" * 72)
    print("DPLL DEVICES")
    print("=" * 72)
    for dev in sorted(devices, key=lambda d: d.dev_id):
        extra = ""
        if dev.dev_clock_id in clock_to_pci and clock_to_pci[dev.dev_clock_id]:
            first = clock_to_pci[dev.dev_clock_id][0]
            n = len(clock_to_pci[dev.dev_clock_id])
            extra = f"  PCI={first['pci_addr']} ({n} ports)"
        elif dev.dev_module_name in cgu_pci_info and cgu_pci_info[dev.dev_module_name]:
            cgu_pci = cgu_pci_info[dev.dev_module_name][0]
            extra = f"  PCI={cgu_pci['pci_addr']} (shared CGU on same card)"
        print(f"  ID={dev.dev_id:2d}  clock=0x{dev.dev_clock_id:016x}  "
              f"type={dev.dev_type.value:4s}  lock={dev.lock_status.value:<14s}  "
              f"module={dev.dev_module_name}{extra}")

    # Classify pins
    cgu_pins = sorted([p for p in pins if p.dev_clock_id in cgu_clock_ids],
                      key=lambda p: (p.pin_id, p.dev_id))
    nic_pins = sorted([p for p in pins if p.dev_clock_id in ice_clock_ids],
                      key=lambda p: (p.pin_id, p.dev_id))

    # Print DPLL pin states (raw facts from netlink)
    print(f"\n{'=' * 72}")
    print("CGU DPLL PINS")
    print("=" * 72)

    cgu_inputs = [p for p in cgu_pins if p.pin_direction == PinDirection.INPUT]
    cgu_outputs = [p for p in cgu_pins if p.pin_direction == PinDirection.OUTPUT]

    print("\n  INPUTS:")
    for pin in sorted(cgu_inputs, key=lambda p: p.pin_id):
        label = pin.pin_board_label or "(none)"
        icon = "●" if pin.pin_state == PinState.CONNECTED else "○"
        dev_type = "EEC" if pin.dev_id == cgu_devices[0].dev_id else "PPS"
        print(f"    {icon} pin={pin.pin_id:2d} dev={pin.dev_id} [{label:<30s}] "
              f"{dev_type}  ({pin.pin_state.value})")

    print("\n  OUTPUTS:")
    for pin in sorted(cgu_outputs, key=lambda p: p.pin_id):
        label = pin.pin_board_label or "(none)"
        icon = "●" if pin.pin_state == PinState.CONNECTED else "○"
        dev_type = "EEC" if pin.dev_id == cgu_devices[0].dev_id else "PPS"
        print(f"    {icon} pin={pin.pin_id:2d} dev={pin.dev_id} [{label:<30s}] "
              f"{dev_type}  ({pin.pin_state.value})")

    print(f"\n{'=' * 72}")
    print("NIC DPLL PINS")
    print("=" * 72)

    for clk in sorted(ice_clock_ids):
        pci_list = clock_to_pci.get(clk, [])
        pci_str = ""
        if pci_list:
            pci_str = f" PCI={pci_list[0]['pci_addr']} ifaces={','.join(p['iface'] for p in pci_list)}"
        print(f"\n   NIC clock=0x{clk:016x}{pci_str}")

        clk_pins = [p for p in nic_pins if p.dev_clock_id == clk]
        outputs = [p for p in clk_pins if p.pin_direction == PinDirection.OUTPUT]
        inputs = [p for p in clk_pins if p.pin_direction == PinDirection.INPUT]

        if outputs:
            print("     OUTPUTS:")
            for pin in outputs:
                label = pin.pin_board_label or "(none)"
                icon = "●" if pin.pin_state == PinState.CONNECTED else "○"
                print(f"       {icon} pin={pin.pin_id:2d} dev={pin.dev_id}"
                      f" [{label}] ({pin.pin_state.value})")
        if inputs:
            print("     INPUTS:")
            for pin in inputs:
                label = pin.pin_board_label or "(none)"
                icon = "●" if pin.pin_state == PinState.CONNECTED else "○"
                print(f"       {icon} pin={pin.pin_id:2d} dev={pin.dev_id}"
                      f" [{label}] ({pin.pin_state.value})")

    # --- Pre-configuration NIC discovery ---
    print(f"\n{'=' * 72}")
    print("NIC DISCOVERY")
    print("=" * 72)

    discovered_nics = discover_ice_nics()

    # ── SECTION 1: OBSERVED FACTS (from sysfs, ethtool, DPLL netlink, dmesg) ──
    print()
    print("  ┌──────────────────────────────────────────────────────────────────┐")
    print("  │  OBSERVED FACTS (directly read from system)                      │")
    print("  └──────────────────────────────────────────────────────────────────┘")
    print()
    print(f"  {'Interface':<16} {'PCI':<14} {'FW':<30} {'Source'}")
    print(f"  {'─' * 15:<16} {'─' * 13:<14} {'─' * 29:<30} {'─' * 10}")
    for nic in discovered_nics:
        print(f"  {nic['iface']:<16} {nic['pci_addr']:<14} {nic['fw_version']:<30} ethtool -i")

    print()
    print("  NIC Type (derived from PCI Device ID via uevent):")
    for nic in discovered_nics:
        dev_id_str = f"0x{nic['pci_device_id']:04X}" if nic['pci_device_id'] else "?"
        fw_parts = nic['fw_version'].split(".") if nic['fw_version'] else []
        fw_maj_min = ".".join(fw_parts[:2]) if len(fw_parts) >= 2 else (fw_parts[0] if fw_parts else "?")
        family_str = f" ({nic['nic_family']})" if nic['nic_family'] else ""
        print(f"    {nic['iface']:<16} PCI_ID=8086:{dev_id_str}"
              f" FW={fw_maj_min} → {nic['nic_type']}{family_str}")

    print()
    print("  CGU Mode (from dmesg 'ice XXXX: PF is configured in ... mode'):")
    any_mode = False
    for nic in discovered_nics:
        if nic['cgu_mode']:
            print(f"    {nic['iface']:<16} {nic['pci_addr']}  → {nic['cgu_mode']}")
            any_mode = True
    if not any_mode:
        print("    (not detected — dmesg may have rotated, try: dmesg | grep 'primary\\|secondary')")

    print()
    print("  tspll_cfg sysfs (/sys/class/net/<iface>/device/tspll_cfg):")
    for nic in discovered_nics:
        if nic['tspll_cfg']:
            print(f"    {nic['iface']:<16} PRESENT: {nic['tspll_cfg']}")
        else:
            print(f"    {nic['iface']:<16} NOT AVAILABLE (file missing or empty)")

    print()
    print("  PTP Hardware Clock (ethtool -T):")
    for nic in discovered_nics:
        ptp_str = "YES" if nic['has_ptp'] else "NO"
        print(f"    {nic['iface']:<16} PTP HW clock: {ptp_str}")

    print()
    print("  Pin Status per port (Netlink DPLL vs PTP sysfs):")
    print("    Netlink = authoritative (active signal state from driver)")
    print("    Sysfs   = configured function (intent, not proof of signal)")
    print()

    for nic in discovered_nics:
        print(f"    {nic['iface']} ({nic['nic_type']}, {nic['pci_addr']})")

        # Resolve this NIC's clock_id for netlink pin lookup
        clk = None
        for c, plist in clock_to_pci.items():
            if any(p['pci_addr'] == nic['pci_addr'] for p in plist):
                clk = c
                break

        # Gather netlink pins for this NIC
        nic_netlink_pins = []
        if clk:
            nic_netlink_pins = [p for p in nic_pins if p.dev_clock_id == clk]

        # Gather sysfs pins
        sysfs_pin_map = {}
        for pin in nic['ptp_pins']:
            parts = pin['cfg'].split()
            func = {"0": "disabled", "1": "input", "2": "output"}.get(
                parts[1], parts[1]) if len(parts) >= 2 else "?"
            sysfs_pin_map[pin['name']] = func

        # Build unified pin list from both sources
        # Netlink pins
        print(f"      {'Pin':<20s} {'Netlink DPLL':<35s} {'PTP sysfs'}")
        print(f"      {'─' * 19:<20s} {'─' * 34:<35s} {'─' * 25}")

        # Show netlink pins
        shown_sysfs = set()
        if nic_netlink_pins:
            for p in sorted(nic_netlink_pins, key=lambda x: x.pin_id):
                label = p.pin_board_label or f"pin_{p.pin_id}"
                direction = "out" if p.pin_direction == PinDirection.OUTPUT else "in"
                netlink_str = f"{direction} state={p.pin_state.value}"
                # Try to match to sysfs pin
                sysfs_str = ""
                for sname, sfunc in sysfs_pin_map.items():
                    if (sname.upper() in label.upper()
                            or label.upper() in sname.upper()
                            or ("TIME_REF" in label and "SDP0" in sname.upper())
                            or ("TIME_SYNC" in label and "SDP1" in sname.upper())):
                        sysfs_str = f"{sname}={sfunc}"
                        shown_sysfs.add(sname)
                        break
                print(f"      {label:<20s} {netlink_str:<35s} {sysfs_str}")
        else:
            print(f"      {'(no netlink data)':<20s} {'':35s}")

        # Show remaining sysfs pins not matched to netlink
        for sname, sfunc in sorted(sysfs_pin_map.items()):
            if sname not in shown_sysfs:
                print(f"      {sname:<20s} {'(no netlink pin)':<35s} {sname}={sfunc}")

        # tspll_cfg
        if nic['tspll_cfg']:
            print(f"      {'TIMEREF':<20s} {'(not a DPLL pin)':<35s}"
                  f" tspll_cfg={nic['tspll_cfg']}")

        print()

    # --- Detect E830 or other NICs receiving from CGU via SDP1 input ---
    # E830 shows as another ice DPLL device but does NOT output to CGU,
    # it only receives 1PPS from CGU on its SDP1 input pin.
    e825_clocks = set()  # NICs that output to CGU (have 1588-TIME_REF output)
    e830_clocks = set()  # NICs that only receive from CGU (SDP1 input, no output to CGU)

    for clk in ice_clock_ids:
        clk_pins_list = [p for p in nic_pins if p.dev_clock_id == clk]
        has_output_to_cgu = any(
            p.pin_direction == PinDirection.OUTPUT
            and p.pin_state == PinState.CONNECTED
            and p.pin_board_label and "TIME_REF" in p.pin_board_label
            for p in clk_pins_list)
        has_sdp1_input = any(
            p.pin_direction == PinDirection.INPUT
            and p.pin_board_label and ("TIME_SYNC" in p.pin_board_label
                                       or "SDP1" in (p.pin_board_label or "").upper())
            for p in clk_pins_list)

        if has_output_to_cgu:
            e825_clocks.add(clk)
        elif has_sdp1_input:
            e830_clocks.add(clk)

    # --- ASCII topology diagram ---
    print(f"\n{'=' * 72}")
    print("PLATFORM TOPOLOGY DIAGRAM")
    print("=" * 72)

    # GNSS source
    gnss_pin = next((p for p in cgu_pins
                     if p.pin_state == PinState.CONNECTED
                     and p.pin_direction == PinDirection.INPUT
                     and p.pin_board_label
                     and "GNSS" in p.pin_board_label.upper()), None)
    gnss_label = gnss_pin.pin_board_label if gnss_pin else "not connected"

    # CGU info
    cgu_mod = cgu_devices[0].dev_module_name if cgu_devices else "CGU"
    cgu_clk = list(cgu_clock_ids)[0] if cgu_clock_ids else 0
    cgu_eec_lock = next((d.lock_status.value for d in cgu_devices
                         if d.dev_type == DeviceType.EEC), "N/A")
    cgu_pps_lock = next((d.lock_status.value for d in cgu_devices
                         if d.dev_type == DeviceType.PPS), "N/A")

    print()
    print("    ┌───────────────────────────────────────────────────────────┐")
    print("    │  GNSS Receiver                                           │")
    print(f"    │  Input: {gnss_label:<51s}│")
    print("    └──────────────────────────┬────────────────────────────────┘")
    print("                               │")
    print("                               ▼ 1PPS")
    print("    ┌───────────────────────────────────────────────────────────┐")
    print(f"    │  Shared DPLL: {cgu_mod:<45s}│")
    print(f"    │  clock: 0x{cgu_clk:016x}                              │")
    print(f"    │  EEC lock: {cgu_eec_lock:<46s}│")
    print(f"    │  PPS lock: {cgu_pps_lock:<46s}│")
    print("    │                                                           │")

    # --- Pin priority and active source ---
    input_priorities = get_cgu_input_priorities(cgu_devices, cgu_pins)
    # Sort by EEC priority (lowest = highest priority)
    prio_sorted = sorted(input_priorities,
                         key=lambda x: (x['prio_eec'] if x['prio_eec'] is not None else 999))

    active_source = next((p for p in prio_sorted if p['state'] == 'connected'), None)

    print("    │  Input Source Selection:                                   │")
    if active_source:
        print(f"    │    ★ ACTIVE: {active_source['label']:<43s}│")
    else:
        print("    │    ★ ACTIVE: (none connected — holdover/free-run)         │")
    print("    │                                                           │")
    print("    │    Priority  Pin  Label                     State          │")
    print("    │    ────────  ───  ────────────────────────── ─────────────  │")

    has_prio_data = any(p['prio_eec'] is not None for p in prio_sorted)
    for entry in prio_sorted:
        prio_str = str(entry['prio_eec']) if entry['prio_eec'] is not None else "?"
        state_str = entry['state']
        marker = "►" if entry['state'] == 'connected' else " "
        label_short = entry['label'][:26]
        print(f"    │  {marker} {prio_str:>8s}  {entry['pin_id']:>3d}  {label_short:<26s} {state_str:<13s} │")

    if not has_prio_data:
        print("    │                                                           │")
        print("    │    (priority not available — try: dpll pin show)           │")

    print("    │                                                           │")
    # --- CGU Outputs/Inputs from actual DPLL pin data ---
    print("    │  Outputs (connected):                                      │")
    cgu_out_connected = [p for p in cgu_outputs if p.pin_state == PinState.CONNECTED]
    if cgu_out_connected:
        for pin in cgu_out_connected:
            label = pin.pin_board_label or "(unnamed)"
            print(f"    │    {label:<55s}│")
    else:
        print("    │    (none connected)                                       │")
    print("    │                                                           │")
    print("    │  Inputs (connected):                                       │")
    cgu_in_connected = [p for p in cgu_inputs if p.pin_state == PinState.CONNECTED]
    if cgu_in_connected:
        for pin in cgu_in_connected:
            label = pin.pin_board_label or "(unnamed)"
            print(f"    │    {label:<55s}│")
    else:
        print("    │    (none connected)                                       │")
    print("    └───────┬───────────────────────────────────┬───────────────┘")
    print("            │                                   │")
    print("            ▼                                   ▼")
    print("    ┌──────────────────────────────┐    ┌──────────────────────────────┐")
    print("    │  E825-C NIC(s) (ice)          │    │  E830 NIC(s) (ice)           │")
    print("    │                              │    │                              │")

    # --- E825-C column: populate from discovered NICs ---
    e825_nics = [n for n in discovered_nics if n['nic_type'] == "E825-C"]
    e830_nics = [n for n in discovered_nics if n['nic_type'] == "E830"]

    # Build connection status for each E825-C NIC
    e825_lines = []
    if e825_nics:
        for nic in e825_nics:
            pci = nic['pci_addr']
            iface = nic['iface']
            e825_lines.append(f"  {iface} / {pci}")
            # Check netlink pins for this NIC
            clk = None
            for c, plist in clock_to_pci.items():
                if any(p['pci_addr'] == pci for p in plist):
                    clk = c
                    break
            has_output = False
            has_input = False
            if clk:
                has_output = any(
                    p.pin_direction == PinDirection.OUTPUT
                    and p.pin_state == PinState.CONNECTED
                    for p in nic_pins if p.dev_clock_id == clk)
                has_input = any(
                    p.pin_direction == PinDirection.INPUT
                    and p.pin_state == PinState.CONNECTED
                    for p in nic_pins if p.dev_clock_id == clk)
            if has_output:
                e825_lines.append("  ✓ Output pin connected")
            else:
                e825_lines.append("  ✗ Output pin (not seen)")
            if has_input:
                e825_lines.append("  ✓ Input pin connected")
            else:
                e825_lines.append("  ✗ Input pin (not seen)")
            if nic['tspll_cfg']:
                e825_lines.append("  ✓ tspll_cfg present")
            e825_lines.append("")
    else:
        e825_lines.append("  (not detected)")

    # Build connection status for each E830 NIC
    e830_lines = []
    if e830_nics:
        for nic in e830_nics:
            pci = nic['pci_addr']
            iface = nic['iface']
            e830_lines.append(f"  {iface} / {pci}")
            # PTP HW clock
            if nic['has_ptp']:
                e830_lines.append("  ✓ PTP HW clock present")
            else:
                e830_lines.append("  ✗ PTP HW clock (not seen)")
            # Check SDP1 input from CGU
            clk = None
            for c, plist in clock_to_pci.items():
                if any(p['pci_addr'] == pci for p in plist):
                    clk = c
                    break
            has_sdp1_in = False
            if clk:
                has_sdp1_in = any(
                    p.pin_direction == PinDirection.INPUT
                    and p.pin_state == PinState.CONNECTED
                    for p in nic_pins if p.dev_clock_id == clk)
            if has_sdp1_in:
                e830_lines.append("  ✓ SDP1 in  ◄── CGU (1PPS)")
            else:
                e830_lines.append("  ✗ SDP1 in  ◄── CGU (not seen)")
            # Check tspll_cfg / freq ref
            if nic['tspll_cfg']:
                e830_lines.append("  ✓ Freq ref (tspll_cfg)")
            else:
                e830_lines.append("  ✗ Freq ref (not seen)")
            # CGU mode
            if nic['cgu_mode']:
                e830_lines.append(f"  CGU mode: {nic['cgu_mode']}")
            e830_lines.append("")
    else:
        e830_lines.append("  (not detected)")

    # Print side-by-side
    max_lines = max(len(e825_lines), len(e830_lines))
    for i in range(max_lines):
        left = e825_lines[i] if i < len(e825_lines) else ""
        right = e830_lines[i] if i < len(e830_lines) else ""
        print(f"    │{left:<30s}│    │{right:<30s}│")

    print("    └──────────────────────────────┘    └──────────────────────────────┘")
    print()
    print("  ─── Connection evidence ───")
    print("  ✓ = Confirmed via DPLL netlink pin state or sysfs")
    print("  ✗ = Not seen in software; may need board schematic confirmation")

    # --- Explanation ---
    print(f"\n{'=' * 72}")
    print("PIN LABEL LEGEND")
    print("=" * 72)
    print("""
  ZL3073x CGU Input pins (NIC feeds CGU):
    ETH0x_SDP_TIMESYNC_0 + _2 = same physical NIC SDP0 wire (two DPLL engines)
    CLK_78M125_NACx_SYNCEn    = NIC SyncE recovered clock
    GNSS_1PPS_IN              = GNSS receiver 1PPS

  ZL3073x CGU Output pins (CGU feeds NIC):
    ETH0x_SDP_TIMESYNC_1 + _3 = same physical NIC SDP1 wire (two DPLL engines)
    156M25_NACx_CLKREF_SYNC   = 156.25MHz clock reference to NIC
    156M25_NACx_TIMEREF_SYNC  = 156.25MHz time reference to NIC
    1PPS_OUT_SW_P/N           = 1PPS output to E830 (board-level)

  E825-C NIC pins (ice driver):
    1588-TIME_REF  = NIC SDP0 output → CGU (1PPS)
    1588-TIME_SYNC = NIC SDP1 input  ← CGU (1PPS)
    TIMEREF        = 156.25MHz frequency reference ← CGU
    MAC-PHY-CLK    = NIC PHY clock output (SyncE TX)

  E830 NIC pins (ice driver):
    SDP1 input ← receives 1PPS from CGU
    ts2phc synchronizes E830 PHC from this 1PPS signal

  Physical wiring (same signal, multiple DPLL registrations):
    NIC SDP0 pin = CGU TIMESYNC_0 + TIMESYNC_2 (one wire, two CGU inputs)
    NIC SDP1 pin = CGU TIMESYNC_1 + TIMESYNC_3 (one wire, two CGU outputs)
""")


if __name__ == "__main__":
    main()
