#!/usr/bin/env python3
# Copyright (c) 2026 Wind River Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""
DPLL Pin Control - Manage CGU input source selection via Netlink API.

Usage:
    ./dpll_pin_control.py show              Show all input pins with priority/state
    ./dpll_pin_control.py disconnect <pin>  Disconnect pin (remove from selection)
    ./dpll_pin_control.py connect <pin>     Enable pin (selectable, or connected in manual mode)
    ./dpll_pin_control.py selectable <pin>  Set pin selectable (eligible for auto-selection)
    ./dpll_pin_control.py prio <pin> <val>  Set priority for pin (lower = higher)
    ./dpll_pin_control.py switch <pin>      Connect pin, disconnect all others
    ./dpll_pin_control.py api               Show pynetlink API methods (debug)

    <pin> can be pin ID (number) or label substring (e.g. "GNSS", "ETH01", "SYNCE0")

Examples:
    ./dpll_pin_control.py show
    ./dpll_pin_control.py disconnect GNSS
    ./dpll_pin_control.py connect GNSS_1PPS_IN
    ./dpll_pin_control.py prio GNSS 14
    ./dpll_pin_control.py prio ETH01_SDP_TIMESYNC_0 0
    ./dpll_pin_control.py switch ETH01_SDP_TIMESYNC_0
"""

import sys

from pynetlink import NetlinkDPLL
from pynetlink import DeviceType
from pynetlink import PinDirection
from pynetlink import PinState
from pynetlink.common import NetlinkException


RECOVERY_MSG = """\
  WARNING: CGU is stuck in holdover with all pins disconnected.
  The zl3073x CGU in automatic-only mode cannot re-acquire lock via netlink.

  To recover, reload the ice driver:
    sudo rmmod ice && sudo modprobe ice

  This resets the CGU and restores automatic source selection."""


def get_cgu_info(dpll):
    """Get CGU devices and input pins."""
    devices = dpll.get_all_devices()
    pins = dpll.get_all_pins()

    cgu_devices = [d for d in devices if d.dev_module_name != "ice"]
    cgu_clock_ids = set(d.dev_clock_id for d in cgu_devices)

    cgu_inputs = [p for p in pins
                  if p.dev_clock_id in cgu_clock_ids
                  and p.pin_direction == PinDirection.INPUT]

    eec_dev = next((d for d in cgu_devices if d.dev_type == DeviceType.EEC), None)
    pps_dev = next((d for d in cgu_devices if d.dev_type == DeviceType.PPS), None)

    return cgu_devices, cgu_inputs, eec_dev, pps_dev


def _all_disconnected(cgu_inputs):
    """Check if all CGU input pins are disconnected (stuck holdover)."""
    return all(p.pin_state == PinState.DISCONNECTED for p in cgu_inputs)


def resolve_pin(cgu_inputs, pin_arg):
    """Resolve pin argument to pin ID. Accepts ID or label substring."""
    try:
        pin_id = int(pin_arg)
        matching = [p for p in cgu_inputs if p.pin_id == pin_id]
        if matching:
            return pin_id, matching[0].pin_board_label or "(none)"
        print(f"ERROR: Pin ID {pin_id} not found in CGU inputs")
        return None, None
    except ValueError:
        pass

    matches = set()
    for p in cgu_inputs:
        if p.pin_board_label and pin_arg.upper() in p.pin_board_label.upper():
            matches.add((p.pin_id, p.pin_board_label))

    if len(matches) == 1:
        return matches.pop()
    elif len(matches) > 1:
        print(f"ERROR: Ambiguous match for '{pin_arg}':")
        for pid, lbl in sorted(matches):
            print(f"  pin={pid}  [{lbl}]")
        return None, None
    else:
        print(f"ERROR: No CGU input pin matching '{pin_arg}'")
        return None, None


def show_inputs(dpll):
    """Show all CGU input pins with state and priority."""
    cgu_devices, cgu_inputs, eec_dev, pps_dev = get_cgu_info(dpll)

    if not cgu_devices:
        print("ERROR: No CGU DPLL devices found")
        return

    print(f"CGU: {cgu_devices[0].dev_module_name}  "
          f"clock=0x{cgu_devices[0].dev_clock_id:016x}")
    if eec_dev:
        mode_str = eec_dev.dev_mode.value
        supported = [m.value for m in eec_dev.dev_mode_supported] if eec_dev.dev_mode_supported else []
        print(f"  EEC (dev {eec_dev.dev_id}): lock={eec_dev.lock_status.value}  "
              f"mode={mode_str}  supported={supported}")
    if pps_dev:
        mode_str = pps_dev.dev_mode.value
        supported = [m.value for m in pps_dev.dev_mode_supported] if pps_dev.dev_mode_supported else []
        print(f"  PPS (dev {pps_dev.dev_id}): lock={pps_dev.lock_status.value}  "
              f"mode={mode_str}  supported={supported}")
    print()

    seen = {}
    for pin in cgu_inputs:
        pid = pin.pin_id
        if pid not in seen:
            seen[pid] = {"label": pin.pin_board_label or "(none)",
                         "eec_state": None, "pps_state": None,
                         "eec_prio": None, "pps_prio": None}
        if eec_dev and pin.dev_id == eec_dev.dev_id:
            seen[pid]["eec_state"] = pin.pin_state.value
            seen[pid]["eec_prio"] = pin.pin_priority
        elif pps_dev and pin.dev_id == pps_dev.dev_id:
            seen[pid]["pps_state"] = pin.pin_state.value
            seen[pid]["pps_prio"] = pin.pin_priority

    sorted_pins = sorted(seen.items(),
                         key=lambda x: (x[1]['eec_prio']
                                        if x[1]['eec_prio'] is not None else 999))

    print(f"  {'Pin':<5} {'Label':<30} {'EEC State':<14} {'EEC Prio':<10} "
          f"{'PPS State':<14} {'PPS Prio':<10}")
    print(f"  {'─'*4:<5} {'─'*29:<30} {'─'*13:<14} {'─'*9:<10} "
          f"{'─'*13:<14} {'─'*9:<10}")

    for pid, info in sorted_pins:
        eec_st = info['eec_state'] or "?"
        pps_st = info['pps_state'] or "?"
        eec_pr = str(info['eec_prio']) if info['eec_prio'] is not None else "?"
        pps_pr = str(info['pps_prio']) if info['pps_prio'] is not None else "?"
        marker = "►" if "connected" in (eec_st, pps_st) else " "
        print(f"{marker} {pid:<5} {info['label']:<30} {eec_st:<14} {eec_pr:<10} "
              f"{pps_st:<14} {pps_pr:<10}")

    print()
    print("  ► = currently active (connected)")
    print("  Priority: lower number = higher priority (selected first)")

    # Warn if stuck in holdover
    if _all_disconnected(cgu_inputs):
        print()
        print(RECOVERY_MSG)


def set_pin_state_cmd(dpll, pin_id, label, state_str):
    """Set pin state via pynetlink API."""
    print(f"Setting pin {pin_id} [{label}] \u2192 {state_str}")
    try:
        dpll.set_pin_state(pin_id, state_str)
        print("  OK")
        return True
    except NetlinkException as e:
        print(f"  ERROR: {e}")
        return False
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return False


def set_pin_state_per_device(dpll, pin_id, label, state_str):
    """Set pin state on each parent device individually."""
    from pynetlink.dpll.constants import PinFields
    from pynetlink.dpll.constants import PinParentFields

    pins = dpll.get_pins_by_id(pin_id)
    parent_ids = list(set(pin.dev_id for pin in pins))

    print(f"Setting pin {pin_id} [{label}] \u2192 {state_str} (per-device)")
    success = False
    for parent_id in sorted(parent_ids):
        dev = next((p for p in pins if p.dev_id == parent_id), None)
        dev_type = dev.dev_type.value if dev else "?"
        pin_info = {
            PinFields.ID: pin_id,
            PinFields.PARENT_DEVICE: [
                {
                    PinParentFields.PARENT_ID: parent_id,
                    PinParentFields.STATE: state_str
                }
            ]
        }
        try:
            dpll._set_pin(pin_info)
            print(f"  dev {parent_id} ({dev_type}): OK")
            success = True
        except NetlinkException as e:
            print(f"  dev {parent_id} ({dev_type}): ERROR - {e}")
        except Exception as e:
            print(f"  dev {parent_id} ({dev_type}): ERROR - {type(e).__name__}: {e}")

    return success


def set_pin_priority_cmd(dpll, pin_id, label, prio):
    """Set pin priority via pynetlink API."""
    print(f"Setting pin {pin_id} [{label}] priority \u2192 {prio}")
    try:
        dpll.set_pin_priority(pin_id, prio)
        print("  OK")
        return True
    except NetlinkException as e:
        print(f"  ERROR: {e}")
        return False
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return False


def show_api(dpll):
    """Show pynetlink API info for debugging."""
    import inspect

    print("NetlinkDPLL methods:")
    for name in sorted(dir(dpll)):
        if name.startswith('_'):
            continue
        obj = getattr(dpll, name)
        if callable(obj):
            try:
                sig = inspect.signature(obj)
                print(f"  {name}{sig}")
            except (ValueError, TypeError):
                print(f"  {name}(...)")

    print()
    print("PinState enum values:")
    for s in PinState:
        print(f"  {s.name} = {repr(s.value)}")

    print()
    print("DeviceType enum values:")
    for d in DeviceType:
        print(f"  {d.name} = {repr(d.value)}")


def cmd_disconnect(dpll, pin_arg):
    _, cgu_inputs, _, _ = get_cgu_info(dpll)
    pin_id, label = resolve_pin(cgu_inputs, pin_arg)
    if pin_id is None:
        return 1

    # Skip if already disconnected
    if all(p.pin_state == PinState.DISCONNECTED
           for p in cgu_inputs if p.pin_id == pin_id):
        print(f"Pin {pin_id} [{label}] is already disconnected")
        return 0

    # Warn if this will leave no active/selectable pins
    other_active = [p for p in cgu_inputs
                    if p.pin_id != pin_id
                    and p.pin_state in (PinState.CONNECTED, PinState.SELECTABLE)]
    if not other_active:
        print(f"  WARNING: '{label}' appears to be the only active source.")
        print("  Disconnecting will put CGU into unrecoverable holdover.")
        print("  Recovery requires: sudo rmmod ice && sudo modprobe ice")
        print()

    return 0 if set_pin_state_cmd(dpll, pin_id, label, "disconnected") else 1


def cmd_selectable(dpll, pin_arg):
    """Set pin to selectable (eligible for auto-selection)."""
    _, cgu_inputs, _, _ = get_cgu_info(dpll)
    pin_id, label = resolve_pin(cgu_inputs, pin_arg)
    if pin_id is None:
        return 1

    # Skip if already selectable
    if any(p.pin_id == pin_id and p.pin_state == PinState.SELECTABLE
           for p in cgu_inputs):
        print(f"Pin {pin_id} [{label}] is already selectable")
        return 0

    return 0 if set_pin_state_cmd(dpll, pin_id, label, "selectable") else 1


def cmd_connect(dpll, pin_arg):
    """Connect pin: try 'connected' per-device, fall back to 'selectable'."""
    _, cgu_inputs, _, _ = get_cgu_info(dpll)
    pin_id, label = resolve_pin(cgu_inputs, pin_arg)
    if pin_id is None:
        return 1

    # Skip if already connected (driver rejects redundant state set)
    if any(p.pin_id == pin_id and p.pin_state == PinState.CONNECTED
           for p in cgu_inputs):
        print(f"Pin {pin_id} [{label}] is already connected")
        return 0

    # Try connected first
    if set_pin_state_per_device(dpll, pin_id, label, "connected"):
        return 0

    # Fall back to selectable
    print("  Falling back to 'selectable'...")
    set_pin_state_per_device(dpll, pin_id, label, "selectable")

    # Re-check if CGU is stuck
    _, cgu_inputs_now, _, _ = get_cgu_info(dpll)
    if _all_disconnected(cgu_inputs_now):
        print()
        print(RECOVERY_MSG)
        return 1

    return 0


def cmd_prio(dpll, pin_arg, prio_val):
    _, cgu_inputs, _, _ = get_cgu_info(dpll)
    pin_id, label = resolve_pin(cgu_inputs, pin_arg)
    if pin_id is None:
        return 1
    try:
        prio = int(prio_val)
    except ValueError:
        print(f"ERROR: Priority must be integer, got '{prio_val}'")
        return 1
    return 0 if set_pin_priority_cmd(dpll, pin_id, label, prio) else 1


def cmd_switch(dpll, pin_arg):
    _, cgu_inputs, _, _ = get_cgu_info(dpll)
    pin_id, label = resolve_pin(cgu_inputs, pin_arg)
    if pin_id is None:
        return 1

    # Connect target first to avoid holdover during transition
    # Skip if already connected (driver rejects redundant state set)
    already_connected = any(
        p.pin_id == pin_id and p.pin_state == PinState.CONNECTED
        for p in cgu_inputs)
    if not already_connected:
        ok = set_pin_state_cmd(dpll, pin_id, label, "connected")
        if not ok:
            return 1

    # Now disconnect all other currently-connected inputs
    all_pin_ids = set(p.pin_id for p in cgu_inputs)
    for pid in sorted(all_pin_ids):
        if pid == pin_id:
            continue
        pin_objs = [p for p in cgu_inputs if p.pin_id == pid]
        if any(p.pin_state == PinState.CONNECTED for p in pin_objs):
            plabel = pin_objs[0].pin_board_label or "(none)"
            set_pin_state_cmd(dpll, pid, plabel, "disconnected")

    print(f"\nSwitched active source \u2192 pin {pin_id} [{label}]")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    cmd = sys.argv[1].lower()

    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    dpll = NetlinkDPLL()

    if cmd == "show":
        show_inputs(dpll)
    elif cmd == "api":
        show_api(dpll)
    elif cmd == "disconnect" and len(sys.argv) >= 3:
        return cmd_disconnect(dpll, sys.argv[2])
    elif cmd == "connect" and len(sys.argv) >= 3:
        return cmd_connect(dpll, sys.argv[2])
    elif cmd == "selectable" and len(sys.argv) >= 3:
        return cmd_selectable(dpll, sys.argv[2])
    elif cmd == "prio" and len(sys.argv) >= 4:
        return cmd_prio(dpll, sys.argv[2], sys.argv[3])
    elif cmd == "switch" and len(sys.argv) >= 3:
        return cmd_switch(dpll, sys.argv[2])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
