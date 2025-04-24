#!/usr/bin/env python3
"""
Broadcasts arbitrary CAN frames on vcan0 every 2 s.  Registers a listener
(virtual ECU) that prints *any* unlock frame (ID 0x648) it receives.

Requires:
    $ sudo modprobe vcan
    $ sudo ip link add dev vcan0 type vcan
    $ sudo ip link set vcan0 up
    pip install python-can
"""

import can, time, random

bus = can.interface.Bus("vcan0", bustype="socketcan")

def virtual_ecu(msg: can.Message):
    if msg.arbitration_id == 0x648:
        print(f"[ECU] 🚗  Door unlocked!  data={msg.data.hex()}")

listener = can.Listener(on_message_received=virtual_ecu)
notifier = can.Notifier(bus, [listener])

while True:
    data = bytes(random.getrandbits(8) for _ in range(8))
    msg  = can.Message(arbitration_id=0x648, data=data, is_extended_id=False)
    bus.send(msg)
    time.sleep(2)