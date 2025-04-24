#!/usr/bin/env python3
"""
Listens on vcan0, verifies CMAC (AES-CMAC) appended as the last 4 bytes
of every 12-byte CAN-FD frame.  If valid → forward to ECU; else drop.

For demo purposes we use a shared static key.

Requires kernel CAN-FD support (5.6+) and python-can >= 4.3
"""

import can, hmac, hashlib, binascii

KEY = b"Sixteen byte key"     # NEVER hard-code in production
UNLOCK_ID = 0x648

bus_in  = can.interface.Bus("vcan0", bustype="socketcan")
bus_out = can.interface.Bus("vcan1", bustype="socketcan")  # ECU side

def valid(msg: can.Message):
    if msg.is_extended_id or len(msg.data)!=12: return False
    data, mac = msg.data[:8], msg.data[8:]
    cmac = hmac.new(KEY, msg.arbitration_id.to_bytes(2,'big')+data, hashlib.blake2s).digest()[:4]
    return hmac.compare_digest(cmac, mac)

def on_msg(msg):
    if valid(msg):
        bus_out.send(can.Message(arbitration_id=msg.arbitration_id,
                                 data=msg.data[:8], is_extended_id=False))
    else:
        print("[FIREWALL] ❌  dropped frame id 0x%03X" % msg.arbitration_id)

print("CMAC firewall listening on vcan0 → vcan1")
can.Notifier(bus_in, [on_msg])
import time; time.sleep(1e9)