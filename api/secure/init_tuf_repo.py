#!/usr/bin/env python3
"""
One-time helper that initialises a minimal TUF repo with *root*, *targets*,
*snapshot*, *timestamp* roles and signs a dummy firmware.

Usage:  python init_tuf_repo.py  firmware/latest.bin
Repo out-dir =  tuf_repo/
"""
import sys, pathlib, shutil, tuf.api.metadata as md

if len(sys.argv)<2:
    print("give path to firmware file"); sys.exit(1)

FIRM = pathlib.Path(sys.argv[1]); FIRM.parent.mkdir(parents=True, exist_ok=True)
REPO = pathlib.Path("tuf_repo");   REPO.mkdir(exist_ok=True)

# ── generate temp Ed25519 keys ──
root_key = md.Key.generate()
targets_key = md.Key.generate()

# ── root metadata ──
root = md.Root(version=1, expiration=None)
root.add_key(root_key, "root")
root.add_key(targets_key, "targets")
root.add_role("root", [root_key.keyid])
root.add_role("targets", [targets_key.keyid])
root.sign(root_key)
root.to_file(REPO/"1.root.json")

# ── targets ──
targets = md.Targets(version=1, expiration=None)
targets.add_target(str(FIRM.name), md.TargetFile.from_file(FIRM))
targets.sign(targets_key)
targets.to_file(REPO/"1.targets.json")

# ── snapshot & timestamp ──
snap = md.Snapshot(version=1, expiration=None)
snap.add_meta("targets.json", md.MetaFile(version=targets.version))
snap.sign(root_key)
snap.to_file(REPO/"1.snapshot.json")

ts = md.Timestamp(version=1, expiration=None)
ts.snapshot_meta = md.MetaFile(version=snap.version)
ts.sign(root_key)
ts.to_file(REPO/"1.timestamp.json")

print("TUF repo initialised in", REPO.resolve())