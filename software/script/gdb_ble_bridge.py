#!/usr/bin/env python3
"""
TCP <-> BLE bridge for the gdb_gateway standalone mode (BLE side).

Arm gdb_gateway on the device first (both-button long press). Once armed the
BLE NUS link carries raw GDB RSP bytes instead of the framed CLI protocol
(firmware/application/src/utils/gdb_rsp.c), so this script is a dumb byte
pump -- no framing, no interpretation -- between a local TCP socket and
chameleon_ble.BLESerialShim. gdb connects to the TCP side:

    (gdb) target remote localhost:3333

Run from software/script/ (needs chameleon_ble.py, i.e. bleak, alongside it).
"""
import argparse
import socket
import sys
import threading
import time

from chameleon_ble import BLEConnectException, BLESerialShim


def ble_connect(ble, target):
    while True:
        try:
            ble.connect(target)
            return
        except BLEConnectException as e:
            print(f"BLE connect failed ({e}), retrying in 2s...")
            time.sleep(2)


def pump_tcp_to_ble(conn, ble, stop):
    conn.settimeout(0.1)
    while not stop.is_set():
        try:
            data = conn.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        try:
            ble.write(data)
        except Exception:
            break
    stop.set()


def pump_ble_to_tcp(conn, ble, stop):
    while not stop.is_set():
        data = ble.read(512)
        if data:
            try:
                conn.sendall(data)
            except OSError:
                break
        elif not ble.is_open:
            break
    stop.set()


def serve(ble, target, host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f"listening on {host}:{port} -- in gdb: target remote {host}:{port}")

    while True:
        conn, addr = srv.accept()
        print(f"gdb connected from {addr}")
        if not ble.is_open:
            print("BLE link is down, reconnecting...")
            ble_connect(ble, target)

        stop = threading.Event()
        t1 = threading.Thread(target=pump_tcp_to_ble, args=(conn, ble, stop), daemon=True)
        t2 = threading.Thread(target=pump_ble_to_tcp, args=(conn, ble, stop), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        conn.close()
        print("gdb disconnected")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("ble_target", nargs="?", default="",
                     help="BLE address or name filter (default: first Chameleon found)")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=3333)
    args = ap.parse_args()

    ble = BLESerialShim()
    print("connecting to BLE NUS...")
    ble_connect(ble, args.ble_target)
    print("connected. Arm gdb_gateway on the device now if you haven't.")
    try:
        serve(ble, args.ble_target, args.host, args.port)
    except KeyboardInterrupt:
        pass
    finally:
        ble.close()


if __name__ == "__main__":
    main()
