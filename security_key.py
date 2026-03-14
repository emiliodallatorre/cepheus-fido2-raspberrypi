#!/usr/bin/python3

import random
import threading
import time

import cbor2
import RPi.GPIO as GPIO

from fido2sk.authenticator_api import (
    authenticatorGetAssertion,
    authenticatorGetInfo,
    authenticatorGetNextAssertion,
    authenticatorMakeCredential,
    authenticatorReset,
)
from fido2sk.key_store import initialize_store

# Per-channel packet assembly buffer.
full_data = {}


def CTAPHID_CBOR(channel, payload):
    command = 0x10
    cbor_command = payload[0]
    cbor_command_bytes = payload[0:1]
    show(cbor_command_bytes, 'CBOR Command')
    cbor_payload = payload[1:]
    success = 0

    if cbor_command == 0x04:
        reply_payload, success = authenticatorGetInfo()
    if cbor_command == 0x01:
        reply_payload, success = authenticatorMakeCredential(cbor2.loads(cbor_payload))
    if cbor_command == 0x02:
        reply_payload, success = authenticatorGetAssertion(cbor2.loads(cbor_payload))
    if cbor_command == 0x08:
        reply_payload, success = authenticatorGetNextAssertion()
    if cbor_command == 0x07:
        reply_payload, success = authenticatorReset()

    if success == 0:
        reply = (0).to_bytes(1, 'big')
        reply = reply + cbor2.dumps(reply_payload)
        bcnt = len(reply)
        to_send = preprocess_send_data(channel, command, bcnt, reply)
        send_data(to_send)
    else:
        reply = success.to_bytes(1, 'big')
        bcnt = len(reply)
        to_send = preprocess_send_data(channel, command, bcnt, reply)
        send_data(to_send)


def make_channel_id():
    value = random.randint(1, 0xfffffffe)
    return value.to_bytes(4, 'big')


def CTAPHID_INIT(channel, payload):
    if channel == bytes.fromhex('ffffffff'):
        channel_new = make_channel_id()
    else:
        channel_new = channel
        cstr = channel.hex()
        if cstr in full_data:
            full_data.pop(cstr)

    command = 0x06
    bcnt = 17
    data = payload
    data = data + channel_new
    data = data + (2).to_bytes(1, 'big')
    data = data + (1).to_bytes(1, 'big')
    data = data + (0).to_bytes(1, 'big')
    data = data + (1).to_bytes(1, 'big')
    data = data + (13).to_bytes(1, 'big')

    to_send = preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)


def CTAPHID_PING(channel, payload):
    command = 0x01
    bcnt = len(payload)
    to_send = preprocess_send_data(channel, command, bcnt, payload)
    send_data(to_send)


def CTAPHID_CANCEL(channel, payload):
    command = 0x11
    bcnt = 0
    to_send = preprocess_send_data(channel, command, bcnt, b'')
    send_data(to_send)


def CTAPHID_WINK(channel, payload):
    command = 0x08
    bcnt = 0
    print("Authenticator wink")
    to_send = preprocess_send_data(channel, command, bcnt, b'')
    send_data(to_send)


def CTAPHID_ERROR(channel, error_code=0x7f):
    command = 0x3f
    bcnt = 1
    data = (error_code).to_bytes(1, 'big')
    to_send = preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)


def CTAPHID_KEEPALIVE(channel, status):
    command = 0x3b
    bcnt = 1
    data = status.to_bytes(1, 'big')
    to_send = preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)


task_thread = None
stop_event = threading.Event()


def send_keepalive(channel, payload):
    global task_thread, stop_event
    while not stop_event.is_set():
        time.sleep(0.08)
        CTAPHID_KEEPALIVE(channel, payload)


def start_keepalive(channel, payload):
    global task_thread, stop_event
    if task_thread and task_thread.is_alive():
        return
    stop_event.clear()
    task_thread = threading.Thread(target=send_keepalive, args=(channel, payload))
    task_thread.start()


def stop_keepalive():
    global task_thread, stop_event
    if task_thread and task_thread.is_alive():
        stop_event.set()
        task_thread.join()


def run_commands(channel, command, bcnt, payload):
    if command == 0x06:
        CTAPHID_INIT(channel, payload)
    if command == 0x01:
        CTAPHID_PING(channel, payload)
    if command == 0x11:
        CTAPHID_CANCEL(channel, payload)
    if command == 0x08:
        CTAPHID_WINK(channel, payload)
    if command == 0x10:
        CTAPHID_CBOR(channel, payload)


def process_packet(packet):
    channel = packet[0:4]
    if channel.hex() == '00000000':
        channel = bytes.fromhex('ffffffff')
    cstr = channel.hex()
    show(channel, 'channel')
    byte4 = packet[4]

    if byte4 > 0x7f:
        print("Command packet")
        command = packet[4] & 0x7f
        command = command.to_bytes(1, 'big')
        show(command, 'CMD')
        bcnt_bytes = packet[5:7]
        show(bcnt_bytes, "BCNT")
        bcnt = int.from_bytes(bcnt_bytes, 'big')
        print("Payload size ", bcnt)
        num_pack = calc_num_packets(bcnt)

        seqnum = -1
        payload = packet[7:]

        full_data[cstr] = [None] * (num_pack + 2)
        full_data[cstr][0] = command
        full_data[cstr][1] = bcnt
    else:
        print("Sequence packet")
        seq = packet[4:5]
        show(seq, "SEQ")
        seqnum = packet[4]
        payload = packet[5:]

    seqnum = seqnum + 3
    try:
        full_data[cstr][seqnum] = payload
    except Exception:
        pass

    try:
        process_transcation(channel)
    except Exception:
        CTAPHID_ERROR(channel)


def show(packet, dat=""):
    print(dat, " ", " ".join(packet.hex()[i:i + 2] for i in range(0, len(packet.hex()), 2)))
    print()


def show_string(packet):
    print("Showing packet string ", packet.decode('utf-8', 'replace'))


def preprocess_send_data(channel, command, bcnt, payload):
    show(payload, 'Pre process')
    num_pack = calc_num_packets(bcnt)
    first_packet_size = 64 - 7
    other_packet_size = 64 - 5
    packet_list = [None] * num_pack

    if bcnt <= first_packet_size:
        packet_list[0] = payload
    else:
        packet_list[0] = payload[:first_packet_size]
        payload = payload[first_packet_size:]
        i = 1
        while len(payload) > 0:
            packet_list[i] = payload[:other_packet_size]
            payload = payload[other_packet_size:]
            i = i + 1

    last_pack = num_pack - 1
    last_size = other_packet_size
    if last_pack == 0:
        last_size = first_packet_size

    if len(packet_list[last_pack]) < last_size:
        pad = last_size - len(packet_list[last_pack])
        packet_list[last_pack] = packet_list[last_pack] + b'\x00' * pad

    full_packets = [None] * num_pack
    first_packet = channel
    first_packet = first_packet + (command | 0x80).to_bytes(1, 'big')
    first_packet = first_packet + bcnt.to_bytes(2, 'big')
    first_packet = first_packet + packet_list[0]
    full_packets[0] = first_packet

    for i in range(1, len(packet_list)):
        packet = channel
        packet = packet + (i - 1).to_bytes(1, 'big')
        packet = packet + packet_list[i]
        full_packets[i] = packet

    return full_packets


def send_data(preprocessed_data):
    indicator_on()
    for x in preprocessed_data:
        show(x, "Sending packet")
        port.write(x)
        time.sleep(0.001)
    indicator_off()


def calc_num_packets(bcnt):
    first_packet_size = 64 - 7
    other_packet_size = 64 - 5
    num_pack = 1
    bcnt = bcnt - first_packet_size
    if bcnt < 0:
        bcnt = 0
    num_pack = num_pack + (bcnt // other_packet_size)
    bcnt = bcnt % other_packet_size
    if bcnt > 0:
        num_pack = num_pack + 1
        bcnt = 0
    return num_pack


def process_transcation(channel):
    cstr = channel.hex()
    data = full_data[cstr]
    if None in data:
        return

    payload = data[2]
    i = 3
    while i < len(data):
        payload = payload + data[i]
        i = i + 1

    bcnt = data[1]
    payload = payload[:bcnt]
    command = int.from_bytes(data[0], 'big')
    run_commands(channel, command, bcnt, payload)


# LED indicator for tx/rx activity.
led = 16
GPIO.setmode(GPIO.BCM)
GPIO.setup(led, GPIO.OUT)


def indicator_on():
    GPIO.output(led, GPIO.HIGH)


def indicator_off():
    GPIO.output(led, GPIO.LOW)


# Initialize encrypted credential store before HID loop starts.
initialize_store()

port = None
portname = '/dev/hidg0'
while True:
    try:
        port = open(portname, 'rb+')
        print('Port opened')
        break
    except PermissionError:
        time.sleep(1)
    except Exception:
        time.sleep(1)

indicator_on()
time.sleep(2)
indicator_off()


if __name__ == '__main__':
    while True:
        packet = port.read(64)
        if packet is None:
            continue
        show(packet, 'Full packet')
        process_packet(packet)
