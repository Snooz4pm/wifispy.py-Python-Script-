import os
import logging
import random
import time
import datetime
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11

interface = 'wlan1mon'
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

queue = []

subtypes_management = {
    0: 'association-request',
    1: 'association-response',
    # ... Add other subtypes as needed
}

subtypes_control = {
    8: 'block-acknowledgement-request',
    9: 'block-acknowledgement',
    # ... Add other subtypes as needed
}

subtypes_data = {
    0: 'data',
    1: 'data-and-contention-free-acknowledgement',
    # ... Add other subtypes as needed
}

def start():
    logging.basicConfig(filename='wifispy.log', format='%(levelname)s:%(message)s', level=logging.INFO)
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

    # Create a new SQLite database
    db = sqlite3.connect('wifispy.sqlite3')
    cursor = db.cursor()
    create_table = (
        "CREATE TABLE IF NOT EXISTS packets "
        "("
        "timestamp TEXT,"
        "type TEXT,"
        "subtype TEXT,"
        "strength INTEGER,"
        "source_address TEXT,"
        "destination_address TEXT,"
        "access_point_name TEXT,"
        "access_point_address TEXT"
        ")"
    )
    cursor.execute(create_table)
    db.commit()
    cursor.close()

    stop_rotating = rotator(channels)
    stop_writing = writer(db)
    try:
        sniff(iface=interface, prn=process_packet)
    except KeyboardInterrupt:
        sys.exit()
    finally:
        stop_writing.set()
        stop_rotating.set()
        db.close()

def rotator(channels):
    def rotate(stop):
        while not stop.is_set():
            try:
                channel = str(random.choice(channels))
                logging.info('Changing to channel ' + channel)
                os.system(change_channel % channel)
                time.sleep(1)  # seconds
            except KeyboardInterrupt:
                pass

    stop = multiprocessing.Event()
    multiprocessing.Process(target=rotate, args=[stop]).start()
    return stop

def writer(db):
    def write(stop):
        while not stop.is_set():
            try:
                logging.info('Writing...')
                cursor = db.cursor()
                for item in queue:
                    insert = (
                        "INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    )
                    cursor.execute(insert, item)
                db.commit()
                cursor.close()
                queue.clear()
                time.sleep(1)  # seconds
            except KeyboardInterrupt:
                pass

    stop = multiprocessing.Event()
    multiprocessing.Process(target=write, args=[stop]).start()
    return stop

def process_packet(packet):
    timestamp = datetime.datetime.now().isoformat()
    if packet.haslayer(RadioTap) and packet.haslayer(Dot11):
        packet_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 0  # dBm
        frame = packet.getlayer(Dot11)
        if frame.type == 0:  # Management frame
            subtype = subtypes_management.get(frame.subtype, 'unknown-management-subtype')
            record = (
                timestamp,
                'management',
                subtype,
                packet_signal,
                frame.addr2,
                frame.addr1,
                frame.info.decode('utf-8') if hasattr(frame, 'info') else '(n/a)',
                frame.addr3,
            )
            queue.append(record)
        elif frame.type == 1:  # Control frame
            subtype = subtypes_control.get(frame.subtype, 'unknown-control-subtype')
            record = (
                timestamp,
                'control',
                subtype,
                packet_signal,
                '(n/a)',  # not available in control packets
                '(n/a)',  # not available in control packets
                '(n/a)',  # not available in control packets
                '(n/a)',  # not available in control packets
            )
            queue.append(record)
        elif frame.type == 2:  # Data frame
            subtype = subtypes_data.get(frame.subtype, 'unknown-data-subtype')
            record = (
                timestamp,
                'data',
                subtype,
                packet_signal,
                frame.addr2,
                frame.addr1,
                '(n/a)',  # not available in data packets
                frame.addr3 if hasattr(frame, 'addr3') else '(n/a)',
            )
            queue.append(record)

start()
