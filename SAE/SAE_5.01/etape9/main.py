from LIS2HH12 import LIS2HH12
from pytrack import Pytrack
import time
import machine
from machine import Pin
from network import LoRa
import socket
import ubinascii

lora = LoRa(mode=LoRa.LORAWAN, region=LoRa.EU868)
app_eui = ubinascii.unhexlify('70F503D5FC099DF2')
app_key = ubinascii.unhexlify('70F503D5FC099DF270F503D5FC099DF2')

py = Pytrack()
acc = LIS2HH12()

SENSITIVITY = 5.0
SLEEP_TIMEOUT = 20
GPS_COORDS = (48.5660, 23.5220)
LORA_DR = 5

gps_enabled = True

def setup_lora():
    lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key), timeout=0)
    while not lora.has_joined():
        time.sleep(2.5)
    s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
    s.setsockopt(socket.SOL_LORA, socket.SO_DR, LORA_DR)
    return s

def prepare_payload(lat, lon, gps_state):
    lat_int = int(lat * 16777215 / 180)
    lon_int = int(lon * 16777215 / 360)
    payload = bytearray()
    payload.extend(lat_int.to_bytes(3, 'big'))
    payload.extend(lon_int.to_bytes(3, 'big'))
    payload.extend(bytes([gps_state]))
    return payload

def handle_downlink(data):
    global gps_enabled
    if data:
        command = data[0]
        if command == 0x00:
            gps_enabled = False
            print("GPS desactive par downlink")
            return True
    return False

def main():
    global gps_enabled
    socket = setup_lora()
    socket.setblocking(True)
    last_activity = time.time()
    last_pitch, last_roll = acc.pitch(), acc.roll()

    while True:
        print("en fonctionnement")
        current_pitch, current_roll = acc.pitch(), acc.roll()

        if gps_enabled and (abs(current_pitch - last_pitch) > SENSITIVITY or abs(current_roll - last_roll) > SENSITIVITY):
            print("Mouvement")
            last_activity = time.time()

            payload = prepare_payload(GPS_COORDS[0], GPS_COORDS[1], 1)
            socket.setblocking(False)
            socket.send(payload)

            time.sleep(2)
            data = socket.recv(64)
            if handle_downlink(data):
                payload = prepare_payload(GPS_COORDS[0], GPS_COORDS[1], 0)
                socket.send(payload)
                pin = Pin('P13', mode=Pin.IN, pull=Pin.PULL_UP)
                machine.pin_sleep_wakeup(pins = ['P13'], mode=machine.WAKEUP_ANY_HIGH, enable_pull=True)
                print("passage en deep sleep")
                machine.deepsleep()

            last_pitch, last_roll = current_pitch, current_roll

        if (time.time() - last_activity) > SLEEP_TIMEOUT:
            print("passage en deep sleep")
            payload = prepare_payload(GPS_COORDS[0], GPS_COORDS[1], 0)
            socket.send(payload)

            acc.enable_activity_interrupt(threshold=500, duration=400)
            pin = Pin('P13', mode=Pin.IN, pull=Pin.PULL_UP)
            machine.pin_sleep_wakeup(pins = ['P13'], mode=machine.WAKEUP_ANY_HIGH, enable_pull=True)
            machine.deepsleep()

        time.sleep(3)

if __name__ == '__main__':
    main()
