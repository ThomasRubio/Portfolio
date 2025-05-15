from network import LoRa
import socket
import time
import ubinascii

lora = LoRa(mode=LoRa.LORAWAN, region=LoRa.EU868)
app_eui = ubinascii.unhexlify('70F503D5FC099DF2')
app_key = ubinascii.unhexlify('70F503D5FC099DF270F503D5FC099DF2')

lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key), timeout=0)

while not lora.has_joined():
    time.sleep(2.5)
    print('Not yet joined...')

print('Joined')

s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
s.setsockopt(socket.SOL_LORA, socket.SO_DR, 5)
s.setblocking(True)

latitude = int(48.5660 * 16777215 / 180)
longitude = int(23.5220 * 16777215 / 360)

payload = bytearray()
payload.extend(latitude.to_bytes(3, 'big'))
payload.extend(longitude.to_bytes(3, 'big'))

s.setblocking(False)

while True:
    s.send(payload)
    data = s.recv(64)
    if data != b'':
        print(data)
        if data == b'\x01':
            print("ON")
        elif data == b'\x00':
            print("OFF")
    time.sleep(5)
