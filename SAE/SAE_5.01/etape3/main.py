from machine import I2C
from L76GNSS import L76GNSS
from pytrack import Pytrack
import time
from network import LoRa
import socket
import ubinascii

lora = LoRa(mode=LoRa.LORAWAN, region=LoRa.EU868)
app_eui = ubinascii.unhexlify('70F503D5FC099DF2')
app_key = ubinascii.unhexlify('70F503D5FC099DF270F503D5FC099DF2')
lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key), timeout=0)
s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
s.setsockopt(socket.SOL_LORA, socket.SO_DR, 5)
s.setblocking(True)


py = Pytrack()
l76 = L76GNSS(py, timeout=30)

while True:
    coord = l76.coordinates()
    while coord == None:
        coord = l76.coordinates()
        print(coord)
        time.sleep(1)

    lat = coord[0]
    lon = coord[1]

    print("{} - {}".format(lat, lon))

    if (lat != None) and (lon != None):
        lat = round(lat, 4)
        lon = round(lon, 4)
        lat_int = int(lat * 10000)
        lon_int = int(lon * 10000)

        data = bytearray(6)
        data[0] = (lat_int >> 16) & 0xFF
        data[1] = (lat_int >> 8) & 0xFF
        data[2] = lat_int & 0xFF
        data[3] = (lon_int >> 16) & 0xFF
        data[4] = (lon_int >> 8) & 0xFF
        data[5] = lon_int & 0xFF

        s.send(data)

        time.sleep(5)
