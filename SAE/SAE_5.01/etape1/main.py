from umqtt.simple import MQTTClient
import time
import ubinascii
import machine
import pycom
from pytrack import Pytrack
from L76GNSS import L76GNSS

Constants,
RED = 0xFF0000
GREEN = 0x00FF00
BLUE = 0x0000FF
OFF = 0x000000
MQTT_BROKER = "test.mosquitto.org"
CLIENT_ID = ubinascii.hexlify(machine.unique_id())
SUBSCRIBE_TOPIC = b"titi"
PUBLISH_TOPIC = b"titi"
last_publish = time.time()
publish_interval = 5

py = Pytrack()
gps = L76GNSS(py, timeout=30)

def sub_cb(topic, msg):
    print((topic, msg))
    if msg.decode() == "ON":
        pycom.rgbled(0x007f00)
    else:
        pycom.rgbled(0x000000)

def main():
    mqttClient = MQTTClient(CLIENT_ID, MQTT_BROKER, keepalive=300)
    mqttClient.set_callback(sub_cb)
    mqttClient.connect()
    mqttClient.subscribe(SUBSCRIBE_TOPIC)

    while True:
        mqttClient.check_msg()
        global last_publish
        if (time.time() - last_publish) >= publish_interval:
            """
            coord = gps.coordinates()
            lat = coord[0]
            lon = coord[1]
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
            """
            message = "{},{}".format(48.5660, 2.35220).encode()
            mqttClient.publish(PUBLISH_TOPIC, message)
            last_publish = time.time()
        time.sleep(1)

if name == "main":
    while True:
        main()
