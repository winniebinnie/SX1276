from machine import Pin
import time, urandom as random, uhashlib, cryptolib, struct
from lora import SX1276

# Heltec WiFi LoRa 32 V2 pin mapping
LoRa_MISO_Pin = 19
LoRa_MOSI_Pin = 27
LoRa_SCK_Pin  = 5
LoRa_CS_Pin   = 18
LoRa_RST_Pin  = 14
LoRa_DIO0_Pin = 26
LoRa_DIO1_Pin = 35
LoRa_DIO2_Pin = 34
SPI_CH        = 1

random.seed(11)
channels2Hopping = [914_000_000 + 200_000 * random.randint(0, 10) for _ in range(128)]

LoRa_id = 1
lora = SX1276(
    LoRa_RST_Pin,
    LoRa_CS_Pin,
    SPI_CH,
    LoRa_SCK_Pin,
    LoRa_MOSI_Pin,
    LoRa_MISO_Pin,
    LoRa_DIO0_Pin,
    LoRa_DIO1_Pin,
    LoRa_id,
    channels2Hopping,
    debug=False,
)

WORD = b"WORD"

session_key = None


def get_payload(self, data, SNR, RSSI):
    global session_key
    if self.latest_rx_pkt_type == self.PKT_TYPE["ACK"]:
        iv = data[:16]
        nonce = data[16:24]
        ciphertext = data[24:]
        chan = 0
        time_slot = 0
        base = int(RSSI)
        for off in range(-5, 6):
            guess = base + off
            material = nonce + struct.pack("b", guess) + bytes([chan]) + struct.pack("I", time_slot)
            key_i = uhashlib.sha256(material).digest()[:16]
            cipher = cryptolib.aes(key_i, 6, iv)
            if cipher.decrypt(ciphertext) == WORD:
                session_key = key_i
                break


lora.req_packet_handler = get_payload

payload = "Hello~"
print("[Sending]", payload)
lora.send(dst_id=0, msg=payload, pkt_type=lora.PKT_TYPE["REQ"])

while not lora.is_available:
    time.sleep(1)

print("[Session Key]", session_key)

