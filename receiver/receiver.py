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

LoRa_id = 0
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
    if self.latest_rx_pkt_type == self.PKT_TYPE["REQ"] and data.endswith(b"Hello~"):
        nonce = bytes(random.getrandbits(8) for _ in range(8))
        rssi_q = int(RSSI)
        chan = 0
        time_slot = 0
        material = nonce + struct.pack("b", rssi_q) + bytes([chan]) + struct.pack("I", time_slot)
        key = uhashlib.sha256(material).digest()[:16]
        iv = bytes(random.getrandbits(8) for _ in range(16))
        cipher = cryptolib.aes(key, 6, iv)
        ciphertext = cipher.encrypt(WORD)
        payload = iv + nonce + ciphertext
        self.send(
            dst_id=self.pending_src_id,
            pkt_id=self.pending_pkt_id,
            pkt_type=self.PKT_TYPE["ACK"],
            msg=payload,
        )
        session_key = key


lora.req_packet_handler = get_payload
lora.mode = "RXCONTINUOUS"

while not lora.is_available:
    time.sleep(1)

print("[Session Key]", session_key)

