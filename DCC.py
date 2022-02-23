#Author:Rotaru Andrei <rotaru.andrei98@gmail.com>
#Project build for fun, and learning process(COSE, Cryptography).
#Using random generated EC key in order to sign the certificate.
#Using, real kID from Romania.


import cbor2
import zlib
import unidecode
import json
import pyqrcode
import png
from pyqrcode import QRCode


from base45 import b45encode
from base64 import b64decode
from binascii import unhexlify
from random import randrange
from datetime import datetime

from cose.messages import Sign1Message, CoseMessage
from cose.keys.curves import P256
from cose.algorithms import Es256
from cose.headers import Algorithm, KID
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpD, EC2KpCurve, KpKty
from cose.keys.keytype import KtyEC2

from cryptography.hazmat.primitives.serialization import load_pem_private_key

def generateID(length):
    string = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    pieces = []
    for i in range(length):
        pieces.append(string[randrange(len(string))])
    return ''.join(pieces)


#Private Key data
Key_pem = b'-----BEGIN EC PRIVATE KEY-----\n'\
    b'MHcCAQEEICx6hY95UOhNCm04Y5FnJpx1uLu50idO4wo5WY+DJ1nnoAoGCCqGSM49\n'\
    b'AwEHoUQDQgAEXh4CnoQEJ+BTD+82pd1gSdMBD9vD8E3Z7izpg8wlOGQtr0C9MDgH\n'\
    b'O0XTJxbNoKMatxJf/mlLMLyNjYCM2e4NMw==\n'\
    b'-----END EC PRIVATE KEY-----'

keyfile = load_pem_private_key(Key_pem, password=None)
privateKey = keyfile.private_numbers().private_value.to_bytes(32, byteorder="big")

#Key ID value
keyid = b64decode('hA1+pwEOxCI=')

#Set identity data:
family_name = "JON"
given_name = "DOE"

#yyyy-mm-dd
birthdate = "1990-01-25"
country = "RO"

#yyyy-mm-dd
last_vaccination_date = "2021-11-25"

#Certificate data:
cert_issuer = "Ministry of Health"
time_to_live = (180*24*3600)*0
issuing_country = "RO"
cert_id = "URN:UVCI:01:"+str(issuing_country)+":"+str(generateID(30))+"#"+str(generateID(2))

#Vaccine data:
vaccine_manufacturer = "ORG-100030215"
vaccine_id = "EU/1/20/1528"

dn = 2 #number of doses
sd = 2 #total number of doses
tg = "840539006"
vp = "J07BX03"
version = "1.3.0"

fnt = unidecode.unidecode(family_name).upper().replace(" ", "<")
gnt = unidecode.unidecode(given_name).upper().replace(" ", "<")


json_issuance = '"v": [{"ci": "' + cert_id + '", "co": "' + country + '", "dn": ' + str(dn) + ', "dt": "' + \
last_vaccination_date + '", "is": "' + cert_issuer + '", "ma": "' + vaccine_manufacturer + \
'", "mp": "' + vaccine_id + '", "sd": ' + str(sd) + ', "tg": "' + tg + '", "vp": "' + vp + '"}]'
json_name = '"nam": {"fn": "' + family_name + '", "gn": "' + given_name + '", "fnt": "' + fnt + '", "gnt": "' + gnt + '"}'
json_payload = '{ ' + json_issuance + ', "dob": "' + birthdate + '", ' + json_name + ', "ver": "' + version + '"}'

json_payload = json_payload.encode("utf-8")
json_payload = json.loads(json_payload.decode("utf-8"))

json_payload =  {
    1: issuing_country,
    4: 1656622799,
    6: int(datetime.today().timestamp()),
    -260 :{
        1: json_payload,
        },
    }

payload = cbor2.dumps(json_payload)

message = Sign1Message(phdr={Algorithm:Es256, KID:keyid}, payload=payload)

Key_options = {
    KpKty:KtyEC2,
    KpAlg:Es256,
    EC2KpCurve:P256,
    EC2KpD: privateKey,
    }

cose_key = CoseKey.from_dict(Key_options)

message.key = cose_key

output = message.encode()

output = zlib.compress(output, 9)

output_print = b45encode(output)

print(b'HC1:'+output_print)

qr = pyqrcode.create(b'HC1:'+output_print)

qr.png(''+str(generateID(30))+'.png', scale=8)

