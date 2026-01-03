#!/usr/bin/env python3
import argparse
import pynfc.nfc as nfcmod

from pynfc import Nfc, TimeoutException
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

SALT = bytes([0x9a,0x75,0x9c,0xf2,0xc4,0xf7,0xca,0xff,0x22,0x2c,0xb9,0x76,0x9b,0x41,0xbc,0x96])

SECNUM = 16
BPS = 4

dump = {}
dumped_ids = []
warned_ids = []

def generate_keys(uid):
    keys_a=HKDF(uid, 6, SALT, SHA256, 16, context=b"RFID-A\0")
    keys_b=HKDF(uid, 6, SALT, SHA256, 16, context=b"RFID-B\0")

    return {'A':keys_a,'B':keys_b}


def build_auth_tag(sector, keys):
    tag_struct = nfcmod.mifare_classic_tag()

    last_block = (sector + 1) * BPS - 1

    tag_struct.amb[last_block].mbt.abtKeyA = (nfcmod.uint8_t * 6)(*keys['A'][sector])
    tag_struct.amb[last_block].mbt.abtKeyB = (nfcmod.uint8_t * 6)(*keys['B'][sector])

    return tag_struct

def read_tag(tag, sector, keys):

    data = bytearray()
    
    print(f"\t--- Reading sector {sector} ---")
    first_block = sector * BPS
    last_block = first_block + BPS - 1

    authenticated = False

    try:  
        auth_tag = build_auth_tag(sector, keys)       
        key = auth_tag.amb[last_block].mbt.abtKeyA
        if tag.auth(auth_tag,sector,True):
                # print(f"Authenticated sector {sector} with Key A:  {list(map(hex,key[:6]))} ")
                authenticated = True
    except Exception as e:
            pass

    if not authenticated:
        print("Authentication failed for this sector")
        return data

    for block in range(first_block, first_block + BPS):
        try:
            buf = (nfcmod.uint8_t* 16)()
            ret = nfcmod.mifare_classic_read(tag.target, block, buf)

            if ret != 0:
                raise RuntimeError("read failed")
            block_data = bytearray(buf)
            
            #print(f"Block {block:02d}: {block_data}")

            if block == last_block:
                block_data[0:6]=key[:6]
                block_data[-6:]=auth_tag.amb[last_block].mbt.abtKeyB[:6]

            data += block_data

        except Exception as e:
            print(f"Error reading block {block}: {e}")

    return data

def main():

    parser = argparse.ArgumentParser(description="Use libnfc to dump a tag")
    parser.add_argument('-d', '--device', required=True, help='libnfc device to open. e.g "pn532_uart:/dev/ttyUSB0"')

    args = parser.parse_args()
    try:
        n = Nfc(args.device)
    except Exception as e:
        print("Could not open NFC device:", e)
        return

    print("Waiting for Bambu tag... (Ctrl+C to exit)")

    try:
        for tag in n.poll():

            if tag.__class__.__name__ != "Mifare":
                print("Non-MIFARE tag detected, skipping")
                continue

            if not tag.uid:
                print("No UID found; skipping")
                continue

            if tag.uid in dumped_ids and not tag.uid in warned_ids:
                print("Already read tag:", tag.uid.decode())
                warned_ids.append(tag.uid)
                continue
            
            if tag.uid in warned_ids:
                continue

            if not dump.get(tag.uid):
                print(f"Tag UID: {tag.uid.decode()}")
                dump[tag.uid]={'sector':0,'data':list(), 'keys': generate_keys(bytes.fromhex(tag.uid.decode()))}

            if not tag.uid in dumped_ids and dump[tag.uid]['sector']==SECNUM:
                print(f'Tag {tag.uid.decode()} fully dumped; remove tag.')
                with open(f'hf-tag-{tag.uid.decode().upper()}.bin','wb') as fp:
                    for data in dump[tag.uid]['data']:
                        fp.write(data)
                dumped_ids.append(tag.uid)
                continue

            dump[tag.uid]['data'].append(read_tag(tag,dump[tag.uid]['sector'], dump[tag.uid]['keys']))
            dump[tag.uid]['sector']+=1
    
    except (TimeoutException, KeyboardInterrupt):
        print("\nExiting.")

if __name__ == "__main__":
    main()

