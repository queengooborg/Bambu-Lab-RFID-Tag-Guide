# -*- coding: utf-8 -*-

# Python script to extract the keys from a Bambu Lab filament RFID tag, using a Proxmark3
# Created for https://github.com/Bambu-Research-Group/RFID-Tag-Guide
# Written by Vinyl Da.i'gyu-Kazotetsu (www.queengoob.org), 2025

import subprocess
import os
import re
import sys
from pathlib import Path

from lib import strip_color_codes, get_proxmark3_location, run_command, testCommands

#Global variables
pm3Location = None                            #Calculated. The location of Proxmark3
pm3Command = "bin/pm3"                      # The command that works to start proxmark3

def setup():
    global pm3Location

    pm3Location = get_proxmark3_location()
    if not pm3Location:
        exit(-1)

def main():
    print("--------------------------------------------------------")
    print("RFID Tag Writer v0.1.0 - Bambu Research Group 2025")
    print("--------------------------------------------------------")
    print("This will write a tag dump to a physical tag using your")
    print("Proxmark3 device, allowing RFID tags for non-Bambu spools.")
    print("--------------------------------------------------------")

    # Run setup
    setup()

    if len(sys.argv) > 1:
        # If the user included an argument, assume it's the path to the tracefile
        tagdump = os.path.abspath(sys.argv[1])
    else:
        #Get the tracename/filepath from user
        tagdump = input("Enter the path to the tag dump you wish to write: ").replace("\\ ", " ")

    if len(sys.argv) > 2:
        # If the user included a second argument, assume it's the path to the key file
        keydump = os.path.abspath(sys.argv[2])
    else:
        #Get the keyname/filepath from user
        keydump = input("Enter the path to the tag's key dump you wish to write: ").replace("\\ ", " ")

    print()
    print("Start by placing your Proxmark3 device onto the tag you")
    print("wish to write to, then press Enter. I'll wait for you.")

    input()

    tagtype = getTagType()

    print()
    print("=========== WARNING! == WARNING! == WARNING! ===========")
    print("This script will write the contents of a dump to your")
    print("RFID tag, and then PERMANENTLY WRITE LOCK the tag.")
    print("")
    print("This process is IRREVERSIBLE, proceed at your own risk.")
    print("========================================================")
    print()

    confirm = input("Are you SURE you wish to continue (y/N)? ")
    if confirm.lower() not in ["y", "yes"]:
        print("Confirmation not obtained, exiting")
        exit(0)

    print("Writing tag data now...")
    writeTag(tagdump, keydump, tagtype)

    print()
    print("Writing complete! Your tag should now register on the AMS.")
    print()


def getTagType():
    print(f"Checking tag type...")
    output = run_command([pm3Location / pm3Command, "-d", "1", "-c", f"hf mf info"])

    if 'iso14443a card select failed' in output:
        raise RuntimeError("Tag not found or is wrong type")

    cap_re = r"(?:\[\+\] Magic capabilities\.\.\. ([()/\w\d ]+)\n)"

    match = re.search(rf"\[=\] --- Magic Tag Information\n(\[=\] <n/a>\n|{cap_re}+)", output)
    if not match:
        raise RuntimeError("Could not obtain magic tag information")

    if "[=] <n/a>" in match.group(1):
        raise RuntimeError("Tag is not a compatible type (must be Gen 4 FUID or UFUID), or has already been locked")
    
    capabilities = re.findall(cap_re, match.group(1))
    
    if "Gen 4 GDM / USCUID ( Gen4 Magic Wakeup )" in capabilities:
        return "Gen 4 FUID"
    if "Gen 4 GDM / USCUID ( ZUID Gen1 Magic Wakeup )" in capabilities:
        return "Gen 4 UFUID"
    
    raise RuntimeError("Tag is not a compatible type (must be Gen 4 FUID or UFUID)")

def writeTag(tagdump, keydump, tagtype):
    if tagtype == "Gen 4 FUID":
        # Load tag dump onto RFID tag
        output = run_command([pm3Location / pm3Command, "-c", f"hf mf restore --force -f {tagdump.replace(" ", "\\ ")} -k {keydump.replace(" ", "\\ ")}"], pipe=False)
        return

    if tagtype == "Gen 4 UFUID":
        # Load tag dump onto RFID tag, then immediately seal
        output = run_command([pm3Location / pm3Command, "-c", f"hf mf cload -f {tagdump.replace(" ", "\\ ")}; hf 14a raw -a -k -b 7 40; hf 14a raw -k 43; hf 14a raw -k -c e100; hf 14a raw -c 85000000000000000000000000000008"], pipe=False)


if __name__ == "__main__":
    main() #Run main program
