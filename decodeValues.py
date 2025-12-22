import os
import sys
import struct
import textwrap
import argparse

# Block names and descriptions from docs/BambuLabRfid.md
# Mapping: absolute block number -> (short name, description)
block_info = {
    0: ("Block 0", "UID and Tag Manufacturer Data"),
    1: ("Block 1", "Tray Info Index"),
    2: ("Block 2", "Filament Type"),
    3: ("Block 3", "MIFARE encryption keys (standard)"),
    4: ("Block 4", "Detailed Filament Type"),
    5: ("Block 5", "Spool Weight, Color Code, Filament Diameter"),
    6: ("Block 6", "Temperatures and Drying Info"),
    7: ("Block 7", "MIFARE encryption keys (standard)"),
    8: ("Block 8", "X Cam Info, Nozzle Diameter"),
    9: ("Block 9", "Tray UID"),
    10: ("Block 10", "Spool Width"),
    11: ("Block 11", "MIFARE encryption keys (standard)"),
    12: ("Block 12", "Production Date/Time"),
    13: ("Block 13", "Short Production Date/Time"),
    14: ("Block 14", "Filament Length"),
    15: ("Block 15", "MIFARE encryption keys (standard)"),
    16: ("Block 16", "Extra Color Info"),
    17: ("Block 17", "Unknown"),
    18: ("Block 18", "Empty"),
    19: ("Block 19", "MIFARE encryption keys (standard)"),
    20: ("Block 20", "Empty"),
    21: ("Block 21", "Empty"),
    22: ("Block 22", "Empty"),
    23: ("Block 23", "MIFARE encryption keys (standard)"),
    24: ("Block 24", "Empty"),
    25: ("Block 25", "Empty"),
    26: ("Block 26", "Empty"),
    27: ("Block 27", "MIFARE encryption keys (standard)"),
    28: ("Block 28", "Empty"),
    29: ("Block 29", "Empty"),
    30: ("Block 30", "Empty"),
    31: ("Block 31", "MIFARE encryption keys (standard)"),
    32: ("Block 32", "Empty"),
    33: ("Block 33", "Empty"),
    34: ("Block 34", "Empty"),
    35: ("Block 35", "MIFARE encryption keys (standard)"),
    36: ("Block 36", "Empty"),
    37: ("Block 37", "Empty"),
    38: ("Block 38", "Empty"),
    39: ("Block 39", "MIFARE encryption keys (standard)"),
}

# Blocks 40-63: RSA-2048 signature area per docs
for i in range(40, 64):
    block_info[i] = (f"Block {i}", "RSA-2048 Signature area")


def parse_block_hex_tokens(tokens):
    """Convert tokens like ['25','C1',...,'??'] into a list of ints or None for '??'."""
    bytes_out = []
    for t in tokens:
        if '?' in t:
            bytes_out.append(None)
            continue
        try:
            bytes_out.append(int(t, 16))
        except ValueError:
            bytes_out.append(None)
    return bytes_out


def bytes_to_ascii(byte_list):
    out = []
    for b in byte_list:
        if b is None:
            out.append('.')
        elif 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append('.')
    return ''.join(out)


def chunk(values, size):
    for i in range(0, len(values), size):
        yield values[i:i+size]


def safe_unpack(fmt, byte_vals, endian='little'):
    # byte_vals: list of ints (no None) length matches fmt size
    try:
        b = bytes(byte_vals)
        if endian == 'little':
            return struct.unpack('<' + fmt, b)
        else:
            return struct.unpack('>' + fmt, b)
    except Exception:
        return None


def decode_block(block_num, tokens, full_mode=False):
    bytes_list = parse_block_hex_tokens(tokens)
    # hex string
    hex_str = ' '.join(t.upper() for t in tokens)
    # ascii
    ascii_str = bytes_to_ascii([b if b is not None else 0x2E for b in bytes_list])

    out = []
    # annotate with documented name/description when available
    try:
        bi = block_info.get(int(block_num))
    except Exception:
        bi = None
    if bi:
        name, desc = bi
        out.append(f"{name} ({desc}): {hex_str}")
    else:
        out.append(f"Block {block_num}: {hex_str}")

    # attempt to parse documented fields for this block
    typed = parse_typed_block(block_num, tokens)
    if typed:
        # include typed, labeled fields
        for line in typed:
            out.append(f"  {line.strip()}")
        # If not in full mode, return just the typed info (no numeric dumps)
        if not full_mode:
            return '\n'.join(out)
    else:
        # If no typed parser exists and not in full mode, skip this block
        if not full_mode:
            return None
    
    # In full mode, show detailed info
    out.append(f"  ASCII : {ascii_str}")

    # fallback: show generic numeric interpretations
    # show uint16 LE and BE
    u16_le = []
    u16_be = []
    for pair in chunk([b if b is not None else 0 for b in bytes_list], 2):
        if len(pair) < 2:
            break
        v_le = pair[0] | (pair[1] << 8)
        v_be = (pair[0] << 8) | pair[1]
        u16_le.append(str(v_le))
        u16_be.append(str(v_be))
    if u16_le:
        out.append(f"  UINT16 LE: {' '.join(u16_le)}")
        out.append(f"  UINT16 BE: {' '.join(u16_be)}")

    # show uint32 and float32 (LE and BE)
    u32_le = []
    u32_be = []
    f32_le = []
    f32_be = []
    for quad in chunk([b if b is not None else 0 for b in bytes_list], 4):
        if len(quad) < 4:
            break
        v32_le = quad[0] | (quad[1] << 8) | (quad[2] << 16) | (quad[3] << 24)
        v32_be = (quad[0] << 24) | (quad[1] << 16) | (quad[2] << 8) | quad[3]
        u32_le.append(str(v32_le))
        u32_be.append(str(v32_be))
        # floats
        fl_le = safe_unpack('f', quad, endian='little')
        fl_be = safe_unpack('f', quad, endian='big')
        f32_le.append(f"{fl_le[0]:.6g}" if fl_le else 'N/A')
        f32_be.append(f"{fl_be[0]:.6g}" if fl_be else 'N/A')

    if u32_le:
        out.append(f"  UINT32 LE: {' '.join(u32_le)}")
        out.append(f"  UINT32 BE: {' '.join(u32_be)}")
        out.append(f"  FLOAT32 LE: {' '.join(f32_le)}")
        out.append(f"  FLOAT32 BE: {' '.join(f32_be)}")

    # If ASCII contains a long readable string, show it as detected string
    readable = ''.join(ch if ch != '.' else '' for ch in ascii_str)
    if len(readable) >= 4:
        out.append(f"  Detected string: {readable}")

    return '\n'.join(out)


# helpers to read typed values from block bytes
def get_uint16_le(bytes_list, offset):
    if offset + 1 >= len(bytes_list):
        return None
    a = bytes_list[offset] or 0
    b = bytes_list[offset + 1] or 0
    return a | (b << 8)


def get_uint32_le(bytes_list, offset):
    if offset + 3 >= len(bytes_list):
        return None
    vals = [bytes_list[offset + i] or 0 for i in range(4)]
    return vals[0] | (vals[1] << 8) | (vals[2] << 16) | (vals[3] << 24)


def get_float32_le(bytes_list, offset):
    if offset + 3 >= len(bytes_list):
        return None
    vals = [bytes_list[offset + i] or 0 for i in range(4)]
    try:
        return struct.unpack('<f', bytes(vals))[0]
    except Exception:
        return None


def get_string(bytes_list, offset, length):
    seg = bytes((b or 0) for b in bytes_list[offset:offset+length])
    try:
        s = seg.split(b'\x00', 1)[0].decode('ascii', errors='replace')
    except Exception:
        s = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in seg)
    return s


def parse_typed_block(block_num, tokens):
    # tokens are hex strings; parse into ints/None
    bytes_list = parse_block_hex_tokens(tokens)
    out = []
    bn = int(block_num)

    if bn == 0:
        uid = ''.join(f"{(b or 0):02X}" for b in bytes_list[0:4])
        manu = ' '.join(f"{(b or 0):02X}" for b in bytes_list[4:16])
        out.append(f"  UID: {uid}")
        out.append(f"  Manufacturer: {manu}")

    elif bn == 1:
        # Tray Info Index: 0..7 variant, 8..15 material id
        variant = get_string(bytes_list, 0, 8)
        material = get_string(bytes_list, 8, 8)
        out.append(f"  Material variant ID: {variant}")
        out.append(f"  Material ID: {material}")

    elif bn in (2, 4):
        # Filament type / detailed filament type (16-byte ASCII)
        s = get_string(bytes_list, 0, 16)
        out.append(f"  Type: {s}")

    elif bn == 5:
        # Color RGBA (0..3), weight uint16 LE at 4, diameter float LE at 8
        rgba = ''.join(f"{(b or 0):02X}" for b in bytes_list[0:4])
        weight = get_uint16_le(bytes_list, 4)
        diameter = get_float32_le(bytes_list, 8)
        out.append(f"  Color (RGBA hex): {rgba[:-2]}")
        if weight is not None:
            out.append(f"  Spool weight (g): {weight}")
        if diameter is not None:
            out.append(f"  Filament diameter (mm): {diameter}")

    elif bn == 6:
        # Drying/temp fields per docs
        drying_temp = get_uint16_le(bytes_list, 0)
        drying_hours = get_uint16_le(bytes_list, 2)
        bed_temp_type = get_uint16_le(bytes_list, 4)
        bed_temp = get_uint16_le(bytes_list, 6)
        max_hotend = get_uint16_le(bytes_list, 8)
        min_hotend = get_uint16_le(bytes_list, 10)
        if drying_temp is not None:
            out.append(f"  Drying temperature (°C): {drying_temp}")
        if drying_hours is not None:
            out.append(f"  Drying time (hours): {drying_hours}")
        out.append(f"  Bed temperature type: {bed_temp_type}")
        if bed_temp is not None:
            out.append(f"  Bed temperature (°C): {bed_temp}")
        if max_hotend is not None:
            out.append(f"  Hotend max (°C): {max_hotend}")
        if min_hotend is not None:
            out.append(f"  Hotend min (°C): {min_hotend}")

    elif bn == 8:
        xcam = ' '.join(f"{(b or 0):02X}" for b in bytes_list[0:12])
        nozzle = get_float32_le(bytes_list, 12)
        out.append(f"  X Cam (raw 12 bytes): {xcam}")
        if nozzle is not None:
            out.append(f"  Min nozzle diameter (mm): {nozzle}")

    elif bn == 9:
        out.append(f"  Tray UID: {get_string(bytes_list, 0, 16)}")

    elif bn == 10:
        # spool width at offset 4 uint16 LE, value /100
        w = get_uint16_le(bytes_list, 4)
        if w is not None:
            out.append(f"  Spool width (mm): {w / 100:.2f}")

    elif bn == 12:
        out.append(f"  Production date/time: {get_string(bytes_list, 0, 16)}")

    elif bn == 13:
        out.append(f"  Short production: {get_string(bytes_list, 0, 16)}")

    elif bn == 14:
        # filament length in meters? uint16 at offset 4
        length = get_uint16_le(bytes_list, 4)
        if length is not None:
            out.append(f"  Filament length (raw uint16): {length}")

    elif bn == 16:
        fmt_id = get_uint16_le(bytes_list, 0)
        color_count = get_uint16_le(bytes_list, 2)
        second_color_abgr = ''.join(f"{(b or 0):02X}" for b in bytes_list[4:8])
        out.append(f"  Format ID: {fmt_id}")
        out.append(f"  Color count: {color_count}")
        out.append(f"  Second color (ABGR hex): {second_color_abgr}")

    return out


def decode_nfc_file(file_path, full_mode=False):
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()

    results = []
    for line in lines:
        if line.strip().startswith('Block'):
            parts = line.split(':', 1)
            if len(parts) < 2:
                continue
            header = parts[0].strip()
            block_num = header.split()[1]
            tokens = parts[1].strip().split()
            decoded = decode_block(block_num, tokens, full_mode)
            if decoded:  # Only include non-None results
                results.append(decoded)

    return results


if __name__ == '__main__':
    import sys
    # Ensure UTF-8 output for Unicode characters
    if sys.platform == 'win32':
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    
    parser = argparse.ArgumentParser(description='Decode Bambu Lab RFID tag NFC dump files')
    parser.add_argument('nfc_file', help='Path to the .nfc dump file')
    parser.add_argument('--full', action='store_true', 
                        help='Show detailed numeric decodes (ASCII, UINT16/32, FLOAT32) for all blocks')
    args = parser.parse_args()
    
    decoded_output = decode_nfc_file(args.nfc_file, full_mode=args.full)
    if decoded_output:
        print('\n\n'.join(decoded_output))
