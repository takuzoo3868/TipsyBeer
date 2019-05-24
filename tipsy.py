#!/usr/bin/env python

import sys
import getopt
import collections
import binascii
import hashlib
import itertools
import argparse


class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'



# ターミナル出力用のバナー
banner = r"""{}{}

▄▄▄█████▓ ██▓ ██▓███    ██████▓██   ██▓    ▄▄▄▄   ▓█████ ▓█████  ██▀███  
▓  ██▒ ▓▒▓██▒▓██░  ██▒▒██    ▒ ▒██  ██▒   ▓█████▄ ▓█   ▀ ▓█   ▀ ▓██ ▒ ██▒
▒ ▓██░ ▒░▒██▒▓██░ ██▓▒░ ▓██▄    ▒██ ██░   ▒██▒ ▄██▒███   ▒███   ▓██ ░▄█ ▒
░ ▓██▓ ░ ░██░▒██▄█▓▒ ▒  ▒   ██▒ ░ ▐██▓░   ▒██░█▀  ▒▓█  ▄ ▒▓█  ▄ ▒██▀▀█▄  
  ▒██▒ ░ ░██░▒██▒ ░  ░▒██████▒▒ ░ ██▒▓░   ░▓█  ▀█▓░▒████▒░▒████▒░██▓ ▒██▒
  ▒ ░░   ░▓  ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░  ██▒▒▒    ░▒▓███▀▒░░ ▒░ ░░░ ▒░ ░░ ▒▓ ░▒▓░
    ░     ▒ ░░▒ ░     ░ ░▒  ░ ░▓██ ░▒░    ▒░▒   ░  ░ ░  ░ ░ ░  ░  ░▒ ░ ▒░
  ░       ▒ ░░░       ░  ░  ░  ▒ ▒ ░░      ░    ░    ░      ░     ░░   ░ 
          ░                 ░  ░ ░         ░         ░  ░   ░  ░   ░     
                               ░ ░              ░                        
Author: takuzoo3868
E-mail: sawada@net.lab.uec.ac.jp
Last Modified: 22 May 2018.
- Tipsy beer is a block cipher created from my experience of drinking too 
much and making my eyes dim and I can't see letters clearly.
==========================================================================={}
""".format(colors.OKGREEN, colors.BOLD, colors.END)


key_hashed = ''
pigpen_message = ''
encrypted_message = ''
decrypted_message = ''

# pigpen dictionaries
# ref: https://en.wikipedia.org/wiki/Pigpen_cipher
pigpen_A = {'A': 'ETL', 'B': 'ETM', 'C': 'ETR', 'D': 'EML', 'E': 'EMM', 'F': 'EMR', 'G': 'EBL', 'H': 'EBM', 'I': 'EBR',
            'J': 'DTL',
            'K': 'DTM', 'L': 'DTR', 'M': 'DML', 'N': 'DMM', 'O': 'DMR', 'P': 'DBL', 'Q': 'DBM', 'R': 'DBR', 'S': 'EXT',
            'T': 'EXL', 'U': 'EXR',
            'V': 'EXB', 'W': 'DXT', 'X': 'DXL', 'Y': 'DXR', 'Z': 'DXB', ' ': 'EPS', '.': 'EPF', ',': 'EPC', '!': 'EPE',
            '?': 'EPQ', '"': 'EPD',
            '@': 'EPA', '0': 'NTL', '1': 'NTM', '2': 'NTR', '3': 'NML', '4': 'NMM', '5': 'NMR', '6': 'NBL', '7': 'NBM',
            '8': 'NBR', '9': 'NXT'}

pigpen_B = {'C': 'ETL', 'D': 'ETM', 'A': 'ETR', 'B': 'EML', 'G': 'EMM', 'H': 'EMR', 'E': 'EBL', 'F': 'EBM', 'K': 'EBR',
            'L': 'DTL',
            'I': 'DTM', 'J': 'DTR', 'O': 'DML', 'P': 'DMM', 'M': 'DMR', 'N': 'DBL', 'S': 'DBM', 'T': 'DBR', 'Q': 'EXT',
            'R': 'EXL', 'W': 'EXR',
            'X': 'EXB', 'U': 'DXT', 'V': 'DXL', ' ': 'DXR', ',': 'DXB', 'Y': 'EPS', '!': 'EPF', 'Z': 'EPC', '.': 'EPE',
            '@': 'EPQ', '0': 'EPD',
            '?': 'EPA', '"': 'NTL', '3': 'NTM', '4': 'NTR', '1': 'NML', '2': 'NMM', '7': 'NMR', '8': 'NBL', '9': 'NBM',
            '5': 'NBR', '6': 'NXT'}

pigpen_C = {'K': 'ETL', 'L': 'ETM', 'M': 'ETR', 'N': 'EML', 'O': 'EMM', 'P': 'EMR', 'Q': 'EBL', 'R': 'EBM', 'S': 'EBR',
            'U': 'DTL',
            'V': 'DTM', 'W': 'DTR', 'X': 'DML', 'Y': 'DMM', 'Z': 'DMR', ' ': 'DBL', '.': 'DBM', ',': 'DBR', '!': 'EXT',
            '"': 'EXL', '?': 'EXR',
            '@': 'EXB', '0': 'DXT', '1': 'DXL', '2': 'DXR', '3': 'DXB', '4': 'EPS', '5': 'EPF', '6': 'EPC', '7': 'EPE',
            '8': 'EPQ', '9': 'EPD',
            'A': 'EPA', 'B': 'NTL', 'C': 'NTM', 'D': 'NTR', 'E': 'NML', 'F': 'NMM', 'G': 'NMR', 'H': 'NBL', 'I': 'NBM',
            'J': 'NBR', 'T': 'NXT'}


# 鍵の生成
def keyGenerate(verbose_opt, key_phrase):
    global key_hashed

    # ハッシュ値計算
    md5_hash = hashlib.md5(key_phrase.encode())
    sha256_hash = hashlib.sha256(key_phrase.encode())
    sha512_hash = hashlib.sha512(key_phrase.encode())

    # ハッシュ値を１６進数形式で合成
    key_hashed = md5_hash.hexdigest() + sha256_hash.hexdigest() + sha512_hash.hexdigest()

    # 1024bit の鍵を生成
    key_hashed_hash = hashlib.md5(key_hashed.encode())
    key_hashed += key_hashed_hash.hexdigest()

    if verbose_opt:
        print("[KEY GENERATION]")
        print("[+] The key phrase is: {}{}{}".format(colors.OKGREEN, key_phrase, colors.END))
        print("[+] {} is independantly hashed 3 times using MD5, SHA256 and SHA512".format(key_phrase))
        print("[+] The 3 hashes are concatenated with 1 more md5 hash, resulting in the 1024bit key:")
        print("[+] {}\n".format(key_hashed))

    return


# 換字用辞書の選択
def selectDict(key_phrase):
    # ASCII値の計算
    ascii_total = 0
    for x in key_phrase:
        ascii_total += ord(x)

    # mod 3による辞書選択
    if ascii_total % 3 == 0:
        pigpen_dict = pigpen_A

    elif ascii_total % 3 == 1:
        pigpen_dict = pigpen_B

    elif ascii_total % 3 == 2:
        pigpen_dict = pigpen_C

    return pigpen_dict


# 換字処理
def pigpenForward(verbose_opt, your_text, key_phrase):
    global pigpen_message

    message = your_text.upper()

    for letter in message:
        if letter in selectDict(key_phrase):
            pigpen_message += selectDict(key_phrase).get(letter)

    if verbose_opt:
        print("[ENCRYPTION - Phase 1]")
        print("[+] The text is: {}{}{}".format(colors.OKGREEN, your_text, colors.END))
        print(
            "[+] 1 of 3 dictionaries is derived from the sum of the pre-hashed key ASCII values (mod 3)")
        print(
            "[+] The clear text is converted into pigpen cipher text using the selected dictionary:")
        print("[>] {}\n".format(pigpen_message))

    return


# 換字処理(復号化用)　鍵を用いてmod3すれば，元の辞書がどれであったか求めることは容易
def pigpenBackward(verbose_opt, key_phrase):
    global decrypted_message

    message = ''
    try:
        for i in decrypted_message:
            message += chr(i)
    except:
        print("[!] Incorrect key. Cannot decrypt.")

    message_list = [message[i:i + 3] for i in range(0, len(message), 3)]
    decrypted_message = ''

    for element in message_list:
        for key, value in selectDict(key_phrase).items():
            if value == element:
                decrypted_message += key

    if verbose_opt:
        print("[DECRYPTION - Phase 3]")
        print(
            "[+] 1 of 3 dictionaries is derived from the sum of the pre-hashed key ASCII values (mod 3)")
        print("[+] The values of the pigpen cipher text are looked up in the selected dictionary")
        print("[+] The pigpen cipher text is converted back into clear text...")
        print("[DECRYPTION - COMPLETE]")
        print("[*] {}".format(decrypted_message))

    return


# XOR BoxによるXOR処理  
def keyConfusion(message, verbose_opt, decrypt_opt):
    # 鍵のascii値からbase10のint型配列を生成
    key = []
    for x in key_hashed:
        key.append(ord(x))

    # テキストが鍵長より長い場合を想定し，循環する変数を定義
    key_cycle = itertools.cycle(key)

    for i in range(len(message)):
        # 鍵配列からXORに使う鍵データを決める
        key_pointer = next(key_cycle) % 128  # 鍵は128byteだからmod128で計算
        key_byte = key[key_pointer]

        # 鍵データとテキストをXOR
        message[i] = message[i] ^ key_byte

        # 次の鍵データを決めXOR
        key_byte = key[(key_byte % 128)]
        message[i] = message[i] ^ key_byte

        # もう一回，次の鍵データを決めXOR
        key_byte = key[(key_byte % 128)]
        message[i] = message[i] ^ key_byte

    if verbose_opt:
        # 暗号化/復号化のターミナル表示用
        if decrypt_opt:
            print("[DECRYPTION - Phase 2]")
            en_or_de_text = " pigpen cipher text:"

        else:
            print("[ENCRYPTION - Phase 2]")
            en_or_de_text = " partially encrypted string:"

        print("[+] Each byte of the pigpen cipher is then XOR'ed against 3 bytes of the key")
        print("[+] The key byte is XOR'ed against the byte of the message and then used to select the")
        print("[+] position in the key array of the next key byte value. This occurs three times.")
        print("[+] Resulting in the {}".format(en_or_de_text))
        print("[+] {}\n".format(message.decode('utf-8')))

    return message


# 暗号化処理(XORの前処理)
def xorForward(verbose_opt, decrypt_opt):
    global encrypted_message

    # 文字列をバイト型へ変換
    message = bytearray(pigpen_message, encoding='utf8')
    key = bytearray(key_hashed, encoding='utf8')

    # XOR
    message = keyConfusion(message, verbose_opt, decrypt_opt)

    # 最後に鍵の添字とブロックの添字を対応付けてXOR
    for x in range(len(message)):
        for y in range(len(key)):
            xored = key[y] ^ message[x]
            message[x] = xored

    encrypted_message = binascii.hexlify(bytearray(message))

    if verbose_opt:
        print("[ENCRYPTION - Phase 3]")
        print("[+] The partially encrypted cipher text and key are converted into a byte arrays")
        print("[+] Each byte of the message is XOR'ed against each byte of the key")
        print("[+] Resulting in the cipher text hex string...")
        print("[ENCRYPTION - COMPLETE]")
        print("[*] {}".format(encrypted_message.decode('utf-8')))

    return


# 復号化処理(XORの後処理)
def xorBackward(verbose_opt, decrypt_opt, your_text):
    global decrypted_message

    # 文字列をバイト型へ変換
    reverse_key = key_hashed[::-1]
    key = bytearray(reverse_key, encoding='utf8')

    # 暗号文をバイト型へ変換
    message = ''
    try:
        message = bytearray(binascii.unhexlify(your_text))
    except:
        print("[!]: Incorrect string. Cannot decrypt.")

    for x in range(len(message)):
        for y in range(len(key)):
            xored = key[y] ^ message[x]
            message[x] = xored

    if verbose_opt:
        print("[DECRYPTION - Phase 1]")
        print("[+] The cipher text is: {}{}{}".format(colors.OKGREEN, your_text, colors.END))
        print("[+] The cipher text and key are converted into a byte arrays")
        print("[+] The key is reversed in order to reverse this stage of XOR'ing")
        print("[+] Each byte of the cipher text is XOR'ed against each byte of the key")
        print("[+] Resulting in the partially decrypted string:")
        print("[+] {}\n".format(message.decode()))

    # XOR
    decrypted_message = keyConfusion(message, verbose_opt, decrypt_opt)

    return


def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [-v][-d][-k <phrase>][-m <message>]",
        description="This is designed to take a key phrase of any length which can be used to encrypt/decrypt a string of any length.",
    )
    parser.add_argument("-v", help="displays the encryption/decryption process",
                        dest="verbose_opt",
                        action="store_true")
    parser.add_argument("-d", help="run in decryption mode",
                        dest="decrypt_opt",
                        action="store_true")
    parser.add_argument("-k", "--keyphrase", help="specify key phrase",
                        dest="key_phrase",
                        type=str, default="secret key")
    parser.add_argument("-m", "--message", help="specify string to encrypt/decrypt",
                        dest="your_text",
                        type=str, default="This is a secret for me. Don't tell anyone.")
    options = parser.parse_args()

    print(banner)
    if options.decrypt_opt:
        keyGenerate(options.verbose_opt, options.key_phrase)
        xorBackward(options.verbose_opt, options.decrypt_opt, options.your_text)
        pigpenBackward(options.verbose_opt, options.key_phrase)
        if not options.verbose_opt:
            print("[DECRYPTED]: {}".format(decrypted_message))

    else:
        keyGenerate(options.verbose_opt, options.key_phrase)
        pigpenForward(options.verbose_opt, options.your_text, options.key_phrase)
        xorForward(options.verbose_opt, options.decrypt_opt)
        if not options.verbose_opt:
            print("[ENCRYPTED]: {}".format(encrypted_message.decode()))


if __name__ == "__main__":
    main()
