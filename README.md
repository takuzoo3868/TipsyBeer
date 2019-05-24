# Tipsy Beer!!!

`tipsy.py` is designed to take a key phrase of any length which can be used to encrypt/decrypt a string of any length. This is a Block cipher.

```

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
```

## usage

```
usage: tipsy.py [-v][-d][-k <phrase>][-m <message>]

This is designed to take a key phrase of any length which can be used to
encrypt/decrypt a string of any length.

optional arguments:
  -h, --help            show this help message and exit
  -v                    displays the encryption/decryption process
  -d                    run in decryption mode
  -k KEY_PHRASE, --keyphrase KEY_PHRASE
                        specify key phrase
  -m YOUR_TEXT, --message YOUR_TEXT
                        specify string to encrypt/decrypt
```

## remarks
This repository is a product of [UEC 25131117](http://sakiyama-lab.jp/lecture/).
