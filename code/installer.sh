#!/bin/bash
echo '[*] Installing Dependencies...'
pip install Crypto
pip install hashlib
pip install base64

echo '[*] Setting up...'
curl -s beta.lynx-network.us:8000/security.key >> security.key
curl -s beta.lynx-network.us:8000/serve.key >> serve.key

echo '[*] Launching Software'
python main.py -run

#EOF