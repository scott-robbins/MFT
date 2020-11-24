from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from threading import Thread
import hashlib
import base64
import socket
import utils
import time
import sys
import os

class Client():
	inbound = 6666
	outbound = 4242
	remote_master = ''
	private_key = ''
	public_key = ''


	def __init__(self):
		self.initialize()

	def initialize(self):
		if not os.path.isdir(os.getcwd()+'/.data'):
			os.mkdir('.data')
		if not os.path.isfile(os.getcwd()+'/.data/myid.pem'):
			self.public_key = self.create_keys()
		else:
			self.public_key = self.load_keys()

	def load_keys(self):
		if os.path.isdir(os.getcwd()+'/.data'):
			if os.path.isfile(os.getcwd()+'/.data/myid'):
				key = RSA.importKey(open(os.getcwd()+'/.data/myid','rb').read())
				self.private_key = key
				return self.public_key
			

	def create_keys(self):
		key = RSA.generate(2048)
		private_key = key.exportKey()
		public_key = key.publickey()
		file_out = open('.data/myid', "wb")
		file_out.write(key.exportKey('PEM'))
		file_out.close()
		self.private_key = private_key
		return public_key.exportKey()


	def handshake(self, ip):
		# Make sure to have keys before handshaking!
		if self.private_key == '' and not os.path.isdir(os.getcwd()+'/.data/myid.pem'):
			self.public_key = self.create_keys()
		try:
			s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		except socket.error:
			print '[!!] Unable to Create Socket'
			pass
			return False

		try:
			s.connect((ip, 12345))
			s.send('keygen????API_REQUEST')
			remote_pubkey = s.recv(4096)
			# Now send our public key
			s.send(self.public_key)
			# save remote key
			open('.data/%s.pem' % ip.replace('.',''),'wb').write(remote_pubkey)
			# Okay now receive encrypted session token
			encryped_session_key = s.recv(256)
			
			if type(self.private_key)==str:
				k = PKCS1_OAEP.new(RSA.importKey(self.private_key)).decrypt(encryped_session_key)
			else:
				k = PKCS1_OAEP.new(RSA.importKey(self.private_key)).decrypt(encryped_session_key)
			session_key = base64.b64decode(k)
			print '\033[1m[*] Received Session Key: \033[35m%s\033[0m' % k
		except socket.error:
			pass
		s.close()
		return k

def encrypted_test(rmt_addr, k):
	if os.path.isfile(os.getcwd()+'/encryption_test.txt'):
		msg_test = open(os.getcwd()+'/encryption_test.txt', 'rb').read()
	enc_msg = utils.EncodeAES(AES.new(base64.b64decode(k)), msg_test)
	try:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	except socket.error:
		print '[!!] Unable to Create Socket'
		pass
		return False
	try:
		s.connect((rmt_addr, 12345))
		s.send('test_enc????%s' % enc_msg)
		reply = s.recv(1028)
	except socket.error:
		pass
	# verify the hash of the message to check integrity of remomte servers decryption
	# using the public keys just exchanged 
	hasher = hashlib.sha256()
	hasher.update(msg_test)
	correct_hash = hasher.digest()
	verifier = hashlib.sha256()
	verifier.update(reply)
	return (verifier.digest() == correct_hash)

def main():
	client = Client()

	if '-rmt' in sys.argv and len(sys.argv) >= 2:
		addr = sys.argv[2]
		key = client.handshake(addr)
		# verify the encrypted connection
		if encrypted_test('192.168.1.182', key):
			print '\033[1m[*]\033[32m Secure Connection Verified\033[0m'
		else:
			print '\033[1m[*]\033[31m Secure Connection Could NOT be Verified\033[0m'


if __name__ == '__main__':
	main()
