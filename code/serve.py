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

class Server:
	outbound = 54123
	inbound  = 12345
	running = False
	start = 0.0
	privatekey = ''
	clients = {}

	def __init__(self):
		# start server
		self.sock = self.initialize()
		# define server actions
		self.actions = {'keygen':	self.create_key,
						'test_enc': self.encryption_test}

	def initialize(self):
		if not os.path.isdir(os.getcwd()+'/.data'):
			os.mkdir('.data')
		self.start = time.time()
		self.running = True
		s = []
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(('0.0.0.0', self.inbound))
			s.listen(5)
		except socket.error:
			pass
		return s 

	def run(self):
		while self.running:
			try:
				csock, caddr = self.sock.accept()
				cip = caddr[0]
				cport = int(caddr[1])
				# process request
				unserved = True; timeout = 3; tic = time.time()
				while unserved and time.time() - tic < timeout:
					try:
						raw_request = csock.recv(2048)
						api_method  = raw_request.split('????')[0]
						api_request = raw_request.split('????')[1]
						if api_method in self.actions.keys():
							csock = self.actions[api_method](csock, caddr, api_request)
							unserved = True
					except socket.error:
						print '[!!] Timed Out waiting on %s' % cip
						pass
					except IndexError:
						pass
				# End the connection once request was processed 
				try:
					csock.close()
				except socket.error:
					pass

			except socket.error:
				print '[!!] Server Crashed'
				self.running = False
				pass

	def encryption_test(self,client_sock,client_addr, api_req):
		token = self.clients[client_addr[0]]
		print '[*] Testing Session Encryption with key %s' % (base64.b64encode(token))
		decrypted_test = utils.DecodeAES(AES.new(token), api_req)
		client_sock.send(decrypted_test)
		return client_sock

	def create_key(self, client_sock, client_addr, api_req):
		# delete any existing keyfiles
		if os.path.isfile(os.getcwd()+'/.data/id'):
			os.remove('.data/id')
		# create a new keyfile
		key = RSA.generate(2048)
		private_key = key.exportKey()
		public_key = key.publickey()
		self.privatekey = private_key
		file_out = open('.data/id', "wb")
		file_out.write(key.exportKey('PEM'))
		file_out.close()
		# send the private key
		client_sock.send(public_key.exportKey())
		# Also receive that client's public key
		remote_key = RSA.importKey(client_sock.recv(4096))
		rkout = open('.data/%s.pem' % client_addr[0].replace('.',''), "wb")
		rkout.write(remote_key.exportKey())
		rkout.close()
		# now send a session cookie encrypted with public key
		self.clients[client_addr[0]] = get_random_bytes(16)
		client_sock.send(PKCS1_OAEP.new(remote_key).encrypt(base64.b64encode(self.clients[client_addr[0]])))
		print '[*] Keys Exchanged with %s, and session key delivered [%s]' %\
			 (client_addr[0], base64.b64encode(self.clients[client_addr[0]]))
		return client_sock

def main():
	server = Server()
	server.run()

if __name__ == '__main__':
	main()
