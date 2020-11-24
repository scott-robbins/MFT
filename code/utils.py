from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import time
import sys
import os


BSZ=16;PAD='{'
pad=lambda s: s + (BSZ - len(s) % BSZ)*PAD
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PAD)

def fencrypt(fname,destroy):
	if not os.path.isfile(fname):
		exit()
	efile=fname.split('/')[-1].split('.')[0]+'.lol'
	content=open(fname,'rb').read()
	k=get_random_bytes(16);open(efile,'wb').write(EncodeAES(AES.new(k),content))
	open(fname.split('/')[-1].split('.')[0]+'.key','wb').write(base64.b64encode(k))
	if destroy:
		os.remove(fname)

def fdecrypt(fname):
	encd=open(fname,'rb').read()
	kf=fname.split('.')[0]+'.key'
	k=base64.b64decode(open(kf,'rb').read())
	return DecodeAES(AES.new(k),encd)

def recv_sock(csock, timeout):
	unserved = True;	raw_data = ''
	while unserved and time.time() - tic < timeout:
		try:
			raw_data = csock.recv(2048)
			unserved = False
		except socket.error:
			print '[!!] connection Broken with %s' % caddr[0]
			pass
		# End the connection once request was processed 
	try:
		csock.close()
	except socket.error:
		pass
	if unserved:
		print '[!!] Timed Out waiting for %s' % caddr[0]
	return raw_data