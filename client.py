#!/usr/bin/python2.7

#CLIENT
from collections import deque
from time import sleep
import signal, sys, argparse, urllib, urllib2, string, random, threading, base64, select, httplib, socket
from Crypto.Cipher import AES

global ssh_up
global ssh_in
global ssh_out
global proxy
global server
global ssh_thread
global ssh_co
global http_thread

parser = argparse.ArgumentParser()
parser.add_argument('-s','--server', help='Web server IP',required=True)
parser.add_argument('-p','--proxy', help='Proxy server IP',required=True)
parser.add_argument('-pp','--proxyPort', help='Proxy server port',required=True)
args = parser.parse_args()
server = args.server
proxy = str(args.proxy)+':'+str(args.proxyPort)

def switch_off(signal, frame):
        print('Tunnel\'s off !')
        sys.exit(0)

def client_http():
	global ssh_up
	global ssh_in
	global ssh_out
	global proxy
	global server
	global ssh_thread
	global ssh_co
	while 1:
		sleep(0.1)
		proxy2 = urllib2.ProxyHandler({'http': proxy})
		opener = urllib2.build_opener(proxy2)
		urllib2.install_opener(opener)
		params = urllib.urlencode({})
		chemin = ''.join(random.choice(string.ascii_uppercase+string.digits) for i in range(10))+".html"
		try:
			data = ssh_out.popleft()
			print len(data)
			req = urllib2.Request("http://"+server+"/"+chemin+"?data="+data, params)
		except IndexError:
			req = urllib2.Request("http://"+server+"/"+chemin)
		try:
			response=urllib2.urlopen(req)
			if response.getcode() == 204:
				if ssh_up:
					print "SSH stopped"
					response.read()
					ssh_up = False
					ssh_thread.join()
					ssh_in.clear()
					ssh_out.clear()
					ssh_co.close()
			elif response.getcode() == 200:
				data = response.read()	
			elif response.getcode() == 202:
				if not ssh_up:
					print "SSH launched"
					ssh_co = socket.create_connection(('localhost',22))
        	                        ssh_up = True
	                                ssh_thread = threading.Thread(None, ssh_communication, None, (ssh_co,), {})
                	                ssh_thread.start()
				data = response.read()	
				ssh_in.extend((data,))
		except (socket.error, httplib.BadStatusLine):
			
			continue
		
def ssh_communication(connection):
        global ssh_up
        global ssh_in
        global ssh_out
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new('aaaaaaaaaa123456')
        while ssh_up:
                read, write, err = select.select([connection], [connection], [], 120)
                for s in read:
                        data = s.recv(512)
                        data = base64.b64encode(data)
			data = EncodeAES(cipher, data)
                        ssh_out.extend((data,))
                for s in write:
                        try:
                                data = ssh_in.popleft()
				data = DecodeAES(cipher, data)
				data = base64.b64decode(data)
                                if not len(data)==0:
					s.sendall(data)
                        except IndexError:
                                pass

# initialisation des variables
signal.signal(signal.SIGINT, switch_off)
ssh_up = False
ssh_in = deque()
ssh_out = deque()
print "c'est parti"
http_thread = threading.Thread(target=client_http)
http_thread.start()
