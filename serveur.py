#!/usr/bin/python2.7

#SERVEUR
from time import sleep
import socket
import BaseHTTPServer
from collections import deque
import select
import base64
import threading
import os
from Crypto.Cipher import AES

global ssh_up
global ssh_out
global ssh_in
global ssh_sock
global ssh_addr
global http_server

class handler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(s):
		s.send_response(200)
		s.send_header("Content-type", "text/html")
		s.end_headers()
	def do_GET(s):
		handler.rondoudou(s)
	def do_POST(s):
		handler.rondoudou(s)
	def rondoudou(s):
		global ssh_up
	        global ssh_in
        	global ssh_out
	      	if "=" in s.path:
			data = s.path[s.path.index('=')+1:]
      			ssh_in.extend((data,))
		if not ssh_up:
			s.send_response(204)
		elif len(ssh_out)>0:
		       	s.send_response(202)
		else:
			s.send_response(200)
      		s.send_header("Content-Type", "text/html")
      		s.send_header("Content-Lenght", "0")
      		s.end_headers()
      		try:
         		s.wfile.write(ssh_out.popleft())
      		except IndexError:
			s.wfile.write("")

def ssh_communication(connection):
	global ssh_up
	global ssh_in
	global ssh_out
	global ssh_sock
	global ssh_addr
	global http_server
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new('aaaaaaaaaa123456')
	if not ssh_up:
		ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ssh_sock.bind(('',2222))
		ssh_sock.listen(1)
		connection, ssh_addr = ssh_sock.accept()
		ssh_up = True
		print 'SSH launched'	
	while ssh_up:
           	read, write, err = select.select([connection], [connection], [], 120)
		sleep(0.5)
           	for s in read:
              		data = s.recv(512)
             		if len(data)==0:
                 		ssh_up = False
				print 'SSH stopped'
				connection.close()
				ssh_sock.close()
				ssh_out.clear()
                                ssh_in.clear()
				rep = None
				while rep != "yes" and rep != "no" :
					rep = raw_input("Do you want really ? (yes/no) : ")
				if rep == "yes":
					print "Shutting down"
					os._exit(1)
				ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				ssh_sock.bind(('',2222))
				ssh_sock.listen(1)
				connection, ssh_addr = ssh_sock.accept()
				ssh_up = True
				print 'SSH launched'
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
ssh_up = False
ssh_in = deque()
ssh_out = deque()
ssh_co = None
ssh_thread = threading.Thread(None, ssh_communication, None, (ssh_co,), {})
ssh_thread.start()
http_server_info = ('', 80)
http_server = BaseHTTPServer.HTTPServer(http_server_info, handler)
print 'Web server online'
http_server.serve_forever()
