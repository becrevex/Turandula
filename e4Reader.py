#Programmer: becrevex
#Date: December 7, 2022
#Filename: e4Reader.py
#Description: Tool to read Turandula Engine4 produced output files

import sys
import pickle
import os
import json

nets = {}
servs = {}

def load_services(filename='services.e4'):
	with open(filename, "rb") as handle:
		b = pickle.load(handle)
	return b


def load_networks(filename='networks.e4'):
	with open(filename, "rb") as handle:
		b = pickle.load(handle)
	return b


services = load_services()
networks = load_networks()

print("\nCurrent Networks Identified")
print("***************************")
for i in networks:
	print(i)


print("\nCurrent Services Identified")
print("***************************")
print("HTTPS Services: ")
for i in services['HTTPS']:
	print("   ", i+":443")
print("\nSSH Services:")
for i in services['SSH']:
        print("   ", i+":22")
print("\nFTP Services")
for i in services['FTP']:
        print("   ", i+":21")



#print(json.dumps(services, indent=4, sort_keys=True))

#for key, val in services.items():
#	print("{}    {}".format(key, val))

#print(services)
#for s in services:
#	print(s)







