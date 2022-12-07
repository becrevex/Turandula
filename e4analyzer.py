#Programmer: Brent E. Chambers
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


def interrogate_http():
	for host in services['HTTPS']:
		os.system("nmap -vv -A --script=\"http-*\" " + host + " -oN " + host+"_nmap")

interrogate_http()
