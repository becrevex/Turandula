#Programmer: Brent E. Chambers
#Date: June 17, 2016
#Filename: Engine3.py
#Description: Brute Force Discovery Engine (BFDE)

from scapy.all import *
import xlwt
import socket
import random
import string
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Disable no route found warning
from multiprocessing import Process
import time	

Port_Dict = {20:'FTPD',
		21:'FTP',
		22:'SSH',
		23:'TELNET',
		25:'SMTP',
		53:'DNS',
		79:'FINGER',
		80:'HTTP',
		8080:'PROXY',
		110:'POP3',
		139:'NETBIOS',
		161:'SNMP',
		389:'LDAP',
		143:'IMAP',
		443:'HTTPS',
		445:'SMB',
		1433:'MSSQL',
		3389:'RDP',
		512:'REXEC',
		513:'RLOGIN',
		514:'REMOTE_SHELL',
		543:'KERBEROSLOGIN',
		544:'KSHELL',
		1521:'ORACLE',
		5432:'POSTGRESQL',
		5500:'VNC1',
		5900:'VNC2'}
			
Domain = {'Cox Communications':[[24,24],[56,56],[0,63],[0,254]],
		'Sinopec':[[223,223],[118,119],[1,254],[1,254]],
		'State Gate Corp of China':[[210,210],[77,77],[176,191],[1,254]],
		'China Mobile':[[117,117],[128,191],[1,254],[1,254]],
		'China Railway':[[70,70],[32,32],[64,127],[1,254]],
		'Facebook':[[173,173],[252,252],[64,127],[0,254]],
		'ChinaNET':[[42,0],[0,0],[0,3],[1,255]],
		'Level3':[[4,4],[0,255],[0,255],[0,255]],
		'TarassulISP':[[5,5],[0,0],[0,127],[0,255]],
		'USAISC':[[6,6],[0,255],[0,255],[0,255]],
		'DoDNetwork':[[7,7],[0,255],[0,255],[0,255]],
		'IBM':[[9,9],[0,255],[0,255],[0,255]],
		'COX-ATL':[[68,68],[0,15],[0,255],[0,255]],
		'ATTNet':[[69,69],[0,0],[0,127],[0,255]],
		'SprintWZ':[[70,70],[0,14],[0,255],[0,255]]}

arin_ranges = []

def launch(count=30):
	pop = Generator(count)
	pop.bdc_p()
	pop.statistics()
	return pop


def random_IP():
        oct1 = random.randint(1,254)
        oct2 = random.randint(1,254)
        oct3 = random.randint(1,254)
        oct4 = random.randint(1,254)
        ip = str(oct1) + "." + str(oct2) + "." + str(oct3) + "." + str(oct4)
        return ip

def random_IP_Domain(Domain):
        oct1 = random.randint(Domain[0][0], Domain[0][1])
        oct2 = random.randint(Domain[1][0], Domain[1][1])
        oct3 = random.randint(Domain[2][0], Domain[2][1])
        oct4 = random.randint(Domain[3][0], Domain[3][1])
        ip = str(oct1) + "." + str(oct2) + "." + str(oct3) + "." + str(oct4)
        return ip

def source(url):
        import sys
        import urllib2
        from os import system
        req = urllib2.Request(url)
        try:
                fd = urllib2.urlopen(req)
        except:
                print "Inaccessible.  Syntax?  Proxy even?"
                return
        while 1:
                data = fd.read(3072)
                if not len(data):
                        break
                sys.stdout.write(data)
                return data

def convert_range_to_domain(range_string):                      #"192.168.1.1-192.168.60.0"
        ips = string.split(range_string, "-")
        start = ips[0]
        end   = ips[1]
        domain = []
        for i in string.split(start, "."):                      #  You like it..  [[ , ],[ , ]
                domain.append([int(i), int(string.split(end, ".")[string.split(start, ".").index(i)])])
        print domain
        return domain

# Grabs Organization and IP Address Ranges from ARIN
def update_ranges(start=1, end=21):
        import xmltodict
        collect = []
        for oct1 in range(start,end):
                site_source = source('https://whois.arin.net/rest/net/NET-'+str(oct1)+'-0-0-0-1')
                xmap = xmltodict.parse(site_source)
                print xmap['net']['name'], xmap['net']['startAddress']+"-"+xmap['net']['endAddress']
                collect.append((xmap['net']['name'], xmap['net']['startAddress']+"-"+xmap['net']['endAddress']))
		for item in collect:
			arin_ranges.append(item)
        return collect

def random_range(range):                #24.56.0.0-24.56.63.255
        start = string.split(range, "-")[0]
        end   = string.split(range, "-")[1]
        oct1 = random.randint(string.split(start, "."))

def resolve(hostname):
        return socket.gethostbyname(hostname)

def r_resolve(ip):
        return socket.gethostbyaddr(ip)



class Generator:
	DNS_collect 	 = []
	networks         = []
	New_Targets      = {}
	crawl_collection = []
	scanned_hosts    = []
	summary_hosts    = []
	host_pool        = []

	resolved_hosts   = []
	arin_ranges	 = []

	def __init__(self, number):									# A new instance generates a pool of random IPs
	self.host_pool = []
			x = 1
			while x <= number:
					self.host_pool.append(random_IP())
					x = x + 1
			print "\n[+] Indexed", len(self.host_pool), "Targets."
#		print "Resolving IP addresses in background..."
	p1 = Process(target=self.resolve_hosts)
	p1.start()
			for item in Port_Dict.keys():
				self.New_Targets[Port_Dict[item]] = []
			print "[+] Discovery data structure complete. " + str(len(self.New_Targets.keys()))+ " target services available for interrogation.\n"
	print "Resolving target IP addresses in the background..."

        def generate_new(self, number):
                self.host_pool = []
                x = 1
                while x <= number:
                        self.host_pool.append(random_IP())
                        x = x + 1
                print "Indexed", len(self.host_pool), "target IPs."


	def generate_from_domain(self, number, domain='Cox Communications'):
		self.host_pool = []
		x = 0
		print range_domain
		try:
			range_domain = convert_range_to_domain(domain)
			while x <= number:
				self.host_pool.append(random_IP_domain(range_domain))
		except:
			range_domain = domain
			while x <= number:
				self.host_pool.append(random_IP_domain(Domain[domain]))
                self.host_pool = []
                x = 0
		print range_domain
                while x <= number:
                        self.host_pool.append(random_IP_Domain(Domain[range_domain]))
                        x = x + 1
                print "Indexed", len(self.host_pool), "targets."

	def generate_from_range(self, number, range):
		self.host_pool = []
		x = 1
		try:
			range_domain = convert_range_to_domain(range)
		except:
			print "ex. \'58.203.33.12-58.203.33.181\'"  	
		while x <= number:
			self.host_pool.append(random_IP_Domain(range_domain))
			x = x + 1
		print "Indexed", len(self.host_pool), "targets."


	def interrogate_net(self):
		#dns resolve the collection
		#network sweep the network
			#add new hosts to crawl_collection
		
		pass


	def interrogate_host(self, host):
		pass
		#dns resolve the host
		#port_scan the host
		self.portscan_host(host)
		#various nmap/python scripts
		#brute force services
	
	# Resolves IP addresses in the host_pool	
	def resolve_hosts(self):
		collect = []
		hostname = ''
		for item in self.host_pool:
			try:
				hostname = socket.gethostbyaddr(item)
				collect.append((hostname[2], hostname[0]))
				#print hostname
#				collect.append(hostname[2], hostname[0])
#				print hostname[0], hostname[2]
#				self.resolved_hosts.append((hostname[2], hostname[0]))
			except:
				pass

#			self.resolved_hosts.append((hostname[2], hostname[0]))	
				#print hostname[2], hostname[0]
#		for item in collect:
#			print item
		print "Resolved", len(collect), "Targets. \nSee 'self.resolved_hosts'"
		for item in collect:
			print item
			self.DNS_collect.append(item)                                
		return collect

	def resolve_net(self):
		collect = []
		for item in self.networks:
			try:
				hostname = socket.gethostbyaddr(item)
				collect.append((hostname[2], hostname[0]))
				print hostname
			except:
				pass
				#hostname = "unknown host"
				#print hostname
#			collect.append((hostname[2],hostname[0]))
		return collect 

	def portscan_host(self, host):
		if self.is_up(host) == True:
			resp = sr1(IP(dst=host)/TCP(sport=21000,dport=range(1,1024),flags="S"),timeout=0.27, verbose=False)
			#pkts = sr1(IP(dst=host)/TCP(sport=random.randint(21000,51000),dport=(Port_Dict.keys()),flags="S"),timeout=0.27)#, verbose=False)
			pkts = resp
			print pkts
			for item in pkts:
				try:
					print item.summary()
				except:
					pass
		else:
			print "Host is not alive."
		

	def portscan_host_nmap(self, host):
		os.system("nmap -vv -T4 -sS " + host + " -oG ./port_scan.rsc")
		file = open("./port_scan.rsc")
		collect = []
		for item in file:
			sLine = string.split(item)
			if sLine[0] == "Host:":
				collect.append(sLine)
		for i in collect:
			print i
		return collect



	def ping_sweep_nmap(self, host):
		octets = string.split(host, ".")
		net = octets[0]+"."+octets[1]+"."+octets[2]+".0/24"
		os.system("nmap -vv -T4 -sP " + net + " -oG ./ping_sweep.rsc")
		file = open("./ping_sweep.rsc")
		collect =[]
		for item in file:
			if string.split(item)[-1] == 'Up':
				collect.append(string.split(item)[1])
		for i in collect:
			print "Live host: ", i
		return collect


	def ping_sweep(self, host):
		octets = string.split(host, ".")
		net = octets[0]+"."+octets[1]+"."+octets[2]
		net_range = []
		print "[*] Setting up scanner..."
		for item in range(1, 254):
			if self.is_up(net+"."+str(item)) == True:
				self.crawl_collection.append(net+"."+str(item))#, socket.gethostbyaddr(net+"."+str(item))))
			else:
				pass
		
				
		#range = octets[0]+"."+octets[1]+"."+octets[2]+".0"+"/24"
		#self.is_up(range)

	
	def is_up(self, ip):
		print "Pinging", ip
		icmp = IP(dst=ip)/ICMP()
		resp = sr1(icmp, timeout=.75, verbose=False)
		if resp == None:
			return False
		else:
			pkt_sum = string.split(resp.summary())
			print "[+] " + resp.summary()
			
		return True



	def discovery(self, port):
		try:
			svc_name = Port_Dict[port]
			print "Discovering open target", svc_name, "services...."
		except:
			svc_name = 'Other'
			print "Discovering open target services on port "+str(port)+" ..."
		summary_hosts = []
		new_hosts = []
		for item in self.host_pool:
			pkt = sr1(IP(dst=item)/TCP(sport=random.randint(21000,51000),dport=port,flags="S"),timeout=0.33, verbose=False)
#			try:
			if pkt != None:
				if "SA" in string.split(pkt.summary()):
					print "RESP-"+pkt.summary()
					self.New_Targets[svc_name].append(pkt.src)
					#self.New_Targets[svc_name].append(string.split(pkt.summary())[3])
					print "\n[*] ", svc_name, "service found: ", string.split(pkt.summary())[3], "\n"#, socket.gethostbyaddr(pkt.src)[0], "\n"
				elif "RA" in string.split(pkt.summary()):
						print pkt.summary()
						self.networks.append(pkt.src)
						print "[+] New target network: ", string.split(pkt.summary())[3]


	def statistics(self):
		print "******************************************"
		print "*           Statistic Summary            *"
		print "******************************************"
				print "[+] New network segments discovered:     ", len(self.networks)
				print "[+] Systems probed per cycle:            ", len(self.host_pool)
		total = 0
		for item in self.New_Targets.keys():
			total = total + len(self.New_Targets[item])
		print "[+] Total systems/services added:        ", total
		print "------------------------------------------"
				print "[+] Newly Added Services                  "
		print "------------------"
				for srv in self.New_Targets.keys():
			if len(self.New_Targets[srv]) > 0:
				print "\n[+] Target Service: ", srv
				for item in self.New_Targets[srv]:
					try:	
						resolved_host = socket.gethostbyaddr(item)
									print item, resolved_host[0]
					except:
						print item


	def bdc(self, count=6, pool=500):  		# Basic Discovery Cycle: (FTP,SSH,HTTPS), Cycle=6, Pool=500)
		x = 0
		print "Basic Discovery Cycle starting..."
		print "Passes: ", count
		while x <= count:
		     self.generate_new(pool)
		     self.discovery(21)
		     self.discovery(22)
		     self.discovery(443)
		     x = x + 1
		     print "[+] Pass", x, "completed."
		self.statistics()


	def bdc_p(self, count=6, pool=400):
		x = 0
		while x <= count:
			proc = []
			p1 = Process(target=self.discovery(21))
			p2 = Process(target=self.discovery(22))
			p3 = Process(target=self.discovery(443))
			proc = [p1, p2, p3]
			for item in proc:
				print "Starting process..."
				item.start()	
			for item in proc:
				item.join()
			x = x + 1
			self.generate_new(200)


	def run(self, command):
		p1 = Process('target=self.resolve_hosts')
		p1.start()


	def show_targets(self):
		print "Current Target Inventory"
		print "************************"
		for item in self.New_Targets.keys().sort():
			print item, "\n", "\t\t", self.New_Targets[item],
	

	def load_data(self, filename=''):
		pass


	def save_data(self, filename=''):
		workbook = xlwt.Workbook()
		# Write the hosts in each to the sheets
		for item in Port_Dict.keys():
			newSheet = workbook.add_sheet(item)		#Create new sheets based on Port Dict
			x = 0
			for i in self.New_Targets[item]:
				newSheet.write(x, 0, i)
				x = x + 1
		workbook.save(filename)

			
def console():
	pass

