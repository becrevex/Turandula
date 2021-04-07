#Programmer: Brent E. Chambers
#Date: June 17, 2016
#Filename: Engine3.py
#Description: Brute Force Discovery Engine (BFDE)

from scapy.all import *
from ipaddress import IPv4Network
#import xlwt
import sys
import socket
import random
import string
import pickle
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Disable no route found warning
from multiprocessing import Process


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
                5900:'VNC2',
		'Networks':'CIDR'}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



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

def print_green(input_text):
	print(bcolors.OKGREEN + input_text + bcolors.ENDC)

def print_cyan(input_text):
	print(bcolors.OKCYAN + input_text + bcolors.ENDC)

def print_red(input_text):
	print(bcolors.FAIL + input_text + bcolors.ENDC)

def print_yellow(input_text):
	print(bcolors.WARNING + input_text + bcolors.ENDC)

def print_bold(input_text):
	print(bcolors.BOLD + input_text + bcolors.ENDC)

def print_blue(input_text):
	print(bcolors.OKBLUE + input_text + bcolors.ENDC)

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

def random_IP_domain(Domain):
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
        try:
             return socket.gethostbyaddr(ip)
        except:
             pass

class Generator:
        DNS_collect      = []
        networks         = []
        New_Targets      = {}
        crawl_collection = []
        scanned_hosts    = []
        summary_hosts    = []
        host_pool        = []
        resolved_hosts   = []
        arin_ranges      = []


        #***
        # Name: Generator[constructor]()
        # Description: A Generator object, once initialized will generate a pool of random IP's
        # @param  - int number
        # @return - None
        #
        def __init__(self, number):            # A new instance generates a pool of random IPs
                self.host_pool = []
                x = 1
                while x <= number:
                                self.host_pool.append(random_IP())
                                x = x + 1
                print_green("\n[+] Indexed " + str(len(self.host_pool)) + " targets.")
                #print "Resolving IP addresses in background..."
                p1 = Process(target=self.resolve_hosts)
                p1.start()
                for item in Port_Dict.keys():
                                self.New_Targets[Port_Dict[item]] = []
		try:
			self.New_Targets = self.load_services()
			#print_green("Saved service object " + self.New_Targets + " loaded.")
		except:
			print_red("Could not load saved service object.")
		try:
			self.networks = self.load_networks()
			#print_green("Saved network target object " + self.networks + " loaded.")
		except:
			print_red("Could not load saved networks object.")

                print "[+] Discovery data structure complete. " + str(len(self.New_Targets.keys()))+ " target services available for interrogation.\n"
                print_green("Resolving target IP addresses in the background...")

        # ****
        # Name: generate_new()
        # Description: Generates a pool of randomized IP addresses.
        # @param  - int number [the size of the IP pool]
        # @return - None
        # 
        def generate_new(self, number):
                self.host_pool = []
                x = 1
                while x <= number:
                        self.host_pool.append(random_IP())
                        x = x + 1
                print "Indexed", len(self.host_pool), "target IPs."

        # ****
        # Name: generate_from_domain()
        # Description: Generates a pool of randomized IP addresses within a domain/network range  
        # @param  - int number [the size of the IP pool], string domain [domain from dict]
        # @return - None
        # 
        def generate_from_domain(self, number, domain='Cox Communications'):
                self.host_pool = []
                x = 0
                #print range_domain
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

        # ****
        # Name: generate_from_range()
        # Description: Generates a pool of randomized IP addresses from a hyphenated range string
        # @param  - int number [the size of the IP pool], string range [IP range (ex. 192.168.0.11-192.168.5.90)]
        # @return - None
        # 
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


        # ****
        # Name: interrogate_net()
        # Description: Take a network range, and performs general recon and enumeration
        # @param  - string network-range (or IP, which is then stripped for a C class /24 by default)
        # @return - Data Structure with network attributes and characteristics
        # 
        def interrogate_net(self):
                #dns resolve the collection
                #network sweep the network
                        #add new hosts to crawl_collection

                pass

        # ****
        # Name: interrogate_host()
        # Description: Perfrom general recon and enumeration of the provided host and its attack surface
        # @param  - string host 
        # @return - None
        # 
        def interrogate_host(self, host):
                pass
                #dns resolve the host
                #port_scan the host
                self.portscan_host(host)
                #various nmap/python scripts
                #brute force services

        # ****
        # Name: resolve_hosts()
        # Description: DNS resolution of existing hosts in the objects' host_pool
        # @param  - string host 
        # @return - None
        # 
        def resolve_hosts(self):
                collect = []
                hostname = ''
                for item in self.host_pool:
                        try:
                                hostname = socket.gethostbyaddr(item)
                                collect.append((hostname[2], hostname[0]))
                        except:
                                pass
                print "Resolved", len(collect), "Targets. \nSee 'self.resolved_hosts'"
                for item in collect:
                        print item
                        self.DNS_collect.append(item)
                return collect

        # ****
        # Name: resolve_net()
        # Description: DNS resolution of existing hosts within the object's network array
        # @param  - string host 
        # @return - None
        # 
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
#                       collect.append((hostname[2],hostname[0]))
                return collect


        # ****
        # Name: portscan_host()
        # Description: Scapy implementation of a TCP SYN scan (1-1024)
        # @param  - string host 
        # @return - None
        # 
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

        # ****
        # Name: portscan_host_nmap()
        # Description: nmap system command of a TCP SYN scan (1-1024) (sloppy)
        # @param  - string host 
        # @return - None
        # 
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

        # ****
        # Name: is_up()
        # Description: Scapy implementation of a ICMP ping to test host reachability
        # @param  - string host / ip
        # @return - None
        # 
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


	# Description: Scapy implementation of an ICMP ping sweep
	# @param - string CIDR_network e.g. 192.168.0.0/24
	# @return - None
	#
        def ping_sweep(self, network):
                addresses = IPv4Network(network)
                live_count = 0

                for host in addresses:
                    if(host in (addresses.network_address, addresses.broadcast_address)):
                        continue

                    resp = sr1( IP(dst=str(host)) / ICMP(), timeout=1.21, iface='eth0', verbose=0 )
                    if resp is None:
                        pass
                        #print(host, " is down or not responding.")
                    else:
                        print(host, resp.getlayer(ICMP).type)
                    """
                    if resp is None:
                        break
                        #print(host, " is down or not responding.")

                    elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        break
                        #print(host, " is blocking ICMP.")

                    else:
                        print(host, "alive.")
                        live_count += 1
                    """
                #print_green(str(live_count) + addresses.num_addresses + " hosts are online.")




        # ****
        # Name: discovery()
        # Description: TCP port probe of a each host in the host_pool
        # @param  - string host
        # @return - None
        #
        def discovery(self, port):
                try:
                        svc_name = Port_Dict[port]
                        print_green("Discovering open target " + svc_name + " services....")
                except:
                        svc_name = 'Other'
                        print_green("Discovering open target services on port "+str(port)+" ...")
                summary_hosts = []
                new_hosts = []
                for item in self.host_pool:
                        pkt = sr1(IP(dst=item)/TCP(sport=random.randint(21000,51000),dport=port,flags="S"),timeout=0.33, verbose=False)
			print "Probing: " + item + ":" + str(port)
#                        #print '{}\r'.format("Probing: "+item+":"+str(port))
#			sys.stdout.write('\r' + str('Probing: ' + item + ':' + str(port)) + ' '*9)
#                        sys.stdout.flush()
#                       try:
                        if pkt != None:
                                if "SA" in string.split(pkt.summary()):
                                        #print "RESP-"+pkt.summary()
                                        self.New_Targets[svc_name].append(pkt.src)
                                        #self.New_Targets[svc_name].append(string.split(pkt.summary())[3])
                                        print_cyan( "[*] " + svc_name + " service found: " + string.split(pkt.summary())[3])   #, socket.gethostbyaddr(pkt.src)[0], "\n"
                                        try:
                                             print_blue("[+] Hostname: " + r_resolve(pkt.src)[0])
                                        except:
                                             print("[+] Hostname: could not resolve")
					self.save_service()
                                elif "RA" in string.split(pkt.summary()):
                                                #print pkt.summary()
                                                netwk = ('.'.join(pkt.src.split(".")[:3]))+".0/24"
                                                netwk_range = ('.'.join(pkt.src.split(".")[:3])) + ".0-" + ('.'.join(pkt.src.split(".")[:3])) +  ".254"
                                                #self.networks.append(pkt.src)
                                                self.networks.append(netwk_range)
                                                #print_green("[+] New potential target network: " + string.split(pkt.summary())[3])
                                                print_yellow("[+] New potential target network: " + netwk_range)
                                                try:
                                                    print_blue("[+] Hostname ("+pkt.src+"): " + r_resolve(pkt.src)[0])
                                                except:
                                                    print("[!] Hostname: could not resolve")
                                                self.save_network()
        # ****
        # Name: smb_discovery()
        # Description: Adding SMBv3 CVE-2020-0796 discovery capability. 
        # @param  - int port (Default 445/tcp)
        # @return - None
        # 
        def smb_discovery(self, port=445):
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
#                       try:
                        if pkt != None:
                                if "SA" in string.split(pkt.summary()):
                                        print "RESP-"+pkt.summary()
                                        self.New_Targets[svc_name].append(pkt.src)
                                        #self.New_Targets[svc_name].append(string.split(pkt.summary())[3])
                                        print "\n[*] ", svc_name, "service found: ", string.split(pkt.summary())[3], "\n"#, socket.gethostbyaddr(pkt.src)[0], "\n"
                                elif "RA" in string.split(pkt.summary()):
                                                print pkt.summary()
                                                self.networks.append(pkt.src)
                                                print "[+] New potential target network: ", string.split(pkt.summary())[3]


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


        def bdc(self, count=6, pool=500):               # Basic Discovery Cycle: (FTP,SSH,HTTPS), Cycle=6, Pool=500)
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


        def bdc_p(self, count=6, pool=400):				# Basic Discovery Cycle Parallel Implementation
		print "Cycle count:     ", count
		print "Host pool count: ", pool
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


	def bdc_p_ssh(self, count=2, pool=400):                             # Basic Discovery Cycle for SSH hosts
                print "[arg1] Cycle count:     ", count
                print "[arg2] Host pool count: ", pool
                x = 0
                while x <= count:
                        proc = []
                        p1 = Process(target=self.discovery(22))
                        proc = [p1]
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


        def load_services(self, filename='services.e4'):
                with open(filename, "a+") as handle:
			b = pickle.load(handle)
		return b

	def load_networks(self, filename='networks.e4'):
		with open(filename, "a+") as handle:
			b = pickle.load(handle)
		return b

        def save_service(self, filename='services.e4'):
			timestamp = time.strftime("%Y%m%d-%H%M%S")
                        object_pi = self.New_Targets
			services_file = open(filename, "w")
                        #file_h = open("Discovery_probe_"+timestamp+".e4", 'w')
                        pickle.dump(object_pi, services_file)
			print_green("[+] Discovered services file updated.")
			services_file.close()


        def save_network(self, filename='networks.e4'):
                        object_pi = self.networks
			networks_file = open(filename, "w")
                        #file_h = open("Discovery_networks_"+timestamp+".e4", 'w')
                        pickle.dump(object_pi, networks_file)
                        print_green("[+] Discovered networks file updated.")
			networks_file.close()

	def save_session(self):
			timestamp = time.strftime("%Y%m%d-%H%M%S")
			file_h = open("Discovery_probe_"+timestamp+".e4", "w")
			file_i = open("Network_probe_"+timestamp+".e4", "w")
			pickle.dump(self.New_Targets, file_h)
			print_green("Discovered services file saved at: " + timestamp)

			pickle.dump(self.networks, file_i)
			print_green("Discovered networks file saved at: " + timestamp)
			file_h.close()
			file_i.close()


        def save_data(self, filename='instance.xls'):
                workbook = xlwt.Workbook()
                # Write the hosts in each to the sheets
                for item in Port_Dict.keys():
                        newSheet = workbook.add_sheet(item)             #Create new sheets based on Port Dict
                        x = 0
                        for i in self.New_Targets[item]:
                                newSheet.write(x, 0, i)
                                x = x + 1
                workbook.save(filename)


def console():
        os.system("/bin/bash")
