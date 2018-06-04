Background
----------

Random target generator for network discovery, threat landscaping, and playing AIC (adversarial informatics combat).  Turandula came to me while I was suffering through a Linux class that was required for my Programming and Systems Analysis degree.  The idea of finding random hosts on the Internet always interested me, so I whipped together the core functionality of generating a random IP address and testing it for reachability.  The rest of the project grew from there.  

Basic usage:

>>> import Engine4
>>> spider = Engine4.Generator(10)        # 10 == number of random IP's to generate 
### spider will start resolving the randomly generated IP's when the object is created.
>>> spider.bdc_p()                        # Default arguments are bdc_p(count=6, pool=250)
### bdc_p() is a threaded function, performing the connection tests in parallel
---Output---
Parallel Discovery Cycle starting...
Discovering open target FTP services..
Discovering open target SSH services..
Discovering open target HTTPS services..
Starting process<Process(Process-2, initial)>
Starting process<Process(Process-3, initial)>
Starting process<Process(Process-4, initial)>
Indexed 250 target IPs.
Discovering open target FTP services..
[+] (RA) new potential target network: 124.50.13.57:ftp
[*] FTP service found: 134.119.47.223:ftp
[*] FTP service found: 70.39.235.129:ftp
...
----------------------------------------------
    Newly Added Services
----------------------------------------------
  [+] Target Service:  HTTPS
            23.59.45.31(a23-59-45-31.deploy.static.akamaitechnologies.com)
Turandula file does not exist.
rm: cannot remove './Turandula.rsc': No such file or directory
 [+] AIC file save complete.
-rw-r--r-- 1 root root 371 Jun  4 15:10 Turandula.rsc

---Output---

spider.statistics()                       # Displays the results of the previous cycle
**********************************************
*               Statistic Summary            *
**********************************************
[+] New network segments discovered:      5
[+] Systems probed per cycle:             50
[+] Total systems/services added:         11

----------------------------------------------
    Newly Added Services
----------------------------------------------
  [+] Target Service:  networks
            115.4.76.161
            115.4.76.161
            115.4.76.161
            115.58.224.133(hn.kd.ny.adsl)
            115.58.224.133(hn.kd.ny.adsl)
  [+] Target Service:  FTP
            111.92.185.154(qd24.bmx001.com)
  [+] Target Service:  HTTPS
            23.59.45.31(a23-59-45-31.deploy.static.akamaitechnologies.com)
            111.92.185.154(qd24.bmx001.com)
            223.119.212.125
            192.237.155.85
  [+] Target Service:  SSH
            111.92.185.154(qd24.bmx001.com)


About
-----
Created by Brent "q0m" Chambers of Cygiene Solutions
www.cygienesolutions.com

