<img align="center" src="https://github.com/becrevex/Turandula/blob/master/img/sample.JPG" />
<br>
# Basic usage: <br>
<br>
>>> import Engine4<br>
>>> spider = Engine4.Generator(10)        # 10 == number of random IP's to generate <br>
spider will start resolving the randomly generated IP's when the object is created.<br>
>>> spider.bdc_p()                        # Default arguments are bdc_p(count=6, pool=250)<br>
<br>
bdc_p() is a threaded function, performing the connection tests in parallel<br>
<br>
---Output---<br>
Parallel Discovery Cycle starting...<br>
Discovering open target FTP services..<br>
Discovering open target SSH services..<br>
Discovering open target HTTPS services..<br>
Starting process<Process(Process-2, initial)><br>
Starting process<Process(Process-3, initial)><br>
Starting process<Process(Process-4, initial)><br>
Indexed 250 target IPs.<br>
Discovering open target FTP services..<br>
[+] (RA) new potential target network: 124.50.13.57:ftp<br>
[*] FTP service found: 134.119.47.223:ftp<br>
[*] FTP service found: 70.39.235.129:ftp<br>
...<br>
----------------------------------------------<br>
    Newly Added Services<br>
----------------------------------------------<br>
  [+] Target Service:  HTTPS<br>
            23.59.45.31(a23-59-45-31.deploy.static.akamaitechnologies.com)<br>
Turandula file does not exist.<br>
rm: cannot remove './Turandula.rsc': No such file or directory<br>
 [+] AIC file save complete.<br>
-rw-r--r-- 1 root root 371 Jun  4 15:10 Turandula.rsc<br>
<br>
---Output---<br>
<br>
spider.statistics()                       # Displays the results of the previous cycle<br>
**********************************************<br>
*               Statistic Summary            *<br>
**********************************************<br>
[+] New network segments discovered:      5<br>
[+] Systems probed per cycle:             50<br>
[+] Total systems/services added:         11<br>
<br>
----------------------------------------------<br>
    Newly Added Services<br>
----------------------------------------------<br>
  [+] Target Service:  networks<br>
            115.4.76.161<br>
            115.4.76.161<br>
            115.4.76.161<br>
            115.58.224.133(hn.kd.ny.adsl)<br>
            115.58.224.133(hn.kd.ny.adsl)<br>
  [+] Target Service:  FTP<br>
            111.92.185.154(qd24.bmx001.com)<br>
  [+] Target Service:  HTTPS<br>
            23.59.45.31(a23-59-45-31.deploy.static.akamaitechnologies.com)<br>
            111.92.185.154(qd24.bmx001.com)<br>
            223.119.212.125<br>
            192.237.155.85<br>
  [+] Target Service:  SSH<br>
            111.92.185.154(qd24.bmx001.com)<br>
<br>
<br>
About<br>
-----<br>
