<img src="https://a.pomf.cat/wmcshj.png"></img><br></br>
<b>CDNRECON is a reconnaissance tool that tries to find the origin or backend IP address of a website protected by a CDNs reverse proxy. You can use it to get a head start when penetration testing a client protected by one aswell as to find possible misconfigurations on your own server. What ever your use case may be, CDNRECON can also be used as a general recon / scanning tool since it automates some common recon tasks in the process.

<b>The things CDNRECON does:
- Checks the target domain nameservers
- Dumps DNS records with DNSDumpster
- Gets subdomains from the target domains SSL certificate
- Gets subdomains with SecurityTrails API
- Checks common subdomains and gets their IP addresses
- Checks if any of the IP addresses belong to Cloudflare
- Checks if any of the IP addresses belong to Akamai
- Checks if any of the IP addresses are using the AkamaiGHost server
- Optionally returns data from Shodan for possibly leaked IP addresses
- Optionally writes the results to target.com-results.txt file

Shodan and SecurityTrails API keys are NOT required. Altough it's recommended to supply them for maximum output, CDNRECON tries other things before using them.

 <b>Checking the nameservers, common subdomains and their IP addresses</b>
 ```
    __________  _   ______  ________________  _   __
   / ____/ __ \/ | / / __ \/ ____/ ____/ __ \/ | / /
  / /   / / / /  |/ / /_/ / __/ / /   / / / /  |/ / 
/ /___/ /_/ / /|  / _, _/ /___/ /___/ /_/ / /|  /  
\____/_____/_/ |_/_/ |_/_____/\____/\____/_/ |_/   
                                                   

[i] Checking juuso.computer nameservers . . .
[+] Nameservers: jimmy.ns.cloudflare.com, lorna.ns.cloudflare.com
[+] juuso.computer is pointing to Cloudflares nameservers
==================================================
[i] DNSDumpster output for juuso.computer
[+] juuso.computer seems to be valid
==================================================
[i] Getting subdomains from juuso.computer's SSL certificate . . .
[i] This might take a while, hang tight
[+] found *.juuso.computer from the SSL certificate
[+] found www.juuso.computer from the SSL certificate
==================================================
[i] Checking common subdomains . . .
[+] www.juuso.computer is a valid domain                     
==================================================    
[i] Getting subdomain IP addresses . . .
[+] juuso.computer has an IP address of 104.21.75.196
[-] Can't resolve *.juuso.computer's IP address
[+] www.juuso.computer has an IP address of 172.67.180.230
==================================================
````
<b>Getting subdomains from the target domains SSL certificate</b>
````
[i] Getting subdomains from juuso.computer's SSL certificate . . .
[i] This might take a while, hang tight
[+] found *.juuso.computer from the SSL certificate
[+] found www.juuso.computer from the SSL certificate
````
<b>Dumping DNS records with DNSDumpster</b>
````
[i] DNSDumpster output for juuso.computer
[+] juuso.computer seems to be valid
````
 <b>Checking if the IP addresses belong to Cloudflare</b>
````
==================================================
[i] Checking if 104.16.124.96 is Cloudflare . . .
[+] 104.16.124.96 is Cloudflare
[+] Ray-ID: 7556c47a2d879914-ARN
[+] Country: Canada
[i] Checking if 216.58.210.147 is Cloudflare . . .
[!] 216.58.210.147 is NOT cloudflare
[i] Checking if 104.18.41.174 is Cloudflare . . .
[+] 104.18.41.174 is Cloudflare
[+] Ray-ID: 7556c47c8bb615dc-ARN
[+] Country: Canada
[i] Checking if 104.18.39.119 is Cloudflare . . .
[+] 104.18.39.119 is Cloudflare
[+] Ray-ID: 7556c47e0d3afe2c-HEL
[+] Country: Canada
  
````
 <b>Checking if the IP addresses belong to Akamai and if they're using the AkamaiGHost server</b>
```
[i] Checking if 23.61.197.234 is Akamai . . .
[+] 23.61.197.234 Server detected as AkamaiGHost
[+] Country: Sweden
[i] Checking if 95.101.93.134 is Akamai . . .
[+] 95.101.93.134 Server detected as AkamaiGHost
[+] Country: Sweden
==================================================
````
<b>Returns data for non Cloudflare IP addresses from Shodan</b>
````
[i] Shodan results for 23.61.197.234
[+] ISP: Akamai Technologies, Inc.
[+] Country: Sweden
[+] Hostname(s): ['a23-61-197-234.deploy.static.akamaitechnologies.com', 'kbb.com']
[+] Domain(s): ['akamaitechnologies.com', 'kbb.com']
[+] Open port(s): [80, 443]
[i] Shodan results for 95.101.93.134
[+] ISP: Akamai Technologies, Inc.
[+] Country: Sweden
[+] Hostname(s): ['a95-101-93-134.deploy.static.akamaitechnologies.com', 'kbb.com']
[+] Domain(s): ['akamaitechnologies.com', 'kbb.com']
[+] Open port(s): [80, 443]
````
## Installation and usage

<b>Requires atleast python version 3.6 since it uses f-strings.
>Tested on Arch Linux. It should work on any Linux distribution and Windows.

<b>Clone the repository
```
$ sudo git clone https://github.com/Juuso1337/CDNRECON
```
<b>Install the required depencies
```
$ cd CDNRECON
$ pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip --user
$ pip3 install -r requirements.txt
```
<b>Sample usage guide

```
$ nano config
$ write shodan=API-KEY-HERE
$ write securitytrails=API-KEY-HERE
$ CTRL + X to save
$ python3 main.py example.com -c config
```

<b> For more in-depth usage info, supply the -h flag (python3 main.py -h).</b>
````
   __________  _   ______  ________________  _   __
  / ____/ __ \/ | / / __ \/ ____/ ____/ __ \/ | / /
 / /   / / / /  |/ / /_/ / __/ / /   / / / /  |/ / 
/ /___/ /_/ / /|  / _, _/ /___/ /___/ /_/ / /|  /  
\____/_____/_/ |_/_/ |_/_____/\____/\____/_/ |_/   
                                                   

usage: main.py [-h] [-c CONFIG] [-t THREADS] [-o OUTPUT] domain

CDNRECON - A Content Delivery Network recon tool

positional arguments:
  domain                Domain to scan

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configurtation file (see github for syntax)
  -t THREADS, --threads THREADS
                        Max threads the program will use.
  -o OUTPUT, --output OUTPUT
                        Write results to the specified file

````

## How to get a Shodan API key
<b>1. Register an account at https://account.shodan.io/ (it's totally free).<br>
<b>2. Head over the to the "Account" page and see the "API key" field.<br>
<img src="https://a.pomf.cat/nvdiap.png"></img>

## How to get a SecurityTrails API key
<b>1. Register an account at https://securitytrails.com/app/signup (it's totally free).<br>
<b>2. Head over to your account page and see the "API keys" section.<br><br>
<img src="https://a.pomf.cat/phbfgo.png"></img>

## To do
- Add more CDNs
- Add Censys support
- Add certificate search [ DONE ]
- Add IPv4 range bruteforcer
- Add favicon hash search
- Add html body hash search
