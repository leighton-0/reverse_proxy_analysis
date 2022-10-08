#    __________  _   ______  ________________  _   __
#   / ____/ __ \/ | / / __ \/ ____/ ____/ __ \/ | / /
#  / /   / / / /  |/ / /_/ / __/ / /   / / / /  |/ / 
# / /___/ /_/ / /|  / _, _/ /___/ /___/ /_/ / /|  /  
# \____/_____/_/ |_/_/ |_/_____/\____/\____/_/ |_/   
#                                                     
# Created by @Juuso1337 and @R00tendo
# This program tries to find the origin IP address of a website protected by a reverse proxy
# Download the latest version from github.com/juuso1337/CDNRECON
# Version 2.5.2

################################################################# All libraries required by this program
import sys                                                      #
import os                                                       #
if os.name == 'nt':                                             #
    WIN = True                                                  #                                              
else:                                                           #
    WIN = False                                                 #
    import pydig                                                #
from pyfiglet import Figlet                                     # Render ASCII art
import requests                                                 # Simple HTTP library
import socket                                                   # Basic networking
import threading                                                # Threads
import argparse                                                 # Parse commmand line arguments
import shodan                                                   # IoT search engine
import time                                                     # Time
import random                                                   # Random number generator
from colorama import Fore, Style                                # Make ANSII color codes work on Windows
from colorama import init as COLORAMA_INIT                      # Colorama init
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI           # Finds subdomains
from bs4 import BeautifulSoup                                   # Soup, yummy
import re                                                       # Regex
from pysecuritytrails import SecurityTrails, SecurityTrailsError# Securitytrails intelligence API
#################################################################
#--------------------------------------------------------------

#Print logo
ASCII = Figlet(font='slant', width=100)
ASCII_RENDER = ASCII.renderText("CDNRECON")
print (f"{Fore.YELLOW}{ASCII_RENDER}{Style.RESET_ALL}")

PARSER = argparse.ArgumentParser(description = 'CDNRECON - A Content Delivery Network recon tool')

PARSER.add_argument('TARGET_DOMAIN', metavar ='domain', help ='Domain to scan')
PARSER.add_argument('-c', '--config', help ='Configurtation file (see github for syntax)')
PARSER.add_argument('-t', '--threads', help='Max threads the program will use.', default='20')
PARSER.add_argument('-o', '--output', help="Write results to the specified file", default=None)

ARGS = PARSER.parse_args()

###################################### All command line arguments
TARGET_DOMAIN  = ARGS.TARGET_DOMAIN  #
######################################
#-----------------------------------

############################################################# Some global variables
VALID_SUBDOMAINS = []                                       # Valid subdomains get stored in this list
IP_ADDRESSES     = []                                       # Subdomain IP addresses get stored in this list
NOT_CLOUDFLARE   = []                                       # Non Cloudflare IP addresses get stored in this list
AKAMAI           = []                                       # Akamai IP addresses get stored in this list
class API_KEYS:                                             # Api keys that will be used to get for example subdomains
    securitytrails=None                                     #
    shodan=None                                             #
DIRECTORY_PATH  = os.path.dirname(os.path.abspath(__file__))# Absolute path to the app directory
GLOBAL_THREADS = int(ARGS.threads)                          # Max threads the program will use
RUNNING_THREADS = 0                                         # Keeps count of threads running simultaneously
#############################################################
#---------------------

# Parses and loads API keys from a config file (specified with -c/--config)

if ARGS.config != None:
    for LINE in open(ARGS.config, 'r'):
        LINE = LINE.strip()
        if len(LINE.split("=")) == 2:
            exec(f'API_KEYS.{LINE.split("=")[0]} = "{LINE.split("=")[1].strip()}"')

# Initialize colorama

if os.name == 'nt':
    COLORAMA_INIT(convert=True)
else:
    COLORAMA_INIT()

# Start of load wordlists into memory
USER_AGENT_STRINGS = open(f"{DIRECTORY_PATH}/wordlists/User-Agents").read().split("\n")
USER_AGENT_STRINGS = [x for x in USER_AGENT_STRINGS if x != '']
SUBDOMAINS = open(f"{DIRECTORY_PATH}/wordlists/Subdomains").read().split("\n")
SUBDOMAINS = [x for x in SUBDOMAINS if x != '']
# End of load wordlists into memory

##############################
#      Define functions      #
##############################

def IS_POINTING_TO_CF():

        if WIN == True:
            pass

        else:
            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Checking {Fore.MAGENTA}{TARGET_DOMAIN}{Style.RESET_ALL} nameservers . . .")
            NS_RECORD = pydig.query(TARGET_DOMAIN, "NS")

            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Nameservers: {Fore.MAGENTA}{', '.join(NS_RECORD).replace('., ', ', ')[:-1]}{Style.RESET_ALL}")

            if 'cloudflare' in str(NS_RECORD):
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.MAGENTA}{TARGET_DOMAIN}{Style.RESET_ALL} is pointing to Cloudflares nameservers")
            else:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}{TARGET_DOMAIN}{Style.RESET_ALL} is not pointing to Cloudflares nameservers")
                sys.exit()
                

def DNSDUMPSTER():

    try:
        RESPONSE = requests.get("https://dnsdumpster.com", verify=True)
        STATUS_CODE = RESPONSE.status_code
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}dnsdumpster.com{Style.RESET_ALL} seems to be down, skipping . . .")

    if STATUS_CODE != 200:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}dnsdumpster.com{Style.RESET_ALL} seems to be down, skipping . . .")
    
    else:
        print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} DNSDumpster output for {Fore.BLUE}{TARGET_DOMAIN}{Style.RESET_ALL}")

        try:
            RESULTS = DNSDumpsterAPI().search(TARGET_DOMAIN)['dns_records']['host']
            for RESULT in RESULTS:
                RESULT_DOMAIN = RESULT['domain']
                try:
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.BLUE}{RESULT_DOMAIN}{Style.RESET_ALL} seems to be valid")
                    VALID_SUBDOMAINS.append(RESULT_DOMAIN)

                except Exception:
                    pass

        except Exception as e:
                print(f"{e}")

def CERTIFICATE_SEARCH():
        
        CRT_AGENT = random.choice(USER_AGENT_STRINGS)

        HEADERS = {

        'User-Agent': CRT_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://crt.sh/',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Cache-Control': 'max-age=0',

        }

        PARAMS= {

        'q': TARGET_DOMAIN,

        }
        
        SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        RESULT = SOCK.connect_ex((TARGET_DOMAIN,443))

        if RESULT != 0:
            return f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}{TARGET_DOMAIN}{Style.RESET_ALL} doesn't seem to be using HTTPS, skipping certificate search"

        try:
            
            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Getting subdomains from {Fore.MAGENTA}{TARGET_DOMAIN}'s{Style.RESET_ALL} SSL certificate . . .")
            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} This might take a while, hang tight")

            RESPONSE = requests.get('https://crt.sh/', params=PARAMS, headers=HEADERS)
            STATUS_CODE = RESPONSE.status_code

            if STATUS_CODE != 200:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}crt.sh{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")

            else:
                SOUP = BeautifulSoup(RESPONSE.text, 'html.parser')
                TABLES = SOUP.find_all('table')

                for TABLE in TABLES:
                    for DOMAIN in TABLE.find_all('td'):
                        for DM in DOMAIN:
                            if TARGET_DOMAIN in DM and " " not in DM and DM and DM not in VALID_SUBDOMAINS:
                                    print((f"{Fore.CYAN}[+]{Style.RESET_ALL} found {Fore.BLUE}{DM}{Style.RESET_ALL} from the SSL certificate"))
                                    VALID_SUBDOMAINS.append(DM)

        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.MAGENTA}crt.sh{Style.RESET_ALL} isn't responding the way we want to, skipping . . .")

def SECURITYTRAILS_GET_SUBDOMAINS():
    print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} SecurityTrails API subdomain scan output for: {Fore.BLUE}{TARGET_DOMAIN}{Style.RESET_ALL}")
    ST = SecurityTrails(API_KEYS.securitytrails)
    try:
        ST.ping()
    except SecurityTrailsError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Invalid API key")
        exit()   

    SUBDOMAINS_ST = ST.domain_subdomains(TARGET_DOMAIN)
    for SUBDOMAIN in SUBDOMAINS_ST['subdomains']:
        RESULT_DOMAIN = f"{SUBDOMAIN.strip()}.{TARGET_DOMAIN}"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.BLUE}{RESULT_DOMAIN}{Style.RESET_ALL}")
        VALID_SUBDOMAINS.append(RESULT_DOMAIN)

def SUB_ENUM_THREAD(URL,SUB_ENUM_AGENT):
    global RUNNING_THREADS
    try:
        requests.get(URL, headers=SUB_ENUM_AGENT, timeout=5)

    except requests.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except ConnectionRefusedError:
        pass

    else:
        FINAL_URL = URL.replace("http://", "")       # (?) socket.gethostbyname doesn't like "http://"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.BLUE}{FINAL_URL}{Style.RESET_ALL} is a valid domain {' ' * 20}")
        VALID_SUBDOMAINS.append(FINAL_URL)
    RUNNING_THREADS -= 1

def SUB_ENUM():
    global RUNNING_THREADS
    RUNNING_THREADS = 0
    print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Checking common subdomains . . .")

    for SUBDOMAIN_COUNT, SUBDOMAIN in enumerate(SUBDOMAINS):
        print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Checking: {SUBDOMAIN}   {SUBDOMAIN_COUNT}/{len(SUBDOMAINS)}{' ' * 20}", end="\r")
        URL = f'http://{SUBDOMAIN}.{TARGET_DOMAIN}'      # Requests needs a valid HTTP(s) schema
        AGENT = random.choice(USER_AGENT_STRINGS)

        SUB_ENUM_AGENT = {

            'User-Agent': AGENT,
        }

        while RUNNING_THREADS >= GLOBAL_THREADS:
            time.sleep(0.5)
        threading.Thread(target=SUB_ENUM_THREAD, args=(URL,SUB_ENUM_AGENT,)).start()
        RUNNING_THREADS += 1
    while RUNNING_THREADS != 0:
        time.sleep(0.1)
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Scan done! Waiting for threads to exit...", end="\r")


def SUB_IP():
        print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Getting subdomain IP addresses . . .")

        for SUBDOMAIN in VALID_SUBDOMAINS:
            try:
                SUBDOMAIN_IP = socket.gethostbyname(SUBDOMAIN)
            except socket.gaierror:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Can't resolve {Fore.BLUE}{SUBDOMAIN}{Style.RESET_ALL}'s IP address")
            else:
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.BLUE}{SUBDOMAIN}{Style.RESET_ALL} has an IP address of {Fore.BLUE}{SUBDOMAIN_IP}{Style.RESET_ALL}")

                if SUBDOMAIN_IP in IP_ADDRESSES is not None:
                    pass
                else:
                    IP_ADDRESSES.append(SUBDOMAIN_IP)

def IS_CF_IP():

    for IP in IP_ADDRESSES:
            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Checking if {Fore.BLUE}{IP}{Style.RESET_ALL} is Cloudflare . . .")
            AGENT = random.choice(USER_AGENT_STRINGS)

            IS_CF_AGENT = {
                'User-Agent': AGENT
            }

            try:
                HEAD = requests.head(f"http://{IP}", headers=IS_CF_AGENT, timeout=5)
                HEADERS = HEAD.headers

                global IP_COUNTRY
                IP_COUNTRY = requests.get(f"http://ip-api.com/csv/{IP}?fields=country").text.strip()
                
                if 'CF-ray' in HEADERS is not None:

                    CLOUDFLARE = True

                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{IP}{Style.RESET_ALL} is Cloudflare")
                    RAY_ID = HEAD.headers['CF-ray']
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Ray-ID: {Fore.CYAN}{RAY_ID}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {IP_COUNTRY}")

                if 'CF-ray' not in HEADERS:
                    print(f"{Fore.GREEN}[!]{Style.RESET_ALL} {Fore.RED}{IP}{Style.RESET_ALL} is NOT cloudflare")

                    if IP in NOT_CLOUDFLARE is not None:
                        pass
                    else:
                        NOT_CLOUDFLARE.append(IP)
            
            except ConnectionError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Couldn't connect to {Fore.BLUE}{IP}{Style.RESET_ALL}, skipping . . .")   
            except requests.exceptions.ConnectTimeout:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.BLUE}{IP}{Style.RESET_ALL} timed out, skipping . . .")        
            except ConnectionRefusedError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.BLUE}{IP}{Style.RESET_ALL} refused, skipping . . .")
            except Exception:
                pass

def IS_AKAMAI():

    IS_AKAMAI = False

    for IP in NOT_CLOUDFLARE:
        print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Checking if {Fore.BLUE}{IP}{Style.RESET_ALL} is Akamai . . .")
        IS_AKAMAI_AGENT = random.choice(USER_AGENT_STRINGS)

        AKAMAI_USER_AGENT = {
            'User-Agent': IS_AKAMAI_AGENT
        }

        try:
            HEAD = requests.head(f"http://{IP}", headers=AKAMAI_USER_AGENT)
            HEADERS = HEAD.headers

            if 'x-akamai' in HEADERS is not None:

                IS_AKAMAI = True

                AKAMAI.append(IP)

                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{IP}{Style.RESET_ALL} is Akamai")
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {IP_COUNTRY}")
        
            if 'Server' in HEADERS is not None:
                
                SERVER = HEADERS['Server']

                if 'AkamaiGHost' in SERVER is not None:

                        IS_AKAMAI = True

                        AKAMAI.append(IP)

                        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.CYAN}{IP}{Style.RESET_ALL} Server detected as {Fore.GREEN}AkamaiGHost{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {IP_COUNTRY}")
            
            if IS_AKAMAI == False:

                print(f"{Fore.GREEN}[!]{Style.RESET_ALL} {Fore.RED}{IP}{Style.RESET_ALL} is NOT Akamai")
            
        except ConnectionError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Couldn't connect to {Fore.BLUE}{IP}{Style.RESET_ALL}, skipping . . .")
        except requests.exceptions.ConnectTimeout:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.BLUE}{IP}{Style.RESET_ALL} timed out, skipping . . .")
        except ConnectionRefusedError:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection to {Fore.BLUE}{IP}{Style.RESET_ALL} refused, skipping . . .") 
        except Exception:
            pass

def SHODAN_LOOKUP():

    if not NOT_CLOUDFLARE:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No leaked IP addresses found\n")
        sys.exit()

    try:
        API = shodan.Shodan(API_KEYS.shodan)

        for IP in NOT_CLOUDFLARE:
            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Shodan results for {Fore.BLUE}{IP}{Style.RESET_ALL}")

            RESULTS = API.host(IP)
            COUNTRY = RESULTS["country_name"]
            ISP = RESULTS['isp']
            HOSTNAME = RESULTS['hostnames']
            DOMAINS = RESULTS['domains']
            PORTS = RESULTS['ports']
            OS = RESULTS['os']

            NONE = True

            if ISP is not None:       
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} ISP: {Fore.BLUE}{ISP}{Style.RESET_ALL}")
            
            if COUNTRY is not None:
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Country: {Fore.BLUE}{COUNTRY}{Style.RESET_ALL}")
            
            if HOSTNAME is not None:
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Hostname(s): {Fore.BLUE}{HOSTNAME}{Style.RESET_ALL}")
            
            if DOMAINS is not None:
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Domain(s): {Fore.BLUE}{DOMAINS}{Style.RESET_ALL}")
            
            if PORTS is not None:
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Open port(s): {Fore.BLUE}{PORTS}{Style.RESET_ALL}")

            if OS is not None:
                NONE = False
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Operating system: {Fore.BLUE}{OS}{Style.RESET_ALL}")
            
            if NONE == True:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} No results for {Fore.BLUE}{IP}{Style.RESET_ALL}")

    except shodan.APIError as api_error:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No shodan API key supplied or the key is invalid")

def REMOVE_DUPLICATES():
    global VALID_SUBDOMAINS
    VALID_SUBDOMAINS_TEMP = []
    for SUBDOMAIN in VALID_SUBDOMAINS:
        if SUBDOMAIN not in VALID_SUBDOMAINS_TEMP:
            VALID_SUBDOMAINS_TEMP.append(SUBDOMAIN)
    VALID_SUBDOMAINS = VALID_SUBDOMAINS_TEMP
    #print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Duplicate subdomains removed")
def SEPARATOR():

    print(f"{Fore.YELLOW}={Style.RESET_ALL}" * 50)

def THREAD(FUNCTION):

    SEPARATOR()
    THREAD = threading.Thread(target=FUNCTION)
    THREAD.start()
    THREAD.join()
    REMOVE_DUPLICATES()

def MAIN():

        try:

            START_TIME = time.perf_counter()

            IS_POINTING_TO_CF()

            THREAD(DNSDUMPSTER)
            THREAD(CERTIFICATE_SEARCH)
            THREAD(SUB_ENUM)

            if API_KEYS.securitytrails != None:
                THREAD(SECURITYTRAILS_GET_SUBDOMAINS)

            THREAD(SUB_IP)
            THREAD(IS_CF_IP)
            THREAD(IS_AKAMAI)

            if API_KEYS.shodan:
                THREAD(SHODAN_LOOKUP)

            SEPARATOR()
            if ARGS.output != None:

                with open(ARGS.output, "w") as FILE:

                    for SUBDOMAIN in VALID_SUBDOMAINS:
                            FILE.write(f"VALID SUBDOMAIN: {SUBDOMAIN}\n")

                    for IP in NOT_CLOUDFLARE:
                            FILE.write(f"LEAKED IP: {IP}\n")
                    
                    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Saved results in {Fore.BLUE}{ARGS.output}{Style.RESET_ALL}")

            PERF = (time.perf_counter() - START_TIME)
            TOOK = int(PERF)

            print(f"{Fore.MAGENTA}[i]{Style.RESET_ALL} Finished in {TOOK} seconds")

        except KeyboardInterrupt:
            print("[i] Keyboard interrupt detected, exiting...")

        except Exception as errno:
            print(f"[-] Exception occured\n--> {errno}")

if __name__ == "__main__":
        MAIN()

##############################
#      End of program        #
##############################
