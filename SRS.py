import requests
import json
import urllib.request
from urllib.request import urlopen
from pprint import pprint
from termcolor import colored

print("\n")
print(colored("""

 ░▒▓███████▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  
                                         
                     
 \n""","green"))
print(colored("Coded By Praveen H P \n","blue"))

menu_option="""
[1]Ip History
[2]Ip Location Finder
[3]ping
[4]Traceroute
[5]Mac Address Lookup
[6]Phone No Information
[7]Free Email Lookup
[8]Get HTTP Headers
[9]Extract Link From Page
[10]Reverse Google Analytics Search
[11]Reverse IP Lookup
[12]Reverse MX Lookup
[13]Reverse NS Lookup
[14]Reverse DNS Lookup
[15]Port Scanner
[16]DNS Record Lookup Type A
[17]DNS Record Lookup Type MX
[18]DNS Propagation Checker
[19]Spam Database Lookup Test
[20]Host Header Injection
[21]Clickjacking
[22]Exit
"""

print(colored(menu_option,"red"))
key = "fa97f921dd05d7c2f45fab3bd4d130b4beabf231"

def run():

    try:
        choice = input(colored("Which option number : ","green"))
        
        if choice == '1':
            print("\n")
            print("[+] Ip History...")
            Domain = input("[+] Enter The Target Domain : ")
            print("IP history results for",Domain)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/iphistory/?domain="+Domain+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '2':
            print("\n")
            print("[+] Ip Location Finder...")
            Iplocation = input("[+] Enter The Target Ip Address : ")
            print("IP Location Finder results for",Iplocation)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "http://ip-api.com/json/"
            response = urllib.request.urlopen(api + Iplocation)
            data = response.read()
            value = json.loads(data)
            print("Status: " + value['status'])
            print("IP: " + value['query'])
            print("ISP: " + value['isp'])
            print("Country: " + value['country'])
            print("Country code: " + value['countryCode'])
            print("RegionName: " + value['regionName'])
            print("Region: " + value['region'])
            print("City: " + value['city'])
            print("Timezone: " + value['timezone'])
            print("PinCode: " + value['zip'])
            print("Org: " + value['org'])
            print("ASN: " + value['as'])

        elif choice == '3':
            print("\n")
            print("[+] Ping...")
            Ping = input("[+] Enter The Target Domain/Ip : ")
            print("Ping results for",Ping)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/ping/?host="+Ping+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '4':
            print("\n")
            print("[+] Traceroute...")
            Traceroute = input("[+] Enter The Target Domain : ")
            print("Traceroute results for",Traceroute)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/traceroute/?domain="+Traceroute+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '5':
            print("\n")
            print("[+] Mac Address Lookup...")
            mac = input("[+] Enter The Target Mac Address : ")
            print("Reverse DNS Lookup results for",mac)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/maclookup/?mac="+mac+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data) 

        elif choice =='6':
            print("\n")
            print("[+] Phone No Information...")
            Phone = input("[+] Enter The Target Phone No With Country Code : ")
            print("Phone No results for",Phone)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "http://apilayer.net/api/validate?access_key=cd3af5f7d1897dc1707c47d05c3759fd&number="+Phone+"&format=1"
            resp = requests.get(api)
            details = resp.json()
            print('')
            print("Number : " + details['number'])
            print("Localformat : " + details['local_format'])
            print("Internationalformat : " + details['international_format'])
            print("countryprefix : " + details['country_prefix'])
            print("Countrycode : " + details['country_code'])
            print("CountryName : " + details['country_name'])
            print("Location : " + details['location'])
            print("Carrier : " + details['carrier'])
            print("linetype : " + details['line_type'])

        elif choice == '7':
            print("\n")
            print("[+] Free Email Lookup...")
            Email = input("[+] Enter The Target Domain : ")
            print("Free Email Lookup results for",Email)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/freeemail/?domain="+Email+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '8':
            print("\n")
            print("[+] Get HTTP Headers...")
            http = input("[+] Enter The Target Domain : ")
            print("Get HTTP Headers results for",http)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/httpheaders/?domain="+http+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '9':
            print("\n")
            print("[+] Extraxt Links From Page...")
            Elink = input("[+] Enter The Target Domain : ")
            print("Extract Links From Page results for",Elink)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            response = requests.get("https://api.hackertarget.com/pagelinks/?q="+Elink+"")
            print(response.text)

        elif choice == '10':
            print("\n")
            print("[+] Reverse Google Analytics Search...")
            Rgas = input("[+] Enter The Target Domain/Id : ")
            print("Extract Links From Page results for",Rgas)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            response = requests.get("https://api.hackertarget.com/analyticslookup/?q="+Rgas+"")
            print(response.text)

        elif choice == '11':
            print("\n")
            print("[+] Reverse IP Lookup...")
            Ip = input("[+] Enter The Target Domain/IP : ")
            print("Reverse IP results for",Ip)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reverseip/?host="+Ip+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '12':
            print("\n")
            print("[+] Reverse MX Lookup...")
            Mailserver = input("[+] Enter The Target Mailserver(e.g. mail.google.com) : ")
            print("Reverse MX Lookup results for",Mailserver)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversemx/?mx="+Mailserver+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '13':
            print("\n")
            print("[+] Reverse NS Lookup...")
            Nameserver = input("[+] Enter The Target Nameserver(e.g. ns1.example.com) : ")
            print("Reverse NS Lookup results for",Nameserver)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversens/?ns="+Nameserver+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '14':
            print("\n")
            print("[+] Reverse DNS Lookup...")
            rdns = input("[+] Enter The Target IP : ")
            print("Reverse DNS Lookup results for",rdns)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversedns/?ip="+rdns+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '15':
            print("\n")
            print("[+] Port Scanner...")
            port = input("[+] Enter The Target Domain : ")
            print("Port Scanner results for",port)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/portscan/?host="+port+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '16':
            print("\n")
            print("[+] DNS Record Lookup Type A...")
            Atype = input("[+] Enter The Target Domain : ")
            print("DNS Record Lookup Type A results for",Atype)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/dnsrecord/?domain="+Atype+"&recordtype=A&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '17':
            print("\n")
            print("[+] DNS Record Lookup Type MX...")
            Mxtype = input("[+] Enter The Target Domain : ")
            print("DNS Record Lookup Type MX results for",Mxtype)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/dnsrecord/?domain="+Mxtype+"&recordtype=MX&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '18':
            print("\n")
            print("[+] DNS Propagation Checker...")
            Dns = input("[+] Enter The Target Domain : ")
            print("DNS Propagation Checker results for",Dns)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/propagation/?domain="+Dns+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice == '19':
            print("\n")
            print("[+] Spam Database Lookup Test...")
            Spam = input("[+] Enter The Target Ip : ")
            print("Spam Database Lookup Test results for",Spam)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/spamdblookup/?ip="+Spam+"&apikey="+key+"&output=json"
            user_data = requests.get(api).json()
            pprint(user_data)

        elif choice =='20':
            print("\n")
            print("[+] Host Header Injection...")
            url = input("Enter the Full URL with Http/Https : ")
            print("Host Header Injection Results for",url)
            print("--------------------------------------------------------------------------------------")
            print("\n")
            headers = {'url': 'http://evil.com'}
            response = requests.get(url, headers=headers)
            if 'evil.com' in response.headers:
                print("Vulnerable to Host Header Injection")
            else:
                print("Not Vulnerable to Host header injection")

        elif choice =='21':
            print("\n")
            print("[+] ClickJacking Attack...")
            url = input("Enter the Full url with Http/Https : ")
            print("ClickJacking Results for",url)
            print("--------------------------------------------------------------------------------------")
            print("\n")
            data = urlopen(url)
            headers = data.info()
            if not "X-Frame-Options" in headers:
                print("Website is vulnerable to ClickJacking")
            else:
                print("Website is not Vulnerable to ClickJacking")

        elif choice =='23':
            exit()

    except KeyboardInterrupt:
        print("\nAborted!")
        quit()
    except:
        print("Invalid Option !\n")
        return run()
run()

        