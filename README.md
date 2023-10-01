# Readme
A pentest tool written for enumerating HTTP servers and websites. The script has been written in Python 3 and packaged as a single file to make it easy to install or move during an assessment.
The program is built as a collection of modules that can be executed togheter or alone depending on the situation. The following list describes the available modules and their function:
* **whois**: perform a whois query to a given server or automatically pick a server from a list depending on the site's domain. If no server or domain list are provided the whois records are retrieved by sending a GET request to the IANA website
* **dns**: retrieves DNS records for the specified domain. Allows to specify different record types (A, AAAA, MX, CNAME, PTR, SOA, TXT) and alternative server to query
* **trace**: generate a traceroute table.
* **ssl**: dump information about the site certificate and detects TLS/SSL version and ciphers available
* **http**: enumerate the following elements: http version, supported methods, response headers and cookies set
* **web**: retrieves webpage information: metatada in head, robots.txt entries, sitemaps, page title, favicon, included scripts, included stylesheets, page links and comments
* **dorks**: run Google dorks queries against the target url. The module returns the generated Google query urls and a list of links as result. The payloads are retrieved from a file specified with the parameter --dorks-file
* **brute**: detect exposed pages and resources by executing queries for urls listed in a dictionary file specified with the parameter --brute-file
## Installation
To use the python script download the files and install the requirements using the commands below
```
wget https://raw.githubusercontent.com/fborsani/scalpel/main/scalpel/scalpel.py -O scalpel.py
wget https://raw.githubusercontent.com/fborsani/scalpel/main/requirements.txt -O requirements.txt
pip -r requirements.txt
```
The tool is also availabe as a standalone executable file for both Windows and Linux prepackaged with all the required libraries. The files are can be downloaded from the Releases tab
## Usage
By default the script can be invoked without parameters, this will trigger the execution of the following modules: whois, dns, ssl, http and web.
```
python scalpel.py <host>
```
To specify the modules to run use the -a switch. It is possible to specify multiple modules by separating them with a comma.
In this case the modules will be executed one after another in the specified order
```
python scalpel.py <host> -a whois
python scalpel.py <host> -a whois,dns
```
### Settings
Generic
```
-a                     operations to execute on target site
-o <file>              specify an output file
-q                     do not print the banner
-v                     print additional information
-H <header>:<value>    set a request header to be included in all requests. Can be specified multiple times
-C <cookie>=<value>    set a request cookie to be included in all requests. Can be specified multiple times
-t <seconds>           request timeout in seconds
--threads <count>      max threads to use
--dns-server <ip>      dns server for queries and host resolution
```
whois module
```
--whois-server <server>        specify a whois server to query
--whois-server-file  <file>    pick a suitable server to query from a list provided in the specified file. See dict/whois-server for a template
--whois-get-servers <file>     download and store a list of whois servers in the specified file.
```
dns module
```
--dns-records <record1,record2,...>      list of dns queries to perform (i.e. A,AAAA,MX,CNAME). By default will query for all entries
```
trace module
```
--trace-port <port>           local port to listen on for server response (by default is 33434)
--trace-ttl <number>          max number of hops between servers (by default 30)
--trace-show-gateway          print the local gateway everytime is printed. If not specified (default behaviour) the local gateway will be printed only once
```
ssl module
```
--ssl-use-os-library         use the system's openssl library (if available) instead of the one packaged with python
```
dorks module
```
--dorks-file <file>         dictionary file containing the google queries to run
--dorks-tld <tld>           google TLD to query (by default com) accepts values such as es, co.in, jp...
```
brute module
```
--brute-file <file>                    dictionary file containing the requests to run
--brute-include-codes <HTTP codes>     print the result only if the HTTP response code is in the specified list. Accepts multiple values separated by a comma
--brute-print-404                      print a 404 response even if it matches the webapp default 404 error page
```
## Manual Build
To build an executable file (exe or elf) fro source follow these steps:<br/>
Clone the project
```
git clone https://github.com/fborsani/scalpel
```
Install the script dependencies and extra libraries required to generate the exe file
```
pip -r requirements.txt
pip install pyinstaller, psutil
```
Navigate to the build folder and run pyinstaller
```
cd <path>/scalpel-main/build
pyinstaller scalpel.spec
```
The compiled executable file will be stored under <path>/scalpel-main/build/dist
