# Readme
A pentest tool written for enumerating HTTP servers and websites. The script has been written in Python3 and packaged as a single file to make it easy to install or move during an assessment.
The program is built as a collection of modules that can be executed togheter or alone depending on the situation. The following list describes the available modules and their function:
* **whois**: perform a whois query to a given server or automatically guess the server to pick from a list depending on the site's domain. If no server or domain list are provided the whois records are retrieved by sending a GET request to the IANA website
* **dns**: retrieves DNS records for the specified domain. Allows to specify different record types (A, AAAA, MX, CNAME, PTR, SOA, TXT) and alternative server to query
* **trace**: generate a traceroute table similar to the one generated by the tracert command on windows
* **ssl**: dumps information about the site certificate and detects TLS/SSL version and ciphers supported by the server
* **http**: enumerates the following elements: http version, supported methods, response headers and cookies set
* **web**: retrieves webpage information: metatada in head, robots.txt entries, sitemaps, page title, favicon, included scripts, included stylesheets, page links and html comments
* **dorks**: run Google dorks queries against the target url. The module returns the generated Google query urls and a list of links as result. The payloads are retrieved from a file specified with the parameter --dorks-file
* **brute**: detect exposed pages and resources by executing queries for urls listed in a dictionary file. The payloads are retrieved from a file specified with the parameter --brute-file
## Usage
The script creates privileged sockets during its execution and requires root privileges to run.
By default the script can be invoked without parameters, this will trigger the execution of all modules
```
sudo python3 scalpel.py <host>
```
To specify the modules to run use the -a switch. It is possible to specify multiple modules by separating them with a comma.
In this case the modules will be executed one after another in the specified order
```
sudo python3 scalpel.py <host> -a whois
sudo python3 scalpel.py <host> -a whois,dns
```
The -o switch allows to specify an output file. Especially useful when launching several modules during the same scan because the output generated by the script can be diffcult to parse in console due to its size
```
sudo python3 scalpel.py <host> -a whois,dns -o <file>
```
## Installation
Download the python script and requirements.txt files
```
git clone https://github.com/fborsani/scalpel
```
Install the requirements
```
pip -r requirements.txt
```
