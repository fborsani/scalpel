import struct
import dns
from dns import resolver
from dns.exception import DNSException
import socket, ssl, OpenSSL
from ssl import SSLError
from OpenSSL import crypto
from bs4 import BeautifulSoup, Comment
from urllib3 import PoolManager
import requests
from requests.adapters import HTTPAdapter
import time, random, string, re
import os, ctypes, platform, concurrent
import argparse
import subprocess
from subprocess import TimeoutExpired
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
from colorama import Fore, Back, Style, init as coloramaInit

class Environment():
    def __init__(self):
        termSize = os.get_terminal_size()
        self.termWidth = None
        self.termHeight = None
    
        if termSize:
            self.termWidth = termSize.columns
            self.termHeight = termSize.lines
    
        self.os = platform.system()
        self.isWindows = self.os == "Windows"
        self.isLinux = self.os == "Linux"

        self.user = None
        self.isUserAdmin = False

        if self.isLinux:
            self.user = os.geteuid()
            self.isUserAdmin = self.user == 0

        elif self.isWindows:
            self.user = os.getenv('username')
            self.isUserAdmin = ctypes.windll.shell32.IsUserAnAdmin() == 1


class Settings():
    DEFAULT_DNS_SERVER = ["8.8.8.8"]
    DEFAULT_DNS_RECORDS = ["A","AAAA","CNAME","PTR","MX","SOA","TXT"]

    DEFAULT_TRACE_PORT = 33434
    DEFAULT_TRACE_TTL = 30
    DEFAULT_TRACE_TIMEOUT = 5

    DEFAULT_DORKS_TLD = "com"

    SEPARATOR = ","
    DEFAULT_OPERATIONS=["whois", "dns", "ssl", "http", "web"]
    DEFAULT_THREADS = 4
    DEFAULT_TIMEOUT = 5

    def __init__(self, appName:str=None, args:list=None):
        parser = argparse.ArgumentParser(prog=appName, description="Perform enumeration against a website using various techniques")
        parser.add_argument("url")
        parser.add_argument("-a", type=str, help="Specify the modules to run")
        parser.add_argument("-o", type=str, help="Path to output file")
        parser.add_argument("-q", action="store_true", help="Skip printing banner")
        parser.add_argument("--whois-server", type=str, help="WHOIS server to use")
        parser.add_argument("-H", type=str, action="append", nargs="+", help="specify one or more HTTP headers in the format <name>:<value>")
        parser.add_argument("-C", type=str, action="append", nargs="+", help="specify one or more cookies in the format <name>=<value>")
        parser.add_argument("-t", type=int, help="Request timeout")
        parser.add_argument("--threads",type=int, help="Max number of threads in bruteforce tasks")
        parser.add_argument("-v", action="store_true", help="Print additional information")
        parser.add_argument("--whois-server-file", type=str, help="WHOIS file to import. File must contain the domain and the server separated by space")
        parser.add_argument("--whois-get-servers", type=str, help="Download and save a list of whois servers to the specified file")
        parser.add_argument("--dns-server", type=str, help="DNS server to use")
        parser.add_argument("--dns-records", type=str, help="DNS records to query. Accepts multiple values separated by a comma")
        parser.add_argument("--trace-port", type=int, help="port to use for tracing")
        parser.add_argument("--trace-ttl", type=int, help="max number of hops")
        parser.add_argument("--trace-timeout", type=int, help="Timeout in seconds")
        parser.add_argument("--trace-show-gateway", action="store_true", help="display local gateway in traceoute")
        parser.add_argument("--ssl-use-os-library", action="store_true", help="use the system openssl library instead of the one packaged in python")
        parser.add_argument("--dorks-file", type=str, help="File containing google dorks to use")
        parser.add_argument("--dorks-tld", type=str, help="specify the google TLD to query i.e. com, co.in, jp...")
        parser.add_argument("--brute-file", type=str, help="dictionary file for url bruteforcing")
        parser.add_argument("--brute-include-codes", type=str, help="HTTP codes to include in results")
        parser.add_argument("--brute-print-404", action="store_true", help="Print requests that match the website default 404 page")
        args = vars(parser.parse_args(args))

        #------GENERAL PARAMS------
        self.operations = self._parseInput(args, "a", self.DEFAULT_OPERATIONS, self.SEPARATOR)
        self.outputFile = self._parseInput(args, "o")
        self.threads = self._parseInput(args, "threads", self.DEFAULT_THREADS)
        self.quiet = args["q"]
        self.verbose = args["v"]

        #------REQUESTS PARAMS------
        self.url, self.domain, self.domainSimple, self.port, self.method = RequestsUtility.parseUrl(args["url"])
        self.headers = self._parseMultiValueParam(args["H"],":")
        self.cookies = self._parseMultiValueParam(args["C"],"=")
        self.timeout = self._parseInput(args, "t", self.DEFAULT_TIMEOUT)

        #------WHOIS PARAMS------
        self.whoisServer = None
        self.whoisFromFile = None
        self.whoisGetRemoteFile = None

        if args["whois_server"]:
            self.whoisServer = args["whois_server"]
        elif args["whois_server_file"]:
            self.whoisFromFile = args["whois_server_file"]
        elif args["whois_get_servers"]:
            self.whoisGetRemoteFile = args["whois_get_servers"]

        #-----DNS PARAMS------
        self.dnsServer = self._parseInput(args, "dns_server", self.DEFAULT_DNS_SERVER, self.SEPARATOR)
        self.dnsRecords = self._parseInput(args, "dns_records", self.DEFAULT_DNS_RECORDS, self.SEPARATOR)

        #-----TRACE PARAMS------
        self.tracePort = self._parseInput(args, "trace_port", self.DEFAULT_TRACE_PORT)
        self.traceTtl = self._parseInput(args, "trace_ttl", self.DEFAULT_TRACE_TTL)
        self.traceTimeout = self._parseInput(args, "trace_timeout", self.DEFAULT_TRACE_TIMEOUT)
        self.traceShowGateway = args["trace_show_gateway"]

        #-----SSL PARAMS------
        self.useOsLibrary = args["ssl_use_os_library"]

        #-----DORKS PARAMS------
        self.dorksFile = self._parseInput(args, "dorks_file")
        self.dorksTld = self._parseInput(args, "dorks_tld", self.DEFAULT_DORKS_TLD)

        #-----BRUTEFORCE PARAMS------
        self.bruteFile = self._parseInput(args, "brute_file")
        self.bruteIncludedHttpCodes = self._parseInput(args, "brute_include_codes")
        self.brutePrint404 = args["brute_print_404"]

    def _parseInput(self, args, key:str, altValue:str=None, sep:str=None):
        if args[key]:
            if sep:
                return args[key].split(sep)
            return args[key]
        else:
            return altValue
        
    def _parseMultiValueParam(self, input:list, sep:str=None, altValue:str=None):
        dict = {}
        if input:
            for subList in input:
                for entry in subList:
                    if sep and sep in entry:
                        items = entry.split(sep,1)
                        dict[items[0].strip()] = items[1].strip()
            return dict
        return altValue
        

class OutputWriter():
    class msgType(Enum):
        DEFAULT = (Fore.GREEN,"",""),
        BANNER = (Fore.YELLOW, Back.GREEN, Style.BRIGHT),
        ARGNAME = (Fore.GREEN, "", Style.BRIGHT),
        INFO = (Fore.BLUE,"",""),
        SUCCESS = (Fore.GREEN, "", ""),
        WARN = (Fore.YELLOW,"",""),
        ERROR = (Fore.RED,"", ""),
        END = Style.RESET_ALL

    PLACEHOLDER_NONE = "None"
    PLACEHOLDER_TRUE = "Yes"
    PLACEHOLDER_FALSE = "No"

    INDENT = "    "

    TUPLE_ARG_NAME_PADDING = 32
    TUPLE_ARG_VALUE_PADDING = 6
    BANNER_PADDING = 10
    
    BANNER_MIN_TERM_SIZE=120

    def __init__(self):
        self.rowSize = 120
        self.outputFile = None
        coloramaInit()

    @staticmethod
    def printAppBanner():
        banner = '''
                                           ..##..
                                           ..###..
                                            .####..
                                             .####..
                                              .####..
                                               .#####.
                                                .#####.
                                                 .#####.
                                                  .#####.
   ad#######ba        ,ad####ba,              db   .#####.   ##              ########ba     ###########   ##
  d#"       "#b      d#"'    '"#b            d##b   .#####.  ##              ##      "#b    ##            ##
 Y#           b     d#'                     d#''#b   .#####. ##              ##        #P   ##            ##
 Y#,               d#'                     d#'  '#b   ####-. ##              ##        #P   ##            ##
  Y#,              d#                     d#      #b   ###=- ##              ##      "#b    ##            ##
   'Y#aaaaaaa,     ##                    d#YaaaaaaY#b   ##=--.#              ##aaaaaa#P'    #######       ##
    '"""""""#b,    ##                   d#'"""""""''#b   #==--.              ##""""""'      ##"""""       ##
            '#b    Y#                  d#           '#b   .----.             ##             ##            ##
              #b   Y#,                d#'            '#b   .-=---.           ##             ##            ##
  y          ,#P    Y#,              d#'              '#b   .-=----.         ##             ##            ##
  Y#"       ,#P      Y#a.    .a#P   d#'                '#b   .-=----.        ##             ##            ##
   "Y#######P"        '"Y####Y"'   d#'                  '#b  #.-=----.#####  ##             ###########   #############
                                                               .-=---.
                                                                .-=---.
                                                                 .----.
                                                                  .---.
                                                                   .--.
                                                                    .-.
                                                                     ..
                                                                      .
            '''
    
        termWidth = Environment().termWidth
    
        if termWidth and termWidth >= OutputWriter.BANNER_MIN_TERM_SIZE:
            print(OutputWriter.msgType.DEFAULT.value[0][0] + banner + OutputWriter.msgType.END.value)
    
    @staticmethod
    def printInfoText(input:str, module=None):
        msg = input
        if module and module.bannerName:
            msg = f"{module.bannerName}: {input}"

        print(OutputWriter.msgType.INFO.value[0][0] + msg + OutputWriter.msgType.END.value + "\n")

    def setOutputFile(self, path:str):
        self.outputFile = open(path, "w")

    def closeResources(self):
        if self.outputFile:
            self.outputFile.close()

    def writeToFile(self, input:str):
        if self.outputFile:
            self.outputFile.write(input)

    def getErrorString(self, input:str):
        return self.applyStyle(input, OutputWriter.msgType.ERROR)

    def applyStyle(self, input:str, type=msgType.DEFAULT, indent:int=0):

        if isinstance (input, bytes):
            try:
                input = input.decode()
            except:
                input = str(input)
        
        input.strip()
        addNewline = not input.endswith("\n")

        if indent > 0:
            if input.count("\n") > 0:
                input = self.INDENT*indent + input.replace("\n","\n"+self.INDENT*indent)
            else:
                input = self.INDENT*indent + input

        self.writeToFile(input+"\n" if addNewline else input)

        fore, back, style = type.value[0]
        return fore + back + style + input + OutputWriter.msgType.END.value + ("\n" if addNewline else "")
    
    def applyStyleTuple(self, input:tuple, indent:int):
        argName, argValue = input
        strValue = self._toStr(argValue)
        plainString = (
            f"{self.INDENT*indent}"
            f"{argName:<{self.TUPLE_ARG_NAME_PADDING}s}"
            f"{strValue:<{self.TUPLE_ARG_VALUE_PADDING}s}\n"
            )
        
        foreArg, backArg, styleArg = OutputWriter.msgType.ARGNAME.value[0]
        foreVal, backVal, styleVal = OutputWriter.msgType.DEFAULT.value[0]

        styledString = (
            f"{self.INDENT*indent}"
            f"{foreArg}{backArg}{styleArg}"
            f"{argName:<{self.TUPLE_ARG_NAME_PADDING}s}"
            f"{OutputWriter.msgType.END.value}"
            f"{foreVal}{backVal}{styleVal}"
            f"{strValue:<{self.TUPLE_ARG_VALUE_PADDING}s}"
            f"{OutputWriter.msgType.END.value}"
            f"\n"
            )
        
        self.writeToFile(plainString)
        return styledString

    def getFormattedString(self, input):
        return "{}\n".format(self.inputParser(input,0))

    def inputParser(self, input, indent:int=0, extraNewline=False):
        strOut = ""
        if input is None:
            strOut = self.applyStyle(OutputWriter.PLACEHOLDER_NONE, OutputWriter.msgType.ERROR, indent)
        
        elif isinstance(input, bool):
            value = OutputWriter.PLACEHOLDER_FALSE
            style = OutputWriter.msgType.ERROR
            
            if input == True:
                value = OutputWriter.PLACEHOLDER_TRUE
                style = OutputWriter.msgType.SUCCESS
            strOut = self.applyStyle(value, style, indent)
        
        elif isinstance(input, (str, bytes)):
            strOut = self.applyStyle(input, indent=indent)

        elif isinstance(input, dict):
            keys = input.keys()
            if len(keys) > 0:
                lastIdx = len(keys)-1
                for idx, key in enumerate(keys):
                    strOut += self.applyStyle(key, OutputWriter.msgType.ARGNAME, indent) + self.inputParser(input[key], indent+1, idx != lastIdx)
            else:
                strOut = self.inputParser(None,indent)

        elif isinstance(input, list):
            if len(input) > 0:
                lastIdx = len(input)-1
                for idx,r in enumerate(input):
                    if isinstance(r, tuple):
                        strOut += self.applyStyleTuple(r, indent)
                    else:
                        strOut += self.inputParser(r, indent)
                        if isinstance(r, dict):
                            strOut += "\n\n\n"
            else:
                strOut = self.inputParser(None,indent)
        else:
            strOut = self.applyStyle(str(input),indent=indent)

        if extraNewline:
            return strOut+"\n"
        else:
            return strOut
    
    def getBanner(self, input):
        if isinstance(input, EnumComponent):
            value = input.bannerName
        else:
            value = str(input)
        
        banner = f"{'='*self.BANNER_PADDING} {value} {'='*self.BANNER_PADDING}"
        return self.applyStyle(banner,OutputWriter.msgType.BANNER)
    
    def _toStr(self, input) -> str:
        if input == None:
            return self.PLACEHOLDER_NONE
        if input == True:
            return self.PLACEHOLDER_TRUE
        if input == False:
            return self.PLACEHOLDER_FALSE
        return input


#-------ABSTRACT CLASS AND CUSTOM EXCEPTION--------


class EnumComponent(ABC):
    def __init__(self, bannerName:str, settings:Settings):
        self.settings = settings
        self.bannerName = bannerName
    
    @abstractmethod
    def getResult(self):
        pass


class EnumException(Exception):
    def __init__(self, module:EnumComponent, message:str, originalException:Exception=None):
        self.message = message
        self.module = module
        self.fullErrStr = f"{module.bannerName}: {message}" if module else self.message
        super().__init__(originalException)


#-----------------UTILITY CLASSES-----------------

class RequestsUtility():
    SECURE_SCHEME="https"
    DEFAULT_PORT=443

    DEFAULT_DNS = ["8.8.8.8","8.8.4.4"]

    RESERVED_PORT = 1024

    METHODS={
        "get":requests.get,
        "post": requests.post,
        "options": requests.options,
        "put": requests.put,
        "delete": requests.delete,
        "patch": requests.patch      
    }

    HTTP_CODES = {
        200: "OK",
        201: "OK - resource created",
        204: "OK - empty response",
        301: "Permanent redirect",
        302: "Temporary redirerct",
        400: "Malformed request",
        401: "Authentication required",
        403: "Access forbidden",
        404: "Not found",
        405: "Method not allowed",
        429: "Too many requests",
        500: "Server failure",
        501: "Method not implemented",
        502: "Gateway error - upstream server failure",
        503: "Server unavailable",
        504: "Gateway error - upstream server timeout",
        505: "HTTP version not supported"
    }
    
    def __init__(self, caller:EnumComponent,
                 settings:Settings=None,
                 session:bool=False,
                 timeout:int=10,
                 followRedirects:bool=True,
                 headers:dict=None,
                 cookies:dict=None):
        
        if settings:
            self.timeout = settings.timeout
            self.threads = settings.threads
            self.followRedirects = True
            self.cookies = settings.cookies
            self.headers = settings.headers
        else:
            self.timeout = timeout
            self.followRedirects = followRedirects
            self.cookies = cookies
            self.headers = headers

        self.session = requests.session() if session else None

        self.caller = caller

    def httpRequest(self, url:str, method:str="get", params:dict=None):
        try:
            if self.session:
                if method == "get":
                    return self.session.get(url,
                                        timeout=self.timeout,
                                        allow_redirects=self.followRedirects,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        params=params) 
                if method == "post":
                    return self.session.post(url,
                                        timeout=self.timeout,
                                        allow_redirects=self.followRedirects,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        params=params) 

            return self.METHODS[method](url,
                                        timeout=self.timeout,
                                        allow_redirects=self.followRedirects,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        params=params) 
        except requests.ConnectionError as e:
            raise EnumException(self.caller, f"Unable to connect to {url}", e)
        except requests.ConnectTimeout as e:
            raise EnumException(self.caller, f"Request to {url} has timed out", e)

    def getSessionCookies(self):
        if self.session:
            return self.session.cookies
        return None

    def createSocket(self, proto:str=None):
        if not Environment().isUserAdmin:
            raise EnumException(self.caller, f"Administrative privileges are required to open sockets", None)
        
        if proto == "icmp":
            return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        if proto == "udp":
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def sockRequest(self, url:str, port:int, body:str=None):       
        sc = self.createSocket()

        try:      
            sc.settimeout(self.timeout)
            sc.connect((url, port))
            sc.send(body.encode())
            return sc
        except socket.error as e:
            sc.close()
            raise EnumException(self.caller, f"Unable to connect to {url}:{port}", e)

    def sockSendbytes(self, sock, body:bytes, url:str, port:int, timeout:int=None):        
        timeout = timeout if timeout else self.timeout
        sock.settimeout(timeout)
        try:
            sock.sendto(body,(url, port))
            return sock
        except socket.error as e:
            raise EnumException(self.caller, f"Unable to connect to {url}:{port}", e)
  
    def sockReceive(self, sock, size: int= 512):
        try:
            sock.settimeout(self.timeout)
            return sock.recvfrom(size)
        except socket.error:
            return None          

    @staticmethod
    def dnsReverseLookup(ip:str, server:list=None):
        resolver = dns.resolver.Resolver()
        addr=dns.reversename.from_address(ip).to_text()
        result = RequestsUtility.dnsSingleQuery(addr, "PTR", server)
        return result[0] if result else addr
    
    @staticmethod
    def dnsSingleQuery(target:str,record:str, server:list=None):
        try:
            resolver = dns.resolver.Resolver()
            if server:
                resolver.nameservers = server
            result = resolver.resolve(target,record)
            return [i.to_text() for i in result]
        except DNSException:
            return None

    @staticmethod
    def formatResponseCode(response):
        if isinstance(response, requests.Response):
            code = response.status_code
        else:
            code = int(response)

        if code in RequestsUtility.HTTP_CODES.keys():
            return f"{code} ({RequestsUtility.HTTP_CODES[code]})"
        return code

    @staticmethod
    def parseUrl(url:str):
        url = url.strip().lower()

        idxParams = url.find("?")
        urlNoParams = url[:idxParams] if idxParams > 0 else url 
        
        idxMethod = urlNoParams.find("://")
        urlNoMethod = urlNoParams[idxMethod+3:] if idxMethod > 0 else urlNoParams

        idxPort = urlNoMethod.rfind(":")

        domain = urlNoMethod[:idxPort] if idxPort > 0 else urlNoMethod
        domainSimple = domain

        if domain.startswith("www."):
            domainSimple = domain[4:]

        if idxMethod < 0:
            urlNoParams = RequestsUtility.SECURE_SCHEME + "://" + urlNoParams

        return (
            urlNoParams,
            domain,
            domainSimple,
            int(urlNoMethod[idxPort+1:]) if idxPort > -1 else RequestsUtility.DEFAULT_PORT,
            urlNoParams[:idxMethod] if idxMethod > -1 else RequestsUtility.SECURE_SCHEME
        )


class FileUtility():
    def __init__(self, caller:EnumComponent, split:bool=False, separator:str=None, commentSymbol:str=None):
        self.commentSymbol = commentSymbol
        self.split = split
        self.sep = separator if split and separator else None
        self.caller = caller

    def readFile(self, path:str):
        rows = []
        try:
            with open(path, 'r') as f:
                for line in f:
                    if not self.commentSymbol or (self.commentSymbol and not line.startswith(self.commentSymbol)):
                        values = line if self.split else line
                        if self.split:
                            rows.append([l.strip() for l in line.split(self.sep)])
                        else:
                            rows.append(line.strip())
            return rows
        except OSError as e:
            raise EnumException(self.caller, f"Failed to open file {path} with error {e.errno} - {e.strerror}", e)

    def createFromRequest(self, req:RequestsUtility, url:str, dest:str):
        try:
            response = req.httpRequest(url)
            with open(dest, "wb") as f:
                f.write(response.content)
        except OSError as e:
            raise EnumException(self.caller, f"Failed to write to file {dest} with error {e.errno} - {e.strerror}", e)
        

#-----------------MODULES-----------------

class WhoisComponent(EnumComponent):
    FILE_COMMENT = ";"
    FILE_URL = "https://www.nirsoft.net/whois-servers.txt"
    
    def __init__(self, settings:Settings):
        self.domain = settings.domainSimple
        self.server = settings.whoisServer
        self.filePath = settings.whoisFromFile
        self.remoteFileDest = settings.whoisGetRemoteFile
        self.verbose = settings.verbose

        self.req = RequestsUtility(self, settings)
        self.fileUtil = FileUtility(self, True, commentSymbol= WhoisComponent.FILE_COMMENT)
        super().__init__("WHOIS RECORDS",settings)

    def getResult(self): 
        if self.server:
            return self._whois(self.server)
        if self.filePath:
            servers = self.fileUtil.readFile(self.filePath)
            return self._whois(self._pickServer(servers))
        if self.remoteFileDest:
            self.fileUtil.createFromRequest(self.req, WhoisComponent.FILE_URL, self.remoteFileDest)
            servers = self.fileUtil.readFile(self.remoteFileDest)
            return self._whois(self._pickServer(servers))
        return self._whoisIana()
        
    def _pickServer(self, servers:list):
        domain = self.domain[self.domain.find(".")+1:]
        for server in servers:
            ext, whoisServer = server
            if ext == domain:
                return whoisServer
        return None

    def _whoisIana(self):
        request = f"https://www.iana.org/whois?q={self.domain}"

        if self.verbose:
            OutputWriter.printInfoText(f"Sending HTTP request to: {request}", self)

        response = self.req.httpRequest(request)

        if response.status_code == 200 and response.text:
            text = response.text
            result = text[text.find("<pre>")+5:text.rfind("</pre>")]
            if result.strip():
                return result
            else:
                return "Empty response from IANA whois page. Consider sending a request directly to a WHOIS server using --whois-server or --whois-server-file"
        else:
            return f"Connection failed. Response code: {self.req.formatResponseCode(response)}"
    
    def _whois(self,server):
        if self.verbose:
            OutputWriter.printInfoText(f"Contacting whois server {server}", self)

        query = f'{self.domain}\r\n'
        connection = self.req.sockRequest(server,43,query)
        response = ""

        while len(response) < 10000:
            chunk = connection.recv(100).decode()
            if (chunk == ''):
                break
            response = response + chunk

        connection.close()
   
        return response


class DnsComponent(EnumComponent):
    def __init__(self, settings:Settings):
        super().__init__("DNS RECORDS", settings)
        self.domain = settings.domain
        self.records = settings.dnsRecords
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = settings.dnsServer
        
    def reverse(self,address):
         addr=dns.reversename.from_address(address).to_text()
         result = self.dnsSingleQuery(addr,"PTR")
         return result[0] if result else addr

    def getResult(self):
        results = {}
        for r in self.records:
            try:
                result = self.resolver.resolve(self.domain,r)
                record = [i.to_text() for i in result]
            except DNSException:
                 record = None
            results[r] = record
        return results


class TraceComponent(EnumComponent):
    def __init__(self, settings:Settings):
        super().__init__("TRACEROUTE", settings)
        self.domain = settings.domain
        self.destPort = settings.tracePort
        self.port = settings.port
        self.ttl = settings.traceTtl
        self.timeout = settings.timeout
        self.showGateway = settings.traceShowGateway
        self.verbose = settings.verbose

        self.req = RequestsUtility(self)

    def getResult(self):
        destAddress = self.req.dnsSingleQuery(self.domain,"A")
        if not destAddress or not destAddress[0]:
            raise EnumException(self, "Unable to resolve destination")
        
        destAddress = destAddress[0]
        traceResult = self.trace(destAddress) 
        
        return {
            "Destination address": destAddress,
            "Success": traceResult["success"],
            "Note": traceResult["note"],
            "Traceroute": self.printTable(traceResult["hops"], ["Hop","Address","Domain","Time (ms)"], [6,20,40,12])
        }

    def trace(self, destAddress):
        currAddress = ""
        gatewayAddr = None
        counter = 0
        hops = []
        success = False
        note = None
        lastBeforeError = None
        totalTime = 0

        for hop in range(1, self.ttl+1):
            rec = self.req.createSocket("icmp")
            snd = self.req.createSocket("udp")
            rec.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))
            snd.setsockopt(socket.SOL_IP, socket.IP_TTL, hop)

            if self.verbose:
                OutputWriter.printInfoText(f"Current hop: {hop}/{self.ttl+1}", self)

            if currAddress != destAddress:
                self.req.sockSendbytes(snd, b"", destAddress, self.destPort)
                sendTime = time.perf_counter_ns()
                response = self.req.sockReceive(rec)
                if response:
                    _, currAddress = response
                    currAddress = currAddress[0]
                    hostname = self.req.dnsReverseLookup(currAddress)
                    recTime = time.perf_counter_ns()
                    elapsed = (recTime - sendTime) / 1e6
                    totalTime += elapsed
                else:
                    lastBeforeError = currAddress
                    currAddress = None
                    elapsed = None
                    hostname = None
                if self.showGateway or not (self.showGateway or gatewayAddr == hostname):
                    counter += 1
                    hops.append((str(counter),currAddress,hostname,f"{elapsed:.2f}" if elapsed else None))
                    if not gatewayAddr:
                        gatewayAddr = hostname
                snd.close()
                rec.close()
            else:
                success = True
                note = f"Destination host reached in {hop} hops. The trip lasted {totalTime/1000:.2f} seconds"
                
                #close last
                snd.close()
                rec.close()
                break    

        if not success:
            #the variable hostname records the last host visited. If populated it means the target was not reachable within the specified ttl.
            #If the variable is None it means the last request was not completed possibily due to a timeout or host unreachable error

            if hostname:
                note = f"Unable to reach target within {self.ttl} hops. Last destination reached: {hostname}"
            else:
                note = f"Destination unreachable due to request timeout. Request that failed: {lastBeforeError}"

        return {
            "success": success,
            "note": note,
            "hops": hops
        }

    def printTable(self, rows:list, cols:list, padding:list):
        sep = "|"
        nonePlaceholder = "*"
        tableLen = sum(padding) + len(sep) * (len(cols)+1)
        sepRow = "\n" + "-" * tableLen

        header = ""
        body = ""

        for c in range(0,len(cols)):
            header += sep  + f"{' '+cols[c]:<{padding[c]}s}"
        header += sep

        for r in rows:         
            row = sep
            for i in range(0,len(cols)):
                val = r[i] if r[i] else nonePlaceholder
                row += f"{' '+val:<{padding[i]}s}"+sep
            body += "\n" + row

        return header + sepRow + body + sepRow

class SSLComponent(EnumComponent):

    class SSLAdapter(HTTPAdapter):
        def __init__(self, sslVersion=None, **kwargs):
            self.sslVersion = sslVersion

            super(SSLComponent.SSLAdapter, self).__init__(**kwargs)

        def init_poolmanager(self, connections, maxsize, block=False, ):
            self.poolmanager = PoolManager(num_pools=connections,
                                        maxsize=maxsize,
                                        block=block,
                                        ssl_version=self.sslVersion)
            
    def __init__(self, settings:Settings):
        self.domain = settings.domain
        self.port = settings.port
        self.useOsLibrary = settings.useOsLibrary
        self.verbose = settings.verbose

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        
        super().__init__("CERTIFICATE AND SSL", settings)

    def getResult(self) -> dict:
        results = self._getSSLInfoExt() if self.useOsLibrary else self._getSSLInfo()
        return {
                "OpenSSL version": results["version"],
                "Secure protocols": results["proto"],
                "Supported ciphers": results["ciphers"],
                "Certificate details": self.certInfo()}
    
    def _getSSLInfo(self):
        proto = []
        ciphers = []

        #pickle fails when attempting to create a deep copy of SSLContext using copy.deepcopy
        #so I have to do it the manual way
        
        tmpCtx = ssl.create_default_context()
        tmpCtx.check_hostname = self.ctx.check_hostname
        tmpCtx.verify_mode = self.ctx.verify_mode

        formats = [
                    ("SSL 2.0", ssl.PROTOCOL_SSLv2 if hasattr(ssl,"PROTOCOL_SSLv2") else None),
                    ("SSL 3.0", ssl.PROTOCOL_SSLv3 if hasattr(ssl,"PROTOCOL_SSLv3") else None),
                    ("SSL Any", ssl.PROTOCOL_SSLv23 if hasattr(ssl,"PROTOCOL_SSLv23") else None),
                    ("TLS 1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl,"PROTOCOL_TLSv1") else None),
                    ("TLS 1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl,"PROTOCOL_TLSv1_1") else None),
                    ("TLS 1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl,"PROTOCOL_TLSv1_2") else None),
                    ("TLS 1.3", ssl.PROTOCOL_TLSv1_3 if hasattr(ssl,"PROTOCOL_TLSv1_3") else None)
                ]      
        
        if self.verbose:
            OutputWriter.printInfoText("Testing TLS/SSL protocols", self)

        for f in formats:
            fname, fvalue = f
            if fvalue:
                proto.append((fname, self._testSSL(fvalue)))
            else:
                proto.append((fname, "Unsupported client side"))

        if self.verbose:
            OutputWriter.printInfoText("Testing supported ciphers", self)

        for cipher in self.ctx.get_ciphers():
            try:
                tmpCtx.set_ciphers(cipher["name"])
                sc = socket.socket()
                sc.settimeout(5)

                with tmpCtx.wrap_socket(sc, server_hostname=self.domain) as sock:
                    sock.connect((self.domain, self.port))
                ciphers.append((cipher["name"], True))
            except SSLError:
                ciphers.append((cipher["name"], False))
            except socket.error as e:
                ciphers.append((cipher["name"], "Timeout"))

        return {
            "version": ssl.OPENSSL_VERSION,
            "proto": proto,
            "ciphers":ciphers
        }
    
    def _getSSLInfoExt(self):
        cmdRoot = "openssl"
        if platform.system() == "Windows":
            cmdRoot = "openssl.exe"

        try:
            version = subprocess.run([cmdRoot, "version"], capture_output = True).stdout.decode("UTF-8")
            ciphers = subprocess.run([cmdRoot, "ciphers", "ALL"], capture_output = True).stdout.decode("UTF-8").strip().split(":")
        except FileNotFoundError as e:
            raise EnumException(self, f"Unable to execute {cmdRoot}. Verify that the application is installed and that the folder in included in $PATH or BIN env variables", e)
        
        formats = [
                    ("SSLv2", "-ssl2"),
                    ("SSLv3", "-ssl3"),
                    ("TLSv1", "-tls1"),
                    ("TLSv1.1", "-tls1_1"),
                    ("TLSv1.2", "-tls1_2"),
                    ("TLSv1.3", "-tls1_3")
                ] 
        
        proto = []
        supportedCiphers = []
        
        for f in formats:
            fname, switch = f
            res, motivation = self._runSubprocess(cmdRoot, switch, False)
            if res:
                proto.append((fname, True))
            else:
                proto.append((fname, motivation if motivation else False))

        for c in ciphers:
            res, motivation = self._runSubprocess(cmdRoot, c, True)
            if res:
                supportedCiphers.append((c, True))
            else:
                supportedCiphers.append((c, motivation if motivation else False))

        return {
            "version": version,
            "proto": proto,
            "ciphers": supportedCiphers
        }
    
    def _runSubprocess(self,cmdRoot:str, input:str, isCipher:bool):
        try:
            if isCipher:
                cmd = subprocess.run(f"{cmdRoot} s_client -cipher {input} -connect {self.domain}:{self.port} </dev/null", shell=True, capture_output = True, timeout=5)
            else:
                cmd = subprocess.run(f"{cmdRoot} s_client -connect {self.domain}:{self.port} {input} </dev/null", shell=True, capture_output = True, timeout=5)
            
            if cmd.returncode == 0:
                return (True, None)
            else:
                err = cmd.stderr.decode("UTF-8").strip()
                if err.find("no protocols available") > -1 or err.find("unknown option") > -1 or err.find("no cipher match") > -1:
                    return (False, "Unsupported client side")
                else:
                    return (False, None)
        except TimeoutExpired:
            return (False, "Timeout")

   
    def certInfo(self):
        if self.verbose:
            OutputWriter.printInfoText("Retrieving certificate", self)

        with self.ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
            sock.connect((self.domain, self.port))
            certDER = sock.getpeercert(True)
            sock.close()
            certPEM = ssl.DER_cert_to_PEM_cert(certDER)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certPEM)
            pubKey = cert.get_pubkey()
            pubKeyStr= crypto.dump_publickey(crypto.FILETYPE_PEM,pubKey)
            ext = [cert.get_extension(i) for i in range(cert.get_extension_count())]
            return {
                "Ceritificate (PEM)": str(certPEM),
                "Valid": not cert.has_expired(),
                "Signature": cert.get_signature_algorithm(),
                "Fingerprint (SHA1)":cert.digest('sha1'),
                "Fingerprint (SHA256)":cert.digest('sha256'),
                "Serial Number": cert.get_serial_number(),
                "Version": cert.get_version(),
                "Public key": pubKeyStr,
                "Key format": self._formatKeyType(pubKey),
                "Key length": pubKey.bits(),
                "Subject": dict(cert.get_subject().get_components()),
                "Issuer": dict(cert.get_issuer().get_components()),
                "Valid from": datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%S%z").date().isoformat(),
                "Valid until": datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%S%z").date().isoformat(),
                "Extended information": {e.get_short_name().decode(): str(e).replace(", ","\n") for e in ext}
                }
        
    def _formatKeyType(self, pubKey):
        if pubKey.type() == crypto.TYPE_RSA:
            return "RSA"
        if pubKey.type() == crypto.TYPE_DSA:
            return "DSA"
        return pubKey.type()

    def _testSSL(self, sslVersion):
        session = requests.Session()
        session.mount("https://",SSLComponent.SSLAdapter(sslVersion))
        try:
            response = session.get("https://"+self.domain+":"+str(self.port))
            return True
        except:
            return False
    

class HTTPComponent(EnumComponent):
    def __init__(self, settings:Settings):
        self.url = settings.url
        self.req = RequestsUtility(self, settings, True)
        self.verbose = settings.verbose
        
        super().__init__("HTTP REQUESTS", settings)

    def getResult(self) -> dict:
        return {
            "HTTP info": self.getHTTPinfo(),
            "HTTP methods": self.testHTTPMethods()
        }

    def formatHTTPCode(self, code:int) -> str:
        try:
            return "{} ({})".format(code, self.httpCodeDictionary[code])
        except:
            return code

    def getHTTPinfo(self):
        response = self.req.httpRequest(self.url)
        options = self.req.httpRequest(self.url,"options")

        return {
            "Response code": self.req.formatResponseCode(response),
            "HTTP version": self._formatHttpVersion(response.raw.version),
            "Methods": options.headers["Allow"] if "Allow" in options.headers.keys() else None,
            "Headers": {k: [r.strip() for r in v.split(";") if r ] for k,v in response.headers.items()},
            "Cookies": {k.name: {
                            "Value": k.value,
                            "Comment": k.comment,
                            "Expires": datetime.fromtimestamp(k.expires) if k.expires else None,
                            "Domain": k.domain,
                            "Path": k.path,
                            "Secure": k.secure,
                            "HttpOnly": k.has_nonstandard_attr("HttpOnly"),
                            "SameSite": k.get_nonstandard_attr("SameSite") if k.has_nonstandard_attr("SameSite") else False
                        } for k in self.req.getSessionCookies()}
        }

    def _formatHttpVersion(self, version:int) -> str: 
        if version == 10:
            return "HTTP 1.0"
        if version == 11:
            return "HTTP 1.1"
        return "Not Found"
    
    def _parseRequest(self, req, trim:int=80):
        text = None
        if req.text:
            text = req.text[:trim]+"..."
        else:
            text = "EMPTY RESPONSE"

        return {
            "Code": self.req.formatResponseCode(req),
            "Response": text
        }
    
    def testHTTPMethods(self):
        if self.verbose:
            OutputWriter.printInfoText("Testing supported methods", self)

        results = {}

        for method in self.req.METHODS.keys():
            results[method.upper()] = self._parseRequest(self.req.httpRequest(self.url, method))
                                                               
        return results


class WebEnumComponent(EnumComponent):
    def __init__(self, settings:Settings):
        super().__init__("WEBSITE ENUMERATION", settings)
        self.url = settings.url
        self.req = RequestsUtility(self, settings)
        self.verbose = settings.verbose

    def getResult(self):
        response = self.req.httpRequest(self.url)
        soup = BeautifulSoup(response.text,"html.parser")
        robots = self.parseRobotsFile()

        if self.verbose:
            OutputWriter.printInfoText(f"Scanning included resources", self)
    
        return {
            "Title": soup.head.title.string,
            "Favicon": self._getFavicon(soup),
            "HTML params": soup.find("html").attrs,
            "Meta Tags": soup.find_all("meta"),
            "Included scripts": [script["src"].strip() for script in soup.find_all("script",{"src":True}) if script["src"].strip()],
            "Included stylesheets": [link["href"].strip() for link in soup.find_all("link", rel="stylesheet") if link["href"].strip()],
            "Robots entries": robots,
            "Sitemap entries": self.getSitemap(robots["Sitemap"]),
            "Page links": list(set([link["href"].strip() for link in soup.find_all("a",{"href":True}) if link["href"].strip()])),
            "Comments": [line.strip() for line in soup.find_all(string = lambda text: isinstance(text,Comment)) if line.strip()]
            
        }
         
    def _getFavicon(self, soup):
        url = self._getFaviconUrl(soup)
        if url:
            if url.startswith("/"):
                return self.url+url 
            return url
        return None
    
    def _getFaviconUrl(self, soup):
        val = soup.find("link", attrs={'rel': re.compile("^(shortcut icon|icon)$", re.I)})
        if val:
            return val["href"]
             
        val = soup.find("meta", property="og:image")["content"]
        if val:
            return val["content"]
        return val

    
    def getSitemap(self, extraUrls:list=None):
        if self.verbose:
            OutputWriter.printInfoText(f"Scanning sitemaps", self)
    
        urls = ["sitemap","wp-sitemap","sitemap_index","post-sitemap","page-sitemap","pages-sitemap","category-sitemap","tag-sitemap"]

        if extraUrls:
            for url in extraUrls:
                dict = self._sitemapReq(url)
                if dict["Location"]:
                    return dict

        for url in urls:
            fullUrl = "{}/{}".format(self.url,url)
            dict = self._sitemapReq(fullUrl)
            if dict["Location"]:
                return dict
        
        return None
    
    def parseRobotsFile(self):
        if self.verbose:
            OutputWriter.printInfoText(f"Scanning robots file", self)

        response = self.req.httpRequest(self.url+"/robots.txt")
        robots = None
        if(response.status_code == 200 and response.text):
            robots = [l for l in response.text.splitlines() if l.strip()]

            sitemaps = []
            allowedEntries = []
            disallowedEntries = []
            entries = {}
            currentUa = "*"

            for l in robots:
                if l.startswith("Sitemap"):
                    sitemaps.append(l[9:])
                if l.startswith("User-agent"):
                    newUa = l[12:]
                    if newUa != currentUa:
                        entries["User Agent: {}".format(currentUa)] = {
                            "Allowed entries": allowedEntries,
                            "Disallowed entries:": disallowedEntries
                            }
                        currentUa = newUa

                if l.startswith("Allow"):
                    allowedEntries.append(l[7:])

                if l.startswith("Disallow"):
                    disallowedEntries.append(l[10:])
            
            #Store last entries
            entries["User Agent: {}".format(currentUa)] = {
                "Allowed entries": allowedEntries,
                "Disallowed entries:": disallowedEntries  
            }

            return {
                "Sitemap": sitemaps,
                "Entries": entries
            }
        
        return None

    def _sitemapReq(self,url:str):
        headers = {"User-Agent": "Googlebot/2.1"}
        sitemapType = None
        sitemapEntries = None

        if url.endswith(".xml"):
            r  = self.req.httpRequest(url)
            if r.status_code == 200 and r.text:
                sitemapType = "xml"
                soup = BeautifulSoup(r.text, features="xml")
                sitemapTags = soup.find_all("sitemap")
                sitemapEntries = []
                
                if sitemapTags:
                    sitemapType = sitemapType + " (sitemap)"
                else:
                    sitemapType = sitemapType + " (urlset)"
                    sitemapTags = soup.find_all("urlset")
                
                for tag in sitemapTags:
                        for loc in tag.find_all("loc"):
                            sitemapEntries.append(loc.text)      
        else:
            r  = self.req.httpRequest(url,headers=headers)
            if r.status_code == 200 and r.text:
                sitemapType = "plaintext"
                sitemapEntries = r.text.splitlines()
        
        return {"Type": sitemapType, "Location": url, "Entries": sitemapEntries}


class DorksComponent(EnumComponent):
    DORK_SITE_RESTRICTION = "site:"
    HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"}
    REQUESTS_WAIT_TIME = 3

    EXCLUDED_DOMAINS = (
        "/",
        "#",
        "https://howwemakemoney.withgoogle.com",
        "https://policies.google.com",
        "https://support.google.com",
        "https://www.google.com/webhp",
        "https://maps.google.com/maps"
    )

    def __init__(self, settings:Settings):
        super().__init__("GOOGLE DORKS", settings)

        if not settings.dorksFile:
            raise EnumException(self, "A dictionary file must be specified with the flag --dorks-file", None)

        self.dorksFile = settings.dorksFile
        self.domain = settings.domain
        self.verbose = settings.verbose

        self.startPage = 0
        self.googleTLD = settings.dorksTld
        self.baseUrl = f"https://www.google.{self.googleTLD}/search"

        self.req = RequestsUtility(self, headers=DorksComponent.HEADERS)

    def getResult(self):
        dorks = FileUtility(self, split=True, separator=";;").readFile(self.dorksFile)
        results = []

        entries = len(dorks)
        counter = 1

        for dork in dorks:
            if self.verbose:
                OutputWriter.printInfoText(f"Testing entry {counter}/{entries}", self)
                counter += 1

            if len(dork) == 2:
                dorkStr, comment = dork
            else:
                dorkStr = dork[0]
                comment = None

            payload = f"{DorksComponent.DORK_SITE_RESTRICTION}{self.domain} {dorkStr}"
            params = {'q': payload, 'start': self.startPage * 10} 

            response = self.req.httpRequest(self.baseUrl, params=params)
            soup = BeautifulSoup(response.text,"html.parser")
            
            links = []
            for link in soup.find_all("a",{"href":True}):
                href = link["href"]
                if not href.startswith(DorksComponent.EXCLUDED_DOMAINS):
                    links.append(href)

            results.append(
                {
                    "Payload": dorkStr,
                    "Comment": comment,
                    "Url": response.url,
                    "Results": links
                }
            )

            time.sleep(DorksComponent.REQUESTS_WAIT_TIME)

        return results


class BruteforceModule(EnumComponent):
    RANDOM_URL_LENGTH = 20

    def __init__(self, settings: Settings):
        super().__init__("URL BRUTEFORCER", settings)

        if not settings.bruteFile:
            raise EnumException(self, "A dictionary file must be specified with the flag --brute-file", None)
        
        self.file = settings.bruteFile
        self.includedHttpCodes = settings.bruteIncludedHttpCodes
        self.printfourOhfourPages = settings.brutePrint404
        self.extensions = None
        self.domain = settings.url
        self.threads = settings.threads
        self.verbose = settings.verbose
        self.req = RequestsUtility(self, settings, followRedirects=True)

    def getResult(self):
        if self.verbose:
            OutputWriter.printInfoText(f"Detecting default 404 page", self)

        fourOhFour = self.getFourOhFourPage()
        excludeUrl = fourOhFour["Redirects"][-1] if fourOhFour else None
        excludeSize = fourOhFour["Response Size"] if fourOhFour else None

        urls = FileUtility(self).readFile(self.file)
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as threadPool:
            threads = {threadPool.submit(self._worker, url, excludeUrl, excludeSize): url for url in urls}
            completedCounter = 1
            urlCount = len(urls)

            for thread in concurrent.futures.as_completed(threads):
                if self.verbose:
                    OutputWriter.printInfoText(f"Threads completed: {completedCounter}/{urlCount}", self)
                    completedCounter += 1

                res = thread.result()
                if res:
                    results.append(thread.result())        
                else:
                    results.append((threads[thread], "No response"))

        return {
            "404 Generic Page": fourOhFour,
            "Results": results
        }
    
    def _worker(self, url, excludeUrl, excludeSize):
        if url.startswith("/"):
                url = url[1:]

        response = self.req.httpRequest(f"{self.domain}/{url}")
        responseCode = str(response.status_code)
        responseHistory = response.history
            
        if self.includedHttpCodes is None or (self.includedHttpCodes and responseCode in self.includedHttpCodes):
                lastUrl = responseHistory[-1].url if responseHistory else response.url
                responseSize = len(response.text)
                if (excludeUrl and lastUrl == excludeUrl) or (excludeSize and responseSize == excludeSize):
                    if self.printfourOhfourPages:
                        return (url, "404 Page")
                else:
                    return self._printResult(response, url)
    
    def _printResult(self, response, url):
        history = response.history

        if history:
            firstCode = history[0].status_code
            lastCode = history[-1].status_code
            lastUrl = history[-1].url
            return(url, f"{RequestsUtility.formatResponseCode(firstCode)} --> {RequestsUtility.formatResponseCode(lastCode)} [{lastUrl}]")
        else:
            return(url, RequestsUtility.formatResponseCode(response.status_code))

    def getFourOhFourPage(self):
        randomUrl = "".join(random.choice(string.ascii_letters) for i in range(0, self.RANDOM_URL_LENGTH))
        url = self.domain + "/" + randomUrl
        response = self.req.httpRequest(url)
        return{
            "Redirects": [u.url for u in response.history] if response.history else response.url,
            "Response Size": len(response.text) if response.text else 0
        }


class Scan():
    def __init__(self, appName:str=None, args:list=None):
        self.settings = Settings(appName, args)
        self.env = Environment()
        self.ow = OutputWriter()
        
        if self.settings.outputFile:
            self.ow.setOutputFile(self.settings.outputFile)
        
        self.enumComponents = {
            "whois": WhoisComponent,
            "dns": DnsComponent,
            "trace": TraceComponent,
            "ssl": SSLComponent,
            "http": HTTPComponent,
            "web": WebEnumComponent,
            "dorks": DorksComponent,
            "brute": BruteforceModule
        }

    def run(self):
        if not self.settings.quiet:
            self.ow.printAppBanner()

        operations = self.settings.operations if self.settings.operations else self.enumComponents.keys()
        for op in operations:
            try:
                if op in self.enumComponents.keys():
                    component = self.enumComponents[op](self.settings)
                    print(self.ow.getBanner(component))
                    print(self.ow.getFormattedString(component.getResult()))
                else:
                    print(self.ow.getErrorString(f"Unknown operation {op}. Skipped"))
            except EnumException as e:
                print(self.ow.getErrorString(e.fullErrStr))

        self.ow.closeResources()

if __name__ == '__main__':
    Scan().run()

        