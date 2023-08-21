import dns
from dns import resolver
from dns.exception import DNSException
import socket
import ssl
from ssl import SSLError
import OpenSSL
from OpenSSL import crypto
from bs4 import BeautifulSoup
from urllib3 import PoolManager
import requests
from requests.adapters import HTTPAdapter
import time
import argparse
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
from colorama import Fore, Back, Style, init as coloramaInit


class Settings():
    SECURE_SCHEME="https"
    DEFAULT_PORT=443

    DEFAULT_DNS_SERVER = "8.8.8.8"
    DEFAULT_DNS_RECORDS = ["A","AAAA","CNAME","PTR","MX","SOA","TXT"]

    DEFAULT_TRACE_PORT = 33434
    DEFAULT_TRACE_TTL = 30
    DEFAULT_TRACE_TIMEOUT = 5

    SEPARATOR = ","

    def __init__(self):
        parser = argparse.ArgumentParser(description='Enumerate information about a website')
        parser.add_argument("url")
        parser.add_argument("-a",default=None, type=str, action="append", help="Specify the modules to run")
        parser.add_argument("-o",type=str, action="append", help="Path to output file")
        parser.add_argument("--whois-server", type=str, action="append", help="WHOIS server to use")
        parser.add_argument("--whois-server-file", type=str, action="append", help="WHOIS file to import. File must contain the domain and the server separated by space")
        parser.add_argument("--dns-server", type=str, action="append", help="DNS server to use")
        parser.add_argument("--dns-records", type=str, action="append", help="DNS records to query. Accepts multiple values separated by a comma")
        parser.add_argument("--trace-port", type=int, action="append", help="port to use for tracing")
        parser.add_argument("--trace-ttl", type=int, action="append", help="max number of hops")
        parser.add_argument("--trace-timeout", type=int, action="append", help="Timeout in seconds")
        parser.add_argument("--trace-show-gateway", action="store_true", help="Display local gateway in traceoute")
        args = vars(parser.parse_args())

        self.operations = args["a"][0].split(",") if args["a"] else None
        self.url, self.domain, self.domainSimple, self.port, self.method = self._parseUrl(args["url"])
        self.outputFile = self._parseInput(args, "o", None)

        #------WHOIS PARAMS------
        self.whoisServer = None
        self.whoisForceServer = False

        if args["whois_server"]:
            self.whoisServer = args["whois_server"]
            self.whoisForceServer = True
        elif args["whois_server_file"]:
            self.whoisServer = args["whois_server_file"]

        #-----DNS PARAMS------
        self.dnsServer = self._parseInput(args, "dns_server", self.DEFAULT_DNS_SERVER)
        self.dnsRecords = self._parseInput(args, "dns_records", self.DEFAULT_DNS_RECORDS, self.SEPARATOR)

        #-----TRACE PARAMS------
        self.tracePort = self._parseInput(args, "trace_port", self.DEFAULT_TRACE_PORT)
        self.traceTtl = self._parseInput(args, "trace_ttl", self.DEFAULT_TRACE_TTL)
        self.traceTimeout = self._parseInput(args, "trace_timeout", self.DEFAULT_TRACE_TIMEOUT)
        self.traceShowGateway = args["trace_show_gateway"]

    def _parseInput(self, args, key:str, altValue:str, sep:str=None):
        if args[key]:
            if sep:
                return args[key][0].split(sep)
            return args[key][0]
        else:
            return altValue


    def _parseUrl(self, url:str) -> tuple:
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
            urlNoParams = Settings.SECURE_SCHEME + "://" + urlNoParams

        return (
            urlNoParams,
            domain,
            domainSimple,
            urlNoMethod[idxPort+1:] if idxPort > -1 else self.DEFAULT_PORT,
            urlNoParams[:idxMethod] if idxMethod > -1 else self.SECURE_SCHEME
        )
  
    def _fileReader(targetList:list, path:str):
        with open(path, 'r') as f:
            for line in f:
                targetList.append(tuple(line.split()))


class EnumComponent(ABC):
    def __init__(self, bannerName:str, settings:Settings, outputWriter):
        self.settings = settings
        self.outputWriter = outputWriter
        self.bannerName = bannerName
    
    @abstractmethod
    def getResult(self):
        pass


class OutputWriter():
    class msgType(Enum):
        DEFAULT = (Fore.GREEN,"",""),
        BANNER = (Fore.GREEN, Back.LIGHTGREEN_EX, Style.BRIGHT),
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

    def __init__(self, settings:Settings):
        self.rowSize = 120
        coloramaInit()

    def writeToFile(self, input:str):
        return input

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
        return "{}{}{}{}{}{}".format(fore, back, style, input, OutputWriter.msgType.END.value, "\n" if addNewline else "")
    
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
            lastIdx = len(keys)-1
            for idx, key in enumerate(keys):
                strOut += self.applyStyle(key, OutputWriter.msgType.ARGNAME, indent) + self.inputParser(input[key], indent+1, idx != lastIdx)     

        elif isinstance(input, list):
            strOut = ""
            lastIdx = len(input)-1
            for idx,r in enumerate(input):
                if isinstance(r, tuple):
                    strOut += self.applyStyleTuple(r,indent)
                else:
                    strOut += self.applyStyle(str(r),indent=indent)
        else:
            strOut = self.applyStyle(str(input),indent=indent)

        if extraNewline:
            return strOut+"\n"
        else:
            return strOut
    
    def printTable(self, rows:list, cols:list, padding:list):
        sep = "| "
        tableLen = sum(padding) + len(sep) * (len(cols)+1)
        sepRow = "\n" + "-" * tableLen

        header = ""
        body = ""

        for c in range(0,len(cols)):
            header += sep + f"{cols[c]:<{padding[c]}s}"

        for r in rows:
            row = sep
            for i in range(0,len(cols)):
                row += f"{r[i]:<{padding[i]}s}"+sep
            body += "\n" + row

        return self.applyStyle(header + sepRow + body + sepRow)

    def getBanner(self, component:EnumComponent):
        banner = "="*self.BANNER_PADDING + component.bannerName + "="*self.BANNER_PADDING
        return self.applyStyle(banner,OutputWriter.msgType.BANNER)
    
    def _toStr(self, input) -> str:
        if input == None:
            return self.PLACEHOLDER_NONE
        if input == True:
            return self.PLACEHOLDER_TRUE
        if input == False:
            return self.PLACEHOLDER_FALSE
        return input


class WhoisComponent(EnumComponent):
    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        super().__init__("WHOIS RECORDS",settings, outputWriter)
        self.domain = settings.domain
        self.servers = settings.whoisServer
        self.force = settings.whoisForceServer

    def getResult(self):
        if self.servers:
            if self.force:
                return self._whois(self.servers[0])
            else:
                server = self._pickServer()
                if server:
                    return self._whois(server)
        return self._whoisIana()
        
    def _pickServer(self):
        ext = self.domain[self.domain.rfind("."):]
        for server in self.servers:
            if server[0] == ext:
                return server[0]
        return None

    def _whoisIana(self):
        request = "https://www.iana.org/whois?q={}".format(self.domain)
        response = requests.get(request).text
        return response[response.find("<pre>")+5:response.rfind("</pre>")]
    
    def _whois(self,server):
        query = f'{self.domain}\r\n'
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((server, 43))
        connection.send(query.encode())
        
        response = ""

        while len(response) < 10000:
            chunk = connection.recv(100).decode()
            if (chunk == ''):
                break
            response = response + chunk
   
        return response


class DnsComponent(EnumComponent):
    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        super().__init__("DNS RECORDS", settings, outputWriter)
        self.domain = settings.domain
        self.servers = settings.dnsServer
        self.records = settings.dnsRecords
        self.resolver = dns.resolver.Resolver()
        
    def reverse(self,address):
         addr=dns.reversename.from_address(address).to_text()
         result = self.dnsSingleQuery(addr,"PTR")
         return result[0] if result else addr
    
    def dnsSingleQuery(self,target:str,record:str):
        try:
            result = self.resolver.resolve(target,record)
            return [i.to_text() for i in result]
        except DNSException:
            return None
    
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
    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        super().__init__("TRACEROUTE", settings, outputWriter)
        self.dns = DnsComponent(settings, ow)
        self.domain = settings.domain
        self.port = settings.tracePort
        self.ttl = settings.traceTtl
        self.timeout = settings.traceTimeout
        self.showGateway = settings.traceShowGateway

    def getResult(self):
        rec = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        snd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        destAddress = self.dns.dnsSingleQuery(self.domain,"A")
        if len(destAddress) == 0:
            return None
        destAddress = destAddress[0]

        currAddress = ""
        gatewayAddr = None
        counter = 0
        hops = []

        rec.bind(("",self.port))
        rec.settimeout(self.timeout)
        
        for hop in range(1, self.ttl+1):
            if currAddress != destAddress:
                snd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)
                snd.sendto(b"", (destAddress, self.port))
                try:
                    sendTime = time.perf_counter_ns()
                    _, currAddress = rec.recvfrom(512)
                    currAddress = currAddress[0]
                    hostname = self.dns.reverse(currAddress)
                    recTime = time.perf_counter_ns()
                    elapsed = (recTime - sendTime) / 1e6
                except socket.error:
                    currAddress = None
                    elapsed = None
                if self.showGateway or not (self.showGateway or gatewayAddr == hostname):
                    counter += 1
                    hops.append((str(counter),currAddress,hostname,f"{elapsed:.2f}"))
                    if not gatewayAddr:
                        gatewayAddr = hostname
            else:
                break           
        return hops


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
            
    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        self.domain = settings.domain
        self.port = settings.port

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        
        super().__init__("CERTIFICATE AND SSL", settings, outputWriter)

    def getResult(self) -> dict:
        return {
                "OpenSSL version": SSLComponent.getOpenSSLVersion(),
                "Secure protocols": self.checkSSL(),
                "Supported ciphers": self.getSupportedCiphers(),
                "Certificate details": self.certInfo()}

    def getOpenSSLVersion():
        return ssl.OPENSSL_VERSION
    
    def getSupportedCiphers(self):
        results = []
        
        #pickle fails when attempting to create a deep copy of SSLContext using copy.deepcopy.
        #Had to do it the manual way
        
        tmpCtx = ssl.create_default_context()
        tmpCtx.check_hostname = self.ctx.check_hostname
        tmpCtx.verify_mode = self.ctx.verify_mode

        for cipher in self.ctx.get_ciphers():
            try:
                tmpCtx.set_ciphers(cipher["name"])
                with tmpCtx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
                    sock.connect((self.domain, self.port))
                results.append((cipher["name"], True))
            except SSLError:
                results.append((cipher["name"], False))
            except:
                results.append((cipher["name"], None))
        return results
   
    def certInfo(self):
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

    def checkSSL(self):
        results = []
        formats = [
                    ("SSL 3.0", ssl.PROTOCOL_SSLv23),
                    ("TLS 1.0", ssl.PROTOCOL_TLSv1),
                    ("TLS 1.1", ssl.PROTOCOL_TLSv1_1),
                    ("TLS 1.2", ssl.PROTOCOL_TLSv1_2)
                ]      
        for f in formats:
            fname, fvalue = f
            results.append((fname, self._testSSL(fvalue)))
        return results
    

class HTTPComponent(EnumComponent):
    httpCodeDictionary = {
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

    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        self.url = settings.url
        self.session = requests.Session()
        super().__init__("HTTP REQUESTS", settings, outputWriter)

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
        response = self.session.get(self.url)
        options = self.session.options(self.url)

        return {
            "Response code": self.formatHTTPCode(response.status_code),
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
                        } for k in self.session.cookies}
        }

    def _formatHttpVersion(self, version:int) -> str: 
        if version == 10:
            return "HTTP 1.0"
        if version == 11:
            return "HTTP 1.1"
        return "Not Found"
    
    def _parseRequest(self, req, trim:int=80):
        status = req.status_code
        text = None
        if req.text:
            text = req.text[:trim]+"..."
        else:
            text = "EMPTY RESPONSE"

        return {
            "Code": self.formatHTTPCode(status),
            "Response": text
        }
    
    def testHTTPMethods(self):
        getReq = self.session.get(self.url)
        postReq = self.session.post(self.url)
        headReq = self.session.head(self.url)
        optReq = self.session.options(self.url)
        putReq = self.session.put(self.url)
        patchReq = self.session.patch(self.url)
        deleteReq = self.session.delete(self.url)

        return{
            "GET": self._parseRequest(getReq),
            "POST": self._parseRequest(postReq),
            "HEAD": self._parseRequest(headReq),
            "OPTIONS": self._parseRequest(optReq),
            "PUT": self._parseRequest(putReq),
            "PATCH": self._parseRequest(patchReq),
            "DELETE": self._parseRequest(deleteReq),
        }


class WebEnumComponent(EnumComponent):
    def __init__(self, settings:Settings, outputWriter:OutputWriter=None):
        super().__init__("WEBSITE ENUMERATION", settings, outputWriter)
        self.url = settings.url
        self.session = requests.Session()

    def getFavicon(self):
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.text,"html.parser")
        return soup.find("link", rel="shortcut icon")

    def getSitemap(self, extraUrls:list=None):
        urls = ["sitemap","wp-sitemap","sitemap_index","post-sitemap","page-sitemap","pages-sitemap","category-sitemap","tag-sitemap"]

        if extraUrls:
            for url in extraUrls:
                dict = self._sitemapReq(url)
                if dict["location"]:
                    return dict

        for url in urls:
            fullUrl = "{}/{}".format(self.url,url)
            dict = self._sitemapReq(fullUrl)
            if dict["location"]:
                return dict
        
        return None
    
    def parseRobotsFile(self):
        response = self.session.get(self.url+"/robots.txt")
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
                            "Disallowed entries:": disallowedEntries}
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

    def getResult(self):
        robots = self.parseRobotsFile()

        return {
            "Robots entries": robots,
            "Sitemap entries": self.getSitemap(robots["Sitemap"]),
            "Favicon": self.getFavicon()
        }

    def _sitemapReq(self,url:str):
        headers = {"User-Agent": "Googlebot/2.1"}
        sitemapType = None
        sitemapEntries = None

        if url.endswith(".xml"):
            r  = self.session.get(url,headers=headers)
            if r.status_code == 200 and r.text:
                sitemapType = "xml"
                soup = BeautifulSoup(r.text,features="xml")
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
            r  = requests.get(url,headers=headers)
            if r.status_code == 200 and r.text:
                sitemapType = "plaintext"
                sitemapEntries = r.text.splitlines()
        
        return {"type": sitemapType, "location": url, "entries": sitemapEntries}


if __name__ == '__main__':
    settings = Settings()
    ow = OutputWriter(settings)

    enumComponents = {
        "who":{"class": WhoisComponent, "printAsTable": False, "tableParams": None},
        "dns":{"class": DnsComponent, "printAsTable": False, "tableParams": None},
        "trace":{"class": TraceComponent, "printAsTable": True, "tableParams": (["Hop","Address","Domain","Time (ms)"],[4,16,40,10])},
        "ssl": {"class": SSLComponent, "printAsTable": False, "tableParams": None},
        "http": {"class": HTTPComponent, "printAsTable": False, "tableParams": None},
        "web": {"class": WebEnumComponent, "printAsTable": False, "tableParams": None},
    }

    operations = settings.operations if settings.operations else enumComponents.keys()

    for op in operations:
        if op in enumComponents.keys():
            component = enumComponents[op]["class"](settings)
            printAsTable = enumComponents[op]["printAsTable"]
            output = ""
            if printAsTable:
                cols, padding = enumComponents[op]["tableParams"]
                output = ow.printTable(component.getResult(), cols, padding)
            else:
                output = ow.getFormattedString(component.getResult())
            print(ow.getBanner(component))
            print(output)
        else:
            print(ow.getErrorString("Unknown operation {}. Skipped".format(op)))
        