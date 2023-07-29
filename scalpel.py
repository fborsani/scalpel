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
from colorama import Fore, Back, Style, init as coloramaInit

class EnumComponent():
    def __init__(self, id:str, bannerName:str, outputWriter):
        self.outputWriter = outputWriter
        self.id = id
        self.bannerName = bannerName


class Settings():
    SECURE_SCHEME="https"
    DEFAULT_PORT=443

    def __init__(self):
        parser = argparse.ArgumentParser(description='Enumerate information about a website')
        parser.add_argument("url")
        parser.add_argument("--whois-server", action="append", help="Specify a whois server to use")
        parser.add_argument("--whois-server-file", action="append", help="Specify a whois file to import. File must contain the domain and the server separated by space")
        args = vars(parser.parse_args())

        self.url, self.domain, self.domainSimple, self.port, self.method = self._parseUrl(args["url"])

        self.whoisServer = None
        self.whoisForceServer = False
        if args["whois_server"]:
            self.whoisServer = args["whois_server"]
            self.whoisForceServer = True
        elif args["whois_server_file"]:
            self.whoisServer = args["whois_server_file"]


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
            urlNoMethod[idxPort+1:] if idxPort > -1 else Settings.DEFAULT_PORT,
            urlNoParams[:idxMethod] if idxMethod > -1 else Settings.SECURE_SCHEME
        )
  
    def _fileReader(targetList:list, path:str):
        with open(path, 'r') as f:
            for line in f:
                targetList.append(tuple(line.split()))

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

    def __init__(self, settings:Settings):
        self.rowSize = 120
        coloramaInit()

    def applyStyle(self, input:str, type=msgType.DEFAULT):
        if isinstance (input, bytes):
            try:
                input = input.decode()
            except:
                input = str(input)

        fore, back, style = type.value[0]
        return "{}{}{}{}{}".format(fore, back, style, input.strip(), OutputWriter.msgType.END.value)

    def getFormattedString(self, input):
        return "{}\n".format(self.inputParser(input,0))

    def inputParser(self, input, tab:int=0):
        strOut = "\t"*tab

        if input is None:
            return strOut + self.applyStyle(OutputWriter.PLACEHOLDER_NONE, OutputWriter.msgType.ERROR)
        
        if isinstance(input, bool):
            value = OutputWriter.PLACEHOLDER_FALSE
            style = OutputWriter.msgType.ERROR
            
            if input == True:
                value = OutputWriter.PLACEHOLDER_TRUE
                style = OutputWriter.msgType.SUCCESS
            return strOut + self.applyStyle(value, style)
        
        if isinstance(input, str) or isinstance(input, bytes):
            return strOut + self.applyStyle(input.strip()).replace("\n","\n"+"\t"*tab)
        
        if isinstance(input, dict):
            strOut = ""
            keys = input.keys()
            lastIdx = len(keys)-1
            for idx, key in enumerate(keys):
                entry = "\t"*tab + self.applyStyle(key, OutputWriter.msgType.ARGNAME) + "\n" + self.inputParser(input[key], tab+1)
                if idx != lastIdx:
                    entry = entry + "\n"
                strOut = strOut + entry
            return strOut
        
        if isinstance(input, tuple):
            argName, argValue = r
            strKey = self.applyStyle(argName, OutputWriter.msgType.ARGNAME)
            strVal = self.inputParser(argValue, tab+1)
            return strOut + f"{strKey:<{48}s} {strVal:<{6}s}"
        
        if isinstance(input, list):
            strOut = ""
            lastIdx = len(input)-1
            for idx,r in enumerate(input):
                entry = "\t"*tab
                if isinstance(r, tuple):
                    argName, argValue = r
                    strKey = self.applyStyle(argName, OutputWriter.msgType.ARGNAME)
                    strVal = self.inputParser(argValue, 0)
                    entry = f"{strKey:<{48}s} {strVal:<{6}s}"
                else:
                    entry = entry + self.applyStyle(str(r))
            
                strOut = strOut + entry
                if idx != lastIdx:
                    strOut = strOut + "\n"

            return strOut
        
        return strOut + self.applyStyle(str(input))
    
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
        banner = "="*5+component.bannerName+"="*5
        return "\n"+self.applyStyle(banner,OutputWriter.msgType.BANNER)+"\n"
    
    def writeToFile(self):
        pass


class WhoisComponent(EnumComponent):
    def __init__(self, domain:str, servers:list=None, force:bool=False, outputWriter:OutputWriter=None):
        self.domain = domain
        self.servers = servers
        self.force = force
        super().__init__("who","WHOIS RECORDS",outputWriter)

    def whois(self):
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
    def __init__(self, domain:str, servers:list=["8.8.8.8","8.8.4.4"], records:list = ["A","AAAA","CNAME","PTR","MX","SOA","TXT"], outputWriter:OutputWriter=None):
        self.domain = domain
        self.servers = servers
        self.records = records
        self.resolver = dns.resolver.Resolver()
        super().__init__("dns","DNS RECORDS",outputWriter)

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
    
    def dnsQuery(self, tryAll:bool=False):
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
    def __init__(self, dnsComponent:DnsComponent, domain:str, port:int=33434, ttl:int=30, timeout:int=2, showGateway:bool=False, outputWriter:OutputWriter=None):
        self.dns = dnsComponent
        self.domain = domain
        self.port = port
        self.ttl = ttl
        self.timeout = timeout
        self.showGateway = showGateway
        super().__init__("trace","TRACEROUTE",outputWriter)

    def traceroute(self):
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
            
    def __init__(self, domain:str, port:int=443, outputWriter:OutputWriter=None):
        self.domain = domain
        self.port = port

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        
        super().__init__("ssl","CERTIFICATE AND SSL",outputWriter)

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

    def __init__(self, url:str, outputWriter:OutputWriter=None):
        self.url = url
        self.session = requests.Session()
        super().__init__("http","HTTP REQUESTS",outputWriter)

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
            "Methods": options.headers["Allow"],
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
        if status == 200:
            if req.text:
                text = req.text[:trim]+"..."
            else:
                text = "Empty response"

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

    
def getRequests(domain,port=443,secure=True):
    protocol = "https" if secure or port == 443 else "http"
    session = requests.Session()
    domain = "{}://{}:{}".format(protocol,domain,port)
    response = session.get(domain)
    options = session.options(domain).headers["Allow"]
    soup = BeautifulSoup(response.text,"html.parser")
    iconLink = soup.find("link", rel="shortcut icon")
    
    httpVersion = response.raw.version

    if httpVersion == 10:
        httpVersion = "HTTP 1.0"
    elif httpVersion == 11:
        httpVersion = "HTTP 1.1"

    response = session.get(domain+"/robots.txt")
    robots = None
    if(response.status_code == 200 and response.text):
        robots = response.text
        sitemapUrls = [i[9:] for i in robots.splitlines() if i.startswith("Sitemap: ")]

    sitemap = getSitemap(domain, sitemapUrls)

    return {"code": response.status_code,
            "httpVersion": httpVersion,
            "options": options,
            "headers": {k: [r.trim() for r in v.split(";") if r ] for k,v in response.headers.items()},
            "cookies": session.cookies.get_dict(), 
            "robots": robots,
            "faviconPath": iconLink,
            "sitemapLocation": sitemap["location"],
            "sitemapType": sitemap["type"],
            "sitemapEntries": sitemap["entries"]
            }

def getSitemapReq(url:str):
        headers = {"User-Agent": "Googlebot/2.1"}
        sitemapType = None
        sitemapEntries = None

        fullUrl = url+".txt"
        r  = requests.get(url,headers=headers)
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
                    print(tag)
                    for loc in tag.find_all("loc"):
                        sitemapEntries.append(loc.text)

            return {"type": sitemapType, "location": url, "entries": sitemapEntries}
        
        fullUrl = url+".txt"
        r  = requests.get(fullUrl,headers=headers)
        if r.status_code == 200 and r.text:
            sitemapType = "plaintext"
            sitemapEntries = r.text.splitlines()
            return {"type": sitemapType, "location": fullUrl, "entries": sitemapEntries}
        
        return {"type": sitemapType, "location": None, "entries": sitemapEntries}

def getSitemap(domain:str, extraUrls:list=None):
    urls = ["sitemap","wp-sitemap","sitemap_index","post-sitemap","page-sitemap","pages-sitemap","category-sitemap","tag-sitemap"]

    if extraUrls:
        for url in extraUrls:
            dict = getSitemapReq(url)
            if dict["location"]:
                return dict

    for url in urls:
        fullUrl = domain+"/"+url
        dict = getSitemapReq(fullUrl)
        if dict["location"]:
            return dict
        
    return {"type": None, "location": None, "entries": None}
        

if __name__ == '__main__':
    settings = Settings()
    ow = OutputWriter(settings)
    wc = WhoisComponent(settings.domain, settings.whoisServer, settings.whoisForceServer, outputWriter=ow)
    #print(ow.getBanner(wc))
    #print(ow.getFormattedString(wc.whois()))
    #print(WhoisComponent(domain,["whois.verisign-grs.com"]).whois())
    dnsc = DnsComponent(settings.domain,outputWriter=ow)
    print(ow.getBanner(dnsc))
    print(ow.getFormattedString(dnsc.dnsQuery()))
    #trc = TraceComponent(dnsc,settings.domain,outputWriter=ow)
    #print(ow.getBanner(trc))
    #print(ow.printTable(trc.traceroute(),["Hop","Address","Domain","Time (ms)"],[4,16,40,10]))
    sslc = SSLComponent(settings.domain,outputWriter=ow)
    print(ow.getBanner(sslc))
    print(ow.getFormattedString(sslc.checkSSL()))
    print(ow.getFormattedString(sslc.getSupportedCiphers()))
    print(ow.getFormattedString(sslc.certInfo()))
    httpc = HTTPComponent(settings.url,ow)
    print(ow.getBanner(httpc))
    print(ow.getFormattedString(httpc.getHTTPinfo()))
    print(ow.getFormattedString(httpc.testHTTPMethods()))
