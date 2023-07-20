import dns
from dns import resolver
from dns.exception import DNSException
import socket
import ssl
import OpenSSL
from OpenSSL import crypto
from bs4 import BeautifulSoup
from urllib import parse
from urllib3 import PoolManager
from urllib3.util.retry import Retry as Retry
import requests
from requests.adapters import HTTPAdapter
import time
import argparse
from enum import Enum

class Settings():
    SECURE_SCHEME="https"
    DEFAULT_PORT=443

    class VerboseLevels(Enum):
        NONE = 0
        LOW = 1
        HIGH = 2

    def __init__(self):
        parse.urlparse
        parser = argparse.ArgumentParser(description='Enumerate information about a website')
        parser.add_argument("url")
        parser.add_argument("--whois-server", action="append", help="Specify a whois server to use")
        parser.add_argument("--whois-server-file", action="append", help="Specify a whois file to import. File must contain the domain and the server separated by space")
        args = vars(parser.parse_args())

        parsedUrl = parse.urlparse(args["url"])
        self.fullUrl = parsedUrl.path
        self.scheme, self.secure = self._validateScheme(parsedUrl.scheme)
        self.domain = self._clearHostname(parsedUrl.hostname)
        self.port = parsedUrl.port or self.DEFAULT_PORT

        self.whoisServer = None
        self.whoisForceServer = False
        if args["whois_server"]:
            self.whoisServer = args["whois_server"]
            self.whoisForceServer = True
        elif args["whois_server_file"]:
            self.whoisServer = args["whois_server_file"]

    def _clearHostname(self, hostname:str):
        return hostname[hostname.rfind("www."):]
    
    def _validateScheme(self,scheme:str):
        if not scheme:
            return (self.SECURE_SCHEME, True)
        if scheme == "http" or scheme == "https":
            return (scheme, scheme == "https")
        else:
            raise Exception("Invalid schema: valid values are http or https")
        
    def _fileReader(targetList:list, path:str):
        with open(path, 'r') as f:
            for line in f:
                targetList.append(tuple(line.split()))

class EnumComponent():
    def __init__(self, id:str, bannerName:str, outputWriter):
        self.outputWriter = outputWriter
        self.id = id
        self.bannerName = bannerName

class OutputWriter():
    def __init__(self, settings:Settings):
        pass

    def print(self, input, tab:int=0):
        if isinstance(input,str):
            print("\t"*tab+input)
        elif isinstance(input,dict):
            for key in input:
                print("\t"*tab+str(key))
                self.print(input[key], tab=tab+1)
        elif isinstance(input, list):
            for r in input:
                if isinstance(r, tuple):
                    argName, argValue = r
                    if isinstance(argValue, list):
                        print("\t"*tab+argName)
                        self.print(argValue, tab=tab+1)
                    else:
                        print("\t"*tab+"{}:\t{}".format(argName,argValue))
                elif isinstance(r, str):
                    print("\t"*tab+r)
        else:
            print("\t"*tab+str(input))
    
    def printTable(self, rows:list, cols:list, padding:list):
        sep = "| "
        tableLen = sum(padding) + len(sep) * (len(cols)+1)
        header = ""
        for c in range(0,len(cols)):
            header = header + sep + f"{cols[c]:<{padding[c]}s}"
        header = header + sep
        
        print(header)
        print("-" * tableLen)

        for r in rows:
            row = sep
            for i in range(0,len(cols)):
                row = row + f"{r[i]:<{padding[i]}s}"+sep
            print(row)
        
        print("-" * tableLen)

    def printBanner(self, component:EnumComponent):
        banner = "="*5+component.bannerName+"="*5
        print(banner)

class WhoisComponent(EnumComponent):
    def __init__(self, domain:str, servers:list=None, force:bool=False, outputWriter:OutputWriter=None):
        self.domain = domain
        self.servers = servers
        self.force = force
        super().__init__("who","WHOIS COMPONENT",outputWriter)

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
        results = []
        for r in self.records:
            try:
                result = self.resolver.resolve(self.domain,r)
                record = [i.to_text() for i in result]
                results.append((r, record))
            except DNSException:
                 results.append((r, None))
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
        super().__init__("ssl","CERTIFICATE AND SSL",outputWriter)

    def getOpenSSLVersion():
        return ssl.OPENSSL_VERSION

    def certInfo(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
            sock.connect((self.domain, self.port))
            certDER = sock.getpeercert(True)
            sock.close()
            certPEM = ssl.DER_cert_to_PEM_cert(certDER)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certPEM)
            pubKey = cert.get_pubkey()
            pubKeyStr= crypto.dump_publickey(crypto.FILETYPE_PEM,pubKey)
            keySize = pubKey.bits()
            #ext = [cert.get_extension(i) for i in range(cert.get_extension_count())]
            # "extension": {e.get_short_name().strip(): str(e) for e in ext}
            return {
                "Ceritificate (DER)": certDER,
                "Ceritificate (PEM)": str(certPEM),
                "Public key": pubKeyStr,
                "Key format": pubKey.type(),
                "Key length": keySize,
                "Subject": dict(cert.get_subject().get_components()),
                "Issuer": dict(cert.get_issuer().get_components()),
                "Serial Number": cert.get_serial_number(),
                "version": cert.get_version(),
                "Valid from": cert.get_notBefore(),
                "Valid until": cert.get_notAfter()}
        
    def _formatKeyType(self, pubKey):
        if pubKey.type() == crypto.TYPE_RSA:
            return "RSA"
        if pubKey.type() == crypto.TYPE_DSA:
            return "DSA"
        return "Not found"

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
    def __init__(self, url:str, outputWriter:OutputWriter=None):
        self.url = url
        self.session = requests.Session()
        super().__init__("http","HTTP REQUESTS",outputWriter)

    def getHTTPinfo(self):
        response = self.session.get(self.url)
        options = self.session.options(self.url)

        httpVersion = response.raw.version
        headers = dict(response.headers)
        cookies = self.session.cookies.get_dict()
        allowedMethods = options.headers["Allow"]

        return {
            "Response code": response.status_code,
            "HTTP version": self._formatHttpVersion(httpVersion),
            "Methods": allowedMethods,
            "Headers": headers,
            "Cookies": cookies
        }

    def _formatHttpVersion(self, version:int) -> str: 
        if version == 10:
            return "HTTP 1.0"
        if version == 11:
            return "HTTP 1.1"
        return "Not Found"
    
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
            "headers": response.headers,
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
    ow.printBanner(wc)
    ow.print(wc.whois())
    #print(WhoisComponent(domain,["whois.verisign-grs.com"]).whois())
    dnsc = DnsComponent(settings.domain,outputWriter=ow)
    ow.printBanner(dnsc)
    ow.print(dnsc.dnsQuery())
    trc = TraceComponent(dnsc,settings.domain,outputWriter=ow)
    ow.printBanner(trc)
    ow.printTable(trc.traceroute(),["Hop","Address","Domain","Time (ms)"],[4,16,40,10])
    sslc = SSLComponent(settings.domain,outputWriter=ow)
    ow.printBanner(sslc)
    ow.print(sslc.checkSSL())
    ow.print(sslc.certInfo())
    httpc = HTTPComponent("https://"+settings.domain,ow)
    ow.printBanner(httpc)
    ow.print(httpc.getHTTPinfo())
    #print(SSLComponent(settings.domain).certInfo())
    