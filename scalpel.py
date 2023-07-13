import dns
from dns import resolver
from dns.exception import DNSException
import socket
import ssl
import requests
import OpenSSL
import time
from bs4 import BeautifulSoup
from urllib3 import PoolManager
from urllib.parse import urlparse
from urllib3.util.retry import Retry as Retry
from requests.adapters import HTTPAdapter



class WhoisComponent:
    def __init__(self, domain:str, servers:list=None, tryAll:bool=False):
        self.domain = domain
        self.servers = servers
        self.tryAll = tryAll

    def whois(self):
        resultList = []
        if self.servers:
            for server in self.servers:
                result = self._whois(server)
                if result and not result.startswith("No match for"):
                    if self.tryAll:
                        resultList.append((server,result))
                    else:
                        return {"multi": False, "result": result}
            if len(resultList) > 0:
                return {"multi": True, "result": resultList}
            else:
                return {"multi": False, "result": None}
        else:
            return {"multi": False, "result": self._whoisIana()}

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

class DnsComponent:
    def __init__(self, domain:str, servers:list=["8.8.8.8","8.8.4.4"], records:list = ["A","AAAA","CNAME","PTR","MX","SOA","TXT"]):
        self.domain = domain
        self.servers = servers
        self.records = records
        self.resolver = dns.resolver.Resolver()

    def reverse(self,address):
         addr=dns.reversename.from_address(address).to_text()
         result = self.dnsSingleQuery(addr,"PTR")
         return result[0] if result else addr
    
    def dnsSingleQuery(self,target:str,record:str):
        try:
            result = self.resolver.resolve(target)
            return [i.to_text() for i in result]
        except DNSException:
            return None
    
    def dnsQuery(self, tryAll:bool=False):
        results = []
        for r in self.records:
            try:
                result = self.resolver.resolve(self.domain,r)
                record = [i.to_text() for i in result]
                results.append({"record": r, "value": record})
            except DNSException:
                 results.append({"record": r, "value": None})
        return results
    
    def traceroute(self, port:int=33434, ttl:int=30):
        rec = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        snd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        destAddress = self.dnsSingleQuery(self.domain,"A")
        if len(destAddress) == 0:
            return None
        destAddress = destAddress[0]

        print(destAddress)
        currAddress = ""
        hops = []

        rec.bind(("",0))
        rec.settimeout(5)
        
        for hop in range(1, ttl+1):
            if currAddress != destAddress:
                snd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)
                snd.sendto(b"", (destAddress, port))
                try:
                    sendTime = time.perf_counter_ns()
                    _, currAddress = rec.recvfrom(512)
                    currAddress = currAddress[0]
                    hostname = self.reverse(currAddress)
                    recTime = time.perf_counter_ns()
                    elapsed = (recTime - sendTime) / 1e6
                    print(currAddress+" - "+str(hostname)+" - "+str(elapsed))
                except socket.error:
                    currAddress = None
                    elapsed = None
                hops.append((hop,currAddress,hostname,elapsed))
            else:
                break
            
        return hops

def certInfo(domain,port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
        sock.connect((domain, port))
        certDER = sock.getpeercert(True)
        sock.close()
        certPEM = ssl.DER_cert_to_PEM_cert(certDER)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certPEM)
        ext = [cert.get_extension(i) for i in range(cert.get_extension_count())]
        return {
            "certDER": certDER,
            "certPEM": str(certPEM),
            "subject": dict(cert.get_subject().get_components()),
            "issuedBy": dict(cert.get_issuer().get_components()),
            "serialNumber": cert.get_serial_number(),
            "version": cert.get_version(),
            "validFrom": cert.get_notBefore(),
            "validTo": cert.get_notAfter(),
            "extension": {e.get_short_name().strip(): str(e) for e in ext}}
    
class SSLAdapter(HTTPAdapter):
    def __init__(self, sslVersion=None, **kwargs):
        self.sslVersion = sslVersion

        super(SSLAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.sslVersion)
    
def sslRequest(domain, sslVersion, port=443):
    session = requests.Session()
    session.mount("https://",SSLAdapter(sslVersion[1]))
    try:
        response = session.get("https://"+domain+":"+str(port))
        print(sslVersion[0]+": OK")
    except:
        print(sslVersion[0]+": not supported")

def checkSSL(domain, port=443):
    print(ssl.OPENSSL_VERSION)
    formats = [
                ("SSL 3", ssl.PROTOCOL_SSLv23),
                ("TLS 1.0", ssl.PROTOCOL_TLSv1),
                ("TLS 1.1", ssl.PROTOCOL_TLSv1_1),
                ("TLS 1.2", ssl.PROTOCOL_TLSv1_2)
            ]      
    for f in formats:
        sslRequest(domain, f, port)

def getRequests(domain,port=443,secure=True):
    protocol = "https" if secure or port == 443 else "http"
    session = requests.Session()
    domain = "{}://{}:{}".format(protocol,domain,port)
    response = session.get(domain)
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
    domain = "www.google.com"
    print(WhoisComponent(domain).whois()["result"])
    print("---")
    print(WhoisComponent(domain,["whois.verisign-grs.com"]).whois()["result"])
    print(DnsComponent(domain).dnsQuery())
    print(DnsComponent(domain).traceroute(ttl=80))
    #print(getRequests(domain,443,True))
    #print(checkSSL(domain))
    #print(certInfo(domain))
    #print(dnsQuery(domain))