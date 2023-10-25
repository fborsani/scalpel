import struct
import dns.resolver
from dns.exception import DNSException
import socket
import ssl
import OpenSSL
from ssl import SSLError
from OpenSSL import crypto
from bs4 import BeautifulSoup, Comment
from urllib3 import PoolManager
import requests
from requests.adapters import HTTPAdapter
import time
import random
import string
import re
import os
import ctypes
import platform
import concurrent
import argparse
import subprocess
from subprocess import TimeoutExpired
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
from colorama import Fore, Back, Style, init as coloramaInit

class Environment():
    def __init__(self):
        term_size = os.get_terminal_size()
        self.term_width = None
        self.term_height = None
    
        if term_size:
            self.term_width = term_size.columns
            self.term_height = term_size.lines
    
        self.os = platform.system()
        self.is_windows = self.os == "Windows"
        self.is_linux = self.os == "Linux"

        self.user = None
        self.is_user_admin = False

        if self.is_linux:
            self.user = os.geteuid()
            self.is_user_admin = self.user == 0

        elif self.is_windows:
            self.user = os.getenv('username')
            self.is_user_admin = ctypes.windll.shell32.IsUserAnAdmin() == 1


class Settings():
    DEFAULT_DNS_RECORDS = ["A","AAAA","CNAME","NS","PTR","MX","SOA","TXT"]

    DEFAULT_TRACE_PORT = 33434
    DEFAULT_TRACE_TTL = 30
    DEFAULT_TRACE_TIMEOUT = 5

    DEFAULT_DORKS_TLD = "com"

    SEPARATOR = ","
    DEFAULT_OPERATIONS=["whois", "dns", "ssl", "http", "web"]
    DEFAULT_THREADS = 4
    DEFAULT_TIMEOUT = 5

    def __init__(self, app_name:str=None, args:list=None):
        parser = argparse.ArgumentParser(prog=app_name, description="Perform enumeration against a website using various techniques")
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
        self.operations = self._parse_input(args, "a", self.DEFAULT_OPERATIONS, self.SEPARATOR)
        self.output_file = self._parse_input(args, "o")
        self.threads = self._parse_input(args, "threads", self.DEFAULT_THREADS)
        self.dns_server = self._parse_input(args, "dns_server", None, self.SEPARATOR)
        self.quiet = args["q"]
        self.verbose = args["v"]

        #------REQUESTS PARAMS------
        self.url, self.base_url, self.domain, self.tld, self.port = RequestsUtility.parse_url(args["url"])
        self.headers = self._parse_multi_value_param(args["H"],":")
        self.cookies = self._parse_multi_value_param(args["C"],"=")
        self.timeout = self._parse_input(args, "t", self.DEFAULT_TIMEOUT)

        #------WHOIS PARAMS------
        self.whois_server = None
        self.whois_from_file = None
        self.whois_get_remote_file = None

        if args["whois_server"]:
            self.whois_server = args["whois_server"]
        elif args["whois_server_file"]:
            self.whois_from_file = args["whois_server_file"]
        elif args["whois_get_servers"]:
            self.whois_get_remote_file = args["whois_get_servers"]

        #-----DNS PARAMS------
        self.dns_records = self._parse_input(args, "dns_records", self.DEFAULT_DNS_RECORDS, self.SEPARATOR)

        #-----TRACE PARAMS------
        self.trace_port = self._parse_input(args, "trace_port", self.DEFAULT_TRACE_PORT)
        self.trace_ttl = self._parse_input(args, "trace_ttl", self.DEFAULT_TRACE_TTL)
        self.trace_timeout = self._parse_input(args, "trace_timeout", self.DEFAULT_TRACE_TIMEOUT)
        self.trace_show_gateway = args["trace_show_gateway"]

        #-----SSL PARAMS------
        self.ssl_use_os_library = args["ssl_use_os_library"]

        #-----DORKS PARAMS------
        self.dorks_file = self._parse_input(args, "dorks_file")
        self.dorks_tld = self._parse_input(args, "dorks_tld", self.DEFAULT_DORKS_TLD)

        #-----BRUTEFORCE PARAMS------
        self.brute_file = self._parse_input(args, "brute_file")
        self.brute_included_http_codes = self._parse_input(args, "brute_include_codes")
        self.brute_print_404 = args["brute_print_404"]

    def _parse_input(self, args, key:str, alt_value:str=None, sep:str=None):
        if args[key]:
            if sep:
                return args[key].split(sep)
            return args[key]
        else:
            return alt_value
        
    def _parse_multi_value_param(self, input:list, sep:str=None, alt_value:str=None):
        dict = {}
        if input:
            for sub_list in input:
                for entry in sub_list:
                    if sep and sep in entry:
                        items = entry.split(sep,1)
                        dict[items[0].strip()] = items[1].strip()
            return dict
        return alt_value
        

class OutputWriter():
    class MsgTypeEnum(Enum):
        DEFAULT = (Fore.GREEN,"",""),
        BANNER = (Fore.YELLOW, Back.GREEN, Style.BRIGHT),
        ARGNAME = (Fore.GREEN, "", Style.BRIGHT),
        INFO = (Fore.CYAN,"",""),
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
        self.row_size = 120
        self.output_file = None
        coloramaInit()

    @staticmethod
    def print_app_banner():
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
    
        term_width = Environment().term_width
    
        if term_width and term_width >= OutputWriter.BANNER_MIN_TERM_SIZE:
            print(OutputWriter.MsgTypeEnum.DEFAULT.value[0][0] + banner + OutputWriter.MsgTypeEnum.END.value)
    
    @staticmethod
    def print_info_text(input:str, module=None):
        msg = input
        if module and module.banner_name:
            msg = f"{module.banner_name}: {input}"

        print(OutputWriter.MsgTypeEnum.INFO.value[0][0] + msg + OutputWriter.MsgTypeEnum.END.value + "\n")

    def get_banner(self, input):
        if isinstance(input, EnumComponent):
            value = input.banner_name
        else:
            value = str(input)
        
        banner = f"{'='*OutputWriter.BANNER_PADDING} {value} {'='*OutputWriter.BANNER_PADDING}"
        return self.apply_style(banner,OutputWriter.MsgTypeEnum.BANNER, extra_vert_space=1)

    def set_output_file(self, path:str):
        self.output_file = open(path, "w")

    def close_resources(self):
        if self.output_file:
            self.output_file.close()

    def write_file(self, input:str):
        if self.output_file:
            self.output_file.write(input)

    def get_error_string(self, input:str):
        return self.apply_style(input, OutputWriter.MsgTypeEnum.ERROR)

    def apply_style(self, input:str, type=MsgTypeEnum.DEFAULT, indent:int=0, extra_vert_space:int=0):

        if isinstance(input, bytes):
            try:
                input = input.decode()
            except:
                input = str(input)
        
        input.strip()
        add_newline = not input.endswith("\n")

        if indent > 0:
            if input.count("\n") > 0:
                input = self.INDENT*indent + input.replace("\n","\n"+self.INDENT*indent)
            else:
                input = self.INDENT*indent + input

        self.write_file(("\n" * extra_vert_space) + input + ("\n" if add_newline else "") + ("\n" * extra_vert_space))

        fore, back, style = type.value[0]
        return ("\n" * extra_vert_space) + fore + back + style + input + OutputWriter.MsgTypeEnum.END.value + ("\n" if add_newline else "") + ("\n" * extra_vert_space)
    
    def apply_style_tuple(self, input:tuple, indent:int):
        arg_name, arg_value = input
        str_value = self._to_str(arg_value)
        str_plain = (
            f"{self.INDENT*indent}"
            f"{arg_name:<{self.TUPLE_ARG_NAME_PADDING}s}"
            f"{str_value:<{self.TUPLE_ARG_VALUE_PADDING}s}\n"
            )
        
        fore_arg, back_arg, style_arg = OutputWriter.MsgTypeEnum.ARGNAME.value[0]
        fore_value, back_value, style_value = OutputWriter.MsgTypeEnum.DEFAULT.value[0]

        str_styled = (
            f"{self.INDENT*indent}"
            f"{fore_arg}{back_arg}{style_arg}"
            f"{arg_name:<{self.TUPLE_ARG_NAME_PADDING}s}"
            f"{OutputWriter.MsgTypeEnum.END.value}"
            f"{fore_value}{back_value}{style_value}"
            f"{str_value:<{self.TUPLE_ARG_VALUE_PADDING}s}"
            f"{OutputWriter.MsgTypeEnum.END.value}"
            f"\n"
            )
        
        self.write_file(str_plain)
        return str_styled

    def get_formatted_string(self, input):
        return "{}\n".format(self.parse_input(input,0))

    def parse_input(self, input, indent:int=0, extra_newline=False):
        str_out = ""
        if input is None:
            str_out = self.apply_style(OutputWriter.PLACEHOLDER_NONE, OutputWriter.MsgTypeEnum.ERROR, indent)
        
        elif isinstance(input, bool):
            value = OutputWriter.PLACEHOLDER_FALSE
            style = OutputWriter.MsgTypeEnum.ERROR
            
            if input == True:
                value = OutputWriter.PLACEHOLDER_TRUE
                style = OutputWriter.MsgTypeEnum.SUCCESS
            str_out = self.apply_style(value, style, indent)
        
        elif isinstance(input, (str, bytes)):
            str_out = self.apply_style(input, indent=indent)

        elif isinstance(input, dict):
            keys = input.keys()
            if len(keys) > 0:
                last_idx = len(keys)-1
                for idx, key in enumerate(keys):
                    str_out += self.apply_style(key, OutputWriter.MsgTypeEnum.ARGNAME, indent) + self.parse_input(input[key], indent+1, idx != last_idx)
            else:
                str_out = self.parse_input(None,indent)

        elif isinstance(input, list):
            if len(input) > 0:
                last_idx = len(input)-1
                for idx,r in enumerate(input):
                    if isinstance(r, tuple):
                        str_out += self.apply_style_tuple(r, indent)
                    else:
                        str_out += self.parse_input(r, indent)
                        if isinstance(r, dict):
                            str_out += "\n\n\n"
            else:
                str_out = self.parse_input(None,indent)
        else:
            str_out = self.apply_style(str(input),indent=indent)

        if extra_newline:
            return str_out+"\n"
        else:
            return str_out
    
    def _to_str(self, input) -> str:
        if input == None:
            return self.PLACEHOLDER_NONE
        if input == True:
            return self.PLACEHOLDER_TRUE
        if input == False:
            return self.PLACEHOLDER_FALSE
        return input


#-------ABSTRACT CLASS AND CUSTOM EXCEPTION--------


class EnumComponent(ABC):
    def __init__(self, banner_name:str, settings:Settings):
        self.settings = settings
        self.banner_name = banner_name
    
    @abstractmethod
    def run(self):
        pass


class EnumException(Exception):
    def __init__(self, module:EnumComponent, message:str, original_error:Exception=None):
        self.message = message
        self.module = module
        self.fullErrStr = f"{module.banner_name}: {message}" if module else self.message
        super().__init__(original_error)


#-----------------UTILITY CLASSES-----------------

class RequestsUtility():
    SECURE_SCHEME="https"
    DEFAULT_PORT=443

    DEFAULT_DNS = ["8.8.8.8","8.8.4.4"]

    RESERVED_PORT = 1024
    RANDOM_URL_LENGTH = 25
    MALFORMED_URL = "test//test;[]{},./#\\test%0A%0D%00test"

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
        302: "Temporary redirect",
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
                 follow_redirects:bool=True,
                 headers:dict=None,
                 cookies:dict=None):
        
        if settings:
            self.timeout = settings.timeout
            self.threads = settings.threads
            self.follow_redirects = True
            self.cookies = settings.cookies
            self.headers = settings.headers
        else:
            self.timeout = timeout
            self.follow_redirects = follow_redirects
            self.cookies = cookies
            self.headers = headers

        self.session = requests.session() if session else None

        self.caller = caller

    def http_request(self, url:str, method:str="get", params:dict=None, headers:dict=None, cookies:dict=None):
        try:
            if self.session:
                if method == "get":
                    return self.session.get(url,
                                        timeout=self.timeout,
                                        allow_redirects=self.follow_redirects,
                                        cookies=cookies if cookies else self.cookies,
                                        headers=headers if headers else self.headers,
                                        params=params) 
                if method == "post":
                    return self.session.post(url,
                                        timeout=self.timeout,
                                        allow_redirects=self.follow_redirects,
                                        cookies=cookies if cookies else self.cookies,
                                        headers=headers if headers else self.headers,
                                        params=params) 

            return self.METHODS[method](url,
                                        timeout=self.timeout,
                                        allow_redirects=self.follow_redirects,
                                        cookies=cookies if cookies else self.cookies,
                                        headers=headers if headers else self.headers,
                                        params=params) 
        except requests.ConnectionError as e:
            raise EnumException(self.caller, f"Unable to connect to {url}", e)
        except requests.exceptions.ConnectTimeout as e:
            raise EnumException(self.caller, f"Request to {url} has timed out", e)

    def get_session_cookies(self):
        if self.session:
            return self.session.cookies
        return None

    def create_socket(self, proto:str=None):
        if not Environment().is_user_admin:
            raise EnumException(self.caller, f"Administrative privileges are required to open sockets", None)
        
        if proto == "icmp":
            return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        if proto == "udp":
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

    def create_listener(self):
        if Environment().is_windows:
            host = RequestsUtility.whoami()
            rec = self.create_socket("icmp")
            rec.bind((host,0))
            rec.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            rec.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            rec = self.create_socket("icmp")
            rec.bind(("",0))
            rec.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))
        return rec
    
    def sock_request(self, url:str, port:int, body:str=None, ssl_ctx=None):

        if ssl_ctx:
            sc = ssl_ctx.wrap_socket(socket.socket(), server_hostname=url)
        else:
            sc = self.create_socket()

        try:      
            sc.settimeout(self.timeout)
            sc.connect((url, port))
            if body:
                sc.send(body.encode())
            return sc
        except socket.error as e:
            sc.close()
            raise EnumException(self.caller, f"Unable to connect to {url}:{port}", e)

    def sock_send_bytes(self, sock, body:bytes, url:str, port:int, timeout:int=None):        
        timeout = timeout if timeout else self.timeout
        sock.settimeout(timeout)
        try:
            sock.sendto(body,(url, port))
            return sock
        except socket.error as e:
            raise EnumException(self.caller, f"Unable to connect to {url}:{port}", e)
  
    def sock_receive(self, sock, size: int= 512):
        try:
            sock.settimeout(self.timeout)
            return sock.recvfrom(size)
        except socket.error:
            return None          
    
    @staticmethod    
    def whoami():
        return socket.gethostbyname(socket.gethostname())

    @staticmethod
    def dns_reverse_lookup(ip:str, server:list=None, timeout:int=5):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        addr=dns.reversename.from_address(ip).to_text()
        result = RequestsUtility.dns_single_query(addr, "PTR", server)
        return result[0] if result else addr
    
    @staticmethod
    def dns_single_query(target:str,record:str, server:list=None, timeout:int=5):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            if server:
                resolver.nameservers = server
            result = resolver.resolve(target,record)
            return [i.to_text() for i in result]
        except DNSException:
            return None

    @staticmethod
    def format_response_code(response):
        
        if isinstance(response, requests.Response):
            history = response.history
            code = response.status_code
            if history:
                first_redirect = history[0]
                return f"{RequestsUtility.format_response_code(first_redirect)} --> {RequestsUtility.format_response_code(code)} [{response.url}]"
        else:
            code = int(response)
        
        if code in RequestsUtility.HTTP_CODES.keys():
            return f"{code} ({RequestsUtility.HTTP_CODES[code]})"
        return code
    
    @staticmethod
    def format_http_version(version:int): 
        if version == 10:
            return "HTTP 1.0"
        if version == 11:
            return "HTTP 1.1"
        return "Not Found"
    
    @staticmethod
    def get_random_url(base:str):
        random_url = "".join(random.choice(string.ascii_letters) for i in range(0, RequestsUtility.RANDOM_URL_LENGTH))
        if base.endswith("/"):
            return base + random_url
        return f"{base}/{random_url}"
    
    @staticmethod
    def get_malformed_url(base:str):
        if base.endswith("/"):
            return base + RequestsUtility.MALFORMED_URL
        return f"{base}/{RequestsUtility.MALFORMED_URL}"

    @staticmethod
    def parse_url(url:str):
        url = url.strip()

        idx_params = url.find("?")
        url = url[:idx_params] if idx_params > 0 else url 
        
        idx_method = url.find("://")
        url_no_method = url[idx_method+3:] if idx_method > 0 else url

        idx_path = url_no_method.find("/")
        base_url = url_no_method[:idx_path] if idx_path > 0 else url_no_method 

        idx_port = base_url.rfind(":")
        domain = base_url[:idx_port] if idx_port > 0 else base_url

        idx_ext = re.match(domain,"(\.[a-z]{2,3})+$")
        domain_simple = domain[:idx_ext]

        if domain.count(".") > 1:
            idx_tld = domain_simple.find(".")
            tld = domain_simple[idx_tld+1:]
        else:
            tld = domain

        port = int(base_url[idx_port+1:]) if idx_port > -1 else RequestsUtility.DEFAULT_PORT
   
        if idx_method < 0:
            url = RequestsUtility.SECURE_SCHEME + "://" + url_no_method
            base_url = RequestsUtility.SECURE_SCHEME + "://" + base_url
        
        return (
            url,
            base_url,
            domain,
            tld,
            port
        )


class FileUtility():
    def __init__(self, caller:EnumComponent, split:bool=False, separator:str=None, comment_symbol:str=None):
        self.comment_symbol = comment_symbol
        self.split = split
        self.sep = separator if split and separator else None
        self.caller = caller

    def read_file(self, path:str):
        rows = []
        try:
            with open(path, 'r') as f:
                for line in f:
                    if not self.comment_symbol or (self.comment_symbol and not line.startswith(self.comment_symbol)):
                        if self.split:
                            rows.append([l.strip() for l in line.split(self.sep)])
                        else:
                            rows.append(line.strip())
            return rows
        except OSError as e:
            raise EnumException(self.caller, f"Failed to open file {path} with error {e.errno} - {e.strerror}", e)

    def create_from_request(self, req:RequestsUtility, url:str, dest:str):
        try:
            response = req.http_request(url)
            with open(dest, "wb") as f:
                f.write(response.content)
        except OSError as e:
            raise EnumException(self.caller, f"Failed to write to file {dest} with error {e.errno} - {e.strerror}", e)
        

#-----------------MODULES-----------------

class WhoisComponent(EnumComponent):
    FILE_COMMENT = ";"
    FILE_URL = "https://www.nirsoft.net/whois-servers.txt"
    
    def __init__(self, settings:Settings):
        self.domain = settings.domain
        self.server = settings.whois_server
        self.file_path = settings.whois_from_file
        self.remote_file_dest = settings.whois_get_remote_file
        self.verbose = settings.verbose

        self.req = RequestsUtility(self, settings)
        self.file_util = FileUtility(self, True, comment_symbol= WhoisComponent.FILE_COMMENT)
        super().__init__("WHOIS RECORDS",settings)

    def run(self): 
        if self.server:
            return self._query_whois(self.server)
        if self.file_path:
            servers = self.file_util.read_file(self.file_path)
            return self._query_whois(self._pick_server(servers))
        if self.remote_file_dest:
            self.file_util.create_from_request(self.req, WhoisComponent.FILE_URL, self.remote_file_dest)
            servers = self.file_util.read_file(self.remote_file_dest)
            return self._query_whois(self._pick_server(servers))
        return self._query_iana()
        
    def _pick_server(self, servers:list):
        domain = self.domain[self.domain.find(".")+1:]
        for server in servers:
            ext, whois_server = server
            if ext == domain:
                return whois_server
        return None

    def _query_iana(self):
        request = f"https://www.iana.org/whois?q={self.domain}"

        if self.verbose:
            OutputWriter.print_info_text(f"Sending HTTP request to: {request}", self)

        response = self.req.http_request(request)

        if response.status_code == 200 and response.text:
            text = response.text
            result = text[text.find("<pre>")+5:text.rfind("</pre>")]
            if result.strip():
                return result
            else:
                return "Empty response from IANA whois page. Consider sending a request directly to a WHOIS server using --whois-server or --whois-server-file"
        else:
            return f"Connection failed. Response code: {self.req.format_response_code(response)}"
    
    def _query_whois(self,server):
        if self.verbose:
            OutputWriter.print_info_text(f"Contacting whois server {server}", self)

        query = f'{self.domain}\r\n'
        connection = self.req.sock_request(server,43,query)
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
        self.tld = settings.tld
        self.records = settings.dns_records
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = settings.timeout
        if settings.dns_server:
            self.resolver.nameservers = settings.dns_server
        
    def run(self):
        return {
            "DNS Server info": self._server_info(),
            "Results": self._query_dns()
        }
        
    def _query_dns(self):
        results = {}
        for r in self.records:
            try:
                result = self.resolver.resolve(self.domain,r)
                record = [i.to_text() for i in result]
            except DNSException:
                 record = None
            results[r] = record
        return results

    def _server_info(self):
        results = {}

        try:
            server_soa = self._pretty_print_soa()
            server_nx = [i.to_text() for i in self.resolver.resolve(self.tld, "NS")]
            servers = []
            for s in server_nx:
                servers.append(f"{s} ({self.resolver.resolve(s,'A')[0].to_text()})")
        except DNSException:
            servers = None
            server_soa = None

        return {
            "DNS Server": self.resolver.nameservers,
            "TLD": self.tld,
            "Authoritative DNS Server": servers,
            "SOA Server": server_soa
        }
    
    def _pretty_print_soa(self):
        try:
            req = self.resolver.resolve(self.tld, "SOA")[0].to_text()
            data = req.split(" ")
            return {
                "Main Server": data[0][:-1],
                "Admin Mail": self._format_soa_mail(data[1]),
                "Serial": data[2],
                "Refresh rate": data[3],
                "Retry rate": data[4],
                "Expiry time": data[5],
                "TTL": data[6]
            }
        except DNSException:
            return None
        
    def _format_soa_mail(self, mail:str):
        if mail.endswith("."):
            mail = mail[:-1]

        domain_idx = mail.rfind("\.")
        if domain_idx > -1:
            mail = mail.replace("\.", ".")
        else:
            domain_idx = 0
        
        if domain_idx > 0:
            return mail[:domain_idx+1] + mail[domain_idx+1:].replace(".", "@", 1)
        
        return mail.replace(".", "@", 1)


class TraceComponent(EnumComponent):
    def __init__(self, settings:Settings):
        super().__init__("TRACEROUTE", settings)
        self.domain = settings.domain
        self.dest_port = settings.trace_port
        self.port = settings.port
        self.ttl = settings.trace_ttl
        self.timeout = settings.timeout
        self.dns_server = settings.dns_server
        self.verbose = settings.verbose

        self.req = RequestsUtility(self, settings)

    def run(self):
        dest_address = self.req.dns_single_query(self.domain, "A", self.dns_server, self.timeout)
        if not dest_address or not dest_address[0]:
            raise EnumException(self, "Unable to resolve destination")
        
        dest_address = dest_address[0]
        trace_result = self.trace(dest_address) 
        
        return {
            "Destination address": dest_address,
            "Success": trace_result["success"],
            "Note": trace_result["note"],
            "Traceroute": self.print_table(trace_result["hops"], ["Hop","Address","Domain","Time (ms)"], [6,20,40,12])
        }

    def trace(self, dest_address):
        curr_address = ""
        curr_host = self.req.whoami()
        counter = 0
        hops = []
        success = False
        note = None
        last_addr_before_error = None
        total_time = 0
                    
        if self.verbose and Environment().is_windows:
            OutputWriter.print_info_text(f"Windows OS detected. Verify that your firewall is not blocking the application", self)

        for hop in range(1, self.ttl+1):
            rec = self.req.create_listener()
            snd = self.req.create_socket("udp")
            snd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)

            if self.verbose:
                OutputWriter.print_info_text(f"Current hop: {hop}/{self.ttl}", self)

            self.req.sock_send_bytes(snd, b"", dest_address, self.dest_port)
            sendTime = time.perf_counter_ns()
            response = self.req.sock_receive(rec)
            if response:
                _, curr_address = response
                curr_address = curr_address[0]
                hostname = self.req.dns_reverse_lookup(curr_address, self.dns_server, self.timeout)
                recTime = time.perf_counter_ns()
                elapsed = (recTime - sendTime) / 1e6
                total_time += elapsed
                
                if hostname != curr_host:
                    counter += 1
                    hops.append((str(counter),curr_address,hostname,f"{elapsed:.2f}" if elapsed else None))
            else:
                last_addr_before_error = curr_address
                
            snd.close()
            rec.close()

            if curr_address == dest_address:
                success = True
                note = f"Destination host reached in {counter} hops. The trip lasted {total_time/1000:.2f} seconds"
                break


        if not success:
            #the variable hostname records the last host visited. If populated it means the target was not reachable within the specified ttl.
            #If the variable is None it means the last request was not completed possibily due to a timeout or host unreachable error

            if hostname:
                note = f"Unable to reach target within {self.ttl} hops. Last destination reached: {hostname}"
            else:
                note = f"Destination unreachable due to request timeout. Request that failed: {last_addr_before_error}"

        return {
            "success": success,
            "note": note,
            "hops": hops
        }

    def print_table(self, rows:list, cols:list, padding:list):
        sep = "|"
        placeholder_none = "*"
        len_table = sum(padding) + len(sep) * (len(cols)+1)
        sep_row = "\n" + "-" * len_table

        header = ""
        body = ""

        for c in range(0,len(cols)):
            header += sep + f"{' '+cols[c]:<{padding[c]}s}"
        header += sep

        for r in rows:         
            row = sep
            for i in range(0,len(cols)):
                val = r[i] if r[i] else placeholder_none
                row += f"{' '+val:<{padding[i]}s}"+sep
            body += "\n" + row

        return header + sep_row + body + sep_row

class SSLComponent(EnumComponent):

    class SSLAdapter(HTTPAdapter):
        def __init__(self, ssl_version=None, **kwargs):
            self.ssl_version = ssl_version

            super(SSLComponent.SSLAdapter, self).__init__(**kwargs)

        def init_poolmanager(self, connections, maxsize, block=False, ):
            self.poolmanager = PoolManager(num_pools=connections,
                                        maxsize=maxsize,
                                        block=block,
                                        ssl_version=self.ssl_version)
            
    def __init__(self, settings:Settings):
        self.domain = settings.domain
        self.port = settings.port
        self.ssl_use_os_library = settings.ssl_use_os_library
        self.verbose = settings.verbose
        self.timeout = settings.timeout

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        self.req = RequestsUtility(self, settings)
        
        super().__init__("CERTIFICATE AND SSL", settings)

    def run(self) -> dict:
        results = self._get_ssl_info_ext() if self.ssl_use_os_library else self._get_ssl_info()
        return {
                "OpenSSL version": results["version"],
                "Secure protocols": results["proto"],
                "Supported ciphers": results["ciphers"],
                "Certificate details": self.cert_info()}
    
    def _get_ssl_info(self):
        proto = []
        ciphers = []

        #pickle fails when attempting to create a deep copy of SSLContext using copy.deepcopy
        #so I have to do it the manual way
        
        ctx_tmp = ssl.create_default_context()
        ctx_tmp.check_hostname = self.ctx.check_hostname
        ctx_tmp.verify_mode = self.ctx.verify_mode

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
            OutputWriter.print_info_text("Testing TLS/SSL protocols", self)

        for f in formats:
            fname, fvalue = f
            if fvalue:
                proto.append((fname, self._test_ssl(fvalue)))
            else:
                proto.append((fname, "Unsupported client side"))

        if self.verbose:
            OutputWriter.print_info_text("Testing supported ciphers", self)

        for cipher in self.ctx.get_ciphers():
            try:
                ctx_tmp.set_ciphers(cipher["name"])
                sc = socket.socket()
                sc.settimeout(5)

                with ctx_tmp.wrap_socket(sc, server_hostname=self.domain) as sock:
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
    
    def _get_ssl_info_ext(self):
        cmd_root = "openssl"
        if platform.system() == "Windows":
            cmd_root = "openssl.exe"

        try:
            version = subprocess.run([cmd_root, "version"], capture_output = True).stdout.decode("UTF-8")
            ciphers = subprocess.run([cmd_root, "ciphers", "ALL"], capture_output = True).stdout.decode("UTF-8").strip().split(":")
        except FileNotFoundError as e:
            raise EnumException(self, f"Unable to execute {cmd_root}. Verify that the application is installed and that the folder in included in $PATH or BIN env variables", e)
        
        formats = [
                    ("SSLv2", "-ssl2"),
                    ("SSLv3", "-ssl3"),
                    ("TLSv1", "-tls1"),
                    ("TLSv1.1", "-tls1_1"),
                    ("TLSv1.2", "-tls1_2"),
                    ("TLSv1.3", "-tls1_3")
                ] 
        
        proto = []
        supported_ciphers = []
        
        for f in formats:
            fname, switch = f
            res, motivation = self._run_subprocess(cmd_root, switch, False)
            if res:
                proto.append((fname, True))
            else:
                proto.append((fname, motivation if motivation else False))

        for c in ciphers:
            res, motivation = self._run_subprocess(cmd_root, c, True)
            if res:
                supported_ciphers.append((c, True))
            else:
                supported_ciphers.append((c, motivation if motivation else False))

        return {
            "version": version,
            "proto": proto,
            "ciphers": supported_ciphers
        }
    
    def _run_subprocess(self, cmd_root:str, input:str, is_cipher:bool):
        try:
            if is_cipher:
                cmd = subprocess.run(f"{cmd_root} s_client -cipher {input} -connect {self.domain}:{self.port} </dev/null", shell=True, capture_output=True, timeout=self.timeout)
            else:
                cmd = subprocess.run(f"{cmd_root} s_client -connect {self.domain}:{self.port} {input} </dev/null", shell=True, capture_output=True, timeout=self.timeout)
            
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

   
    def cert_info(self):
        if self.verbose:
            OutputWriter.print_info_text("Retrieving certificate", self)

        sock = self.req.sock_request(self.domain, self.port, ssl_ctx=self.ctx)
        cert_der = sock.getpeercert(True)
        sock.close()
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        pub_key = cert.get_pubkey()
        pub_key_str= crypto.dump_publickey(crypto.FILETYPE_PEM,pub_key)
        ext = [cert.get_extension(i) for i in range(cert.get_extension_count())]
        return {
            "Ceritificate (PEM)": str(cert_pem),
            "Valid": not cert.has_expired(),
            "Signature": cert.get_signature_algorithm(),
            "Fingerprint (SHA1)":cert.digest('sha1'),
            "Fingerprint (SHA256)":cert.digest('sha256'),
            "Serial Number": cert.get_serial_number(),
            "Version": cert.get_version(),
            "Public key": pub_key_str,
            "Key format": self._print_key_type(pub_key),
            "Key length": pub_key.bits(),
            "Subject": dict(cert.get_subject().get_components()),
            "Issuer": dict(cert.get_issuer().get_components()),
            "Valid from": datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%S%z").date().isoformat(),
            "Valid until": datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%S%z").date().isoformat(),
            "Extended information": {e.get_short_name().decode(): str(e).replace(", ","\n") for e in ext}
            }
        
    def _print_key_type(self, pub_key):
        if pub_key.type() == crypto.TYPE_RSA:
            return "RSA"
        if pub_key.type() == crypto.TYPE_DSA:
            return "DSA"
        return pub_key.type()

    def _test_ssl(self, ssl_version):
        session = requests.Session()
        session.mount("https://",SSLComponent.SSLAdapter(ssl_version))
        try:
            response = session.get("https://"+self.domain+":"+str(self.port))
            return True
        except:
            return False
    

class HTTPComponent(EnumComponent):
    def __init__(self, settings:Settings):
        self.url = settings.url
        self.base_url = settings.base_url
        self.req = RequestsUtility(self, settings, True)
        self.verbose = settings.verbose
        
        super().__init__("HTTP REQUESTS", settings)

    def run(self) -> dict:
        if self.verbose:
            OutputWriter.print_info_text(f"Testing url {self.url}", self)

        return {
            "HTTP info": self.get_http_info(),
            "HTTP methods": self._test_methods(),
            "Base Url Response": self._test_base_url(),
            "Page Not Found Response": self._test_page_not_found(),
            "Malformed Url Response": self._test_malformed_url()
        }

    def get_http_info(self):
        response = self.req.http_request(self.url)
        options = self.req.http_request(self.url,"options")

        return {
            "Response": self._parse_request(response),
            "HTTP version": self.req.format_http_version(response.raw.version),
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
                        } for k in self.req.get_session_cookies()}
        }

    def _parse_request(self, req, trim:int=80):
        text = None
        if req.text:
            text = req.text[:trim]+"..."
        else:
            text = "EMPTY RESPONSE"

        return {
            "Url": req.history[0].url if req.history else req.url,
            "Code": self.req.format_response_code(req),
            "Length (bytes)": str(len(req.content)) if req.content else "0",
            "Length (chars)": str(len(req.text)) if req.text else "0",
            "Body": text
        }
    
    def _test_methods(self):
        if self.verbose:
            OutputWriter.print_info_text("Testing supported methods", self)

        results = {}

        for method in self.req.METHODS.keys():
            results[method.upper()] = self._parse_request(self.req.http_request(self.url, method))
                                                               
        return results

    def _test_base_url(self):
        if self.url != self.base_url:
            return self._parse_request(self.req.http_request(self.base_url)) 
        return "Already hitting base domain. See HTTP info section above for response data" 
    
    def _test_page_not_found(self):
        random_url = self.req.get_random_url(self.url)
        return self._parse_request(self.req.http_request(random_url))
    
        
    def _test_malformed_url(self):
        url = self.req.get_malformed_url(self.url)
        return self._parse_request(self.req.http_request(url))


class WebEnumComponent(EnumComponent):
    def __init__(self, settings:Settings):
        super().__init__("WEBSITE ENUMERATION", settings)
        self.url = settings.url
        self.req = RequestsUtility(self, settings)
        self.verbose = settings.verbose

    def run(self):
        if self.verbose:
            OutputWriter.print_info_text(f"Testing url {self.url}", self)
            
        response = self.req.http_request(self.url)
        soup = BeautifulSoup(response.text,"html.parser")
        robots = self.parse_robots_file()

        if self.verbose:
            OutputWriter.print_info_text("Scanning included resources", self)
    
        return {
            "Title": soup.head.title.string,
            "Favicon": self._get_favicon(soup),
            "HTML params": soup.find("html").attrs,
            "Meta Tags": soup.find_all("meta"),
            "Included scripts": [script["src"].strip() for script in soup.find_all("script",{"src":True}) if script["src"].strip()],
            "Included stylesheets": [link["href"].strip() for link in soup.find_all("link", rel="stylesheet") if link["href"].strip()],
            "Robots entries": robots,
            "Sitemap entries": self._get_sitemap(robots["Sitemap"] if robots else None),
            "Page links": list(set([link["href"].strip() for link in soup.find_all("a",{"href":True}) if link["href"].strip()])),
            "Comments": [line.strip() for line in soup.find_all(string = lambda text: isinstance(text,Comment)) if line.strip()]
            
        }
         
    def _get_favicon(self, soup):
        url = self._get_favicon_url(soup)
        if url:
            if url.startswith("/"):
                return self.url+url 
            return url
        return None
    
    def _get_favicon_url(self, soup):
        val = soup.find("link", attrs={'rel': re.compile("^(shortcut icon|icon)$", re.I)})
        if val:
            return val["href"]
             
        val = soup.find("meta", property="og:image")
        if val:
            return val["content"]
        return val

    
    def _get_sitemap(self, possible_urls:list=None):
        if self.verbose:
            OutputWriter.print_info_text("Scanning sitemaps", self)
    
        urls = ["sitemap","wp-sitemap","sitemap_index","post-sitemap","page-sitemap","pages-sitemap","category-sitemap","tag-sitemap"]

        if possible_urls:
            for url in possible_urls:
                dict = self._req_sitemap(url)
                if dict["Location"]:
                    return dict

        for url in urls:
            full_path = "{}/{}".format(self.url,url)
            dict = self._req_sitemap(full_path)
            if dict["Location"]:
                return dict
        
        return None
    
    def parse_robots_file(self):
        if self.verbose:
            OutputWriter.print_info_text(f"Scanning robots file", self)

        response = self.req.http_request(self.url+"/robots.txt")
        robots = None
        if(response.status_code == 200 and response.text):
            robots = [l for l in response.text.splitlines() if l.strip()]

            sitemaps = []
            entries_allowed = []
            entries_disallowed = []
            entries = {}
            current_ua = "*"

            for l in robots:
                if l.startswith("Sitemap"):
                    sitemaps.append(l[9:])
                if l.startswith("User-agent"):
                    newUa = l[12:]
                    if newUa != current_ua:
                        entries["User Agent: {}".format(current_ua)] = {
                            "Allowed entries": entries_allowed,
                            "Disallowed entries:": entries_disallowed
                            }
                        current_ua = newUa

                if l.startswith("Allow"):
                    entries_allowed.append(l[7:])

                if l.startswith("Disallow"):
                    entries_disallowed.append(l[10:])
            
            #Store last entries
            entries["User Agent: {}".format(current_ua)] = {
                "Allowed entries": entries_allowed,
                "Disallowed entries:": entries_disallowed  
            }

            return {
                "Sitemap": sitemaps,
                "Entries": entries
            }
        
        return None

    def _req_sitemap(self,url:str):
        headers = {"User-Agent": "Googlebot/2.1"}
        sitemap_type = None
        sitemap_entries = None

        if url.endswith(".xml"):
            r  = self.req.http_request(url)
            if r.status_code == 200 and r.text:
                sitemap_type = "xml"
                soup = BeautifulSoup(r.text, features="xml")
                sitemap_tags = soup.find_all("sitemap")
                sitemap_entries = []
                
                if sitemap_tags:
                    sitemap_type = sitemap_type + " (sitemap)"
                else:
                    sitemap_type = sitemap_type + " (urlset)"
                    sitemap_tags = soup.find_all("urlset")
                
                for tag in sitemap_tags:
                        for loc in tag.find_all("loc"):
                            sitemap_entries.append(loc.text)      
        else:
            r  = self.req.http_request(url)
            if r.status_code == 200 and r.text:
                sitemap_type = "plaintext"
                sitemap_entries = r.text.splitlines()
        
        return {"Type": sitemap_type, "Location": url, "Entries": sitemap_entries}


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

        if not settings.dorks_file:
            raise EnumException(self, "A dictionary file must be specified with the flag --dorks-file", None)

        self.dorks_file = settings.dorks_file
        self.domain = settings.domain
        self.verbose = settings.verbose

        self.startPage = 0
        self.google_tld = settings.dorks_tld
        self.base_url = f"https://www.google.{self.google_tld}/search"

        self.req = RequestsUtility(self, headers=DorksComponent.HEADERS)

    def run(self):
        dorks = FileUtility(self, split=True, separator=";;").read_file(self.dorks_file)
        results = []

        entries = len(dorks)
        counter = 1

        for dork in dorks:
            if self.verbose:
                OutputWriter.print_info_text(f"Testing entry {counter}/{entries}", self)
                counter += 1

            if len(dork) == 2:
                str_dork, comment = dork
            else:
                str_dork = dork[0]
                comment = None

            payload = f"{DorksComponent.DORK_SITE_RESTRICTION}{self.domain} {str_dork}"
            params = {'q': payload, 'start': self.startPage * 10} 

            response = self.req.http_request(self.base_url, params=params)
            soup = BeautifulSoup(response.text,"html.parser")
            
            links = []
            for link in soup.find_all("a",{"href":True}):
                href = link["href"]
                if not href.startswith(DorksComponent.EXCLUDED_DOMAINS):
                    links.append(href)

            results.append(
                {
                    "Payload": str_dork,
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

        if not settings.brute_file:
            raise EnumException(self, "A dictionary file must be specified with the flag --brute-file", None)
        
        self.file = settings.brute_file
        self.included_http_codes = settings.brute_included_http_codes
        self.print_404 = settings.brute_print_404
        self.extensions = None
        self.url = settings.url
        self.threads = settings.threads
        self.verbose = settings.verbose
        self.req = RequestsUtility(self, settings, follow_redirects=True)

    def run(self):
        if self.verbose:
            OutputWriter.print_info_text(f"Detecting default 404 page", self)

        page_404 = self.get_page_404()
        exclude_url = page_404["Redirects"][-1] if page_404 else None
        exclude_size = page_404["Response Size"] if page_404 else None

        urls = FileUtility(self).read_file(self.file)
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as threadPool:
            threads = {threadPool.submit(self._worker, url, exclude_url, exclude_size): url for url in urls}
            completedCounter = 1
            urlCount = len(urls)

            for thread in concurrent.futures.as_completed(threads):
                if self.verbose:
                    OutputWriter.print_info_text(f"Threads completed: {completedCounter}/{urlCount}", self)
                    completedCounter += 1

                res = thread.result()
                if res:
                    results.append(thread.result())        
                else:
                    results.append((threads[thread], "No response"))

        return {
            "404 Generic Page": page_404,
            "Results": results
        }
    
    def _worker(self, url, exclude_url, exclude_size):
        if url.startswith("/"):
                url = url[1:]

        response = self.req.http_request(f"{self.url}/{url}")
        response_code = str(response.status_code)
        response_history = response.history
            
        if self.included_http_codes is None or (self.included_http_codes and response_code in self.included_http_codes):
                last_url = response_history[-1].url if response_history else response.url
                response_size = len(response.text)
                if (exclude_url and last_url == exclude_url) or (exclude_size and response_size == exclude_size):
                    if self.print_404:
                        return (url, "404 Page")
                else:
                    return(url, RequestsUtility.format_response_code(response))

    def get_page_404(self):
        random_url = "".join(random.choice(string.ascii_letters) for i in range(0, self.RANDOM_URL_LENGTH))
        url = self.url + "/" + random_url
        response = self.req.http_request(url)
        return{
            "Redirects": [u.url for u in response.history] if response.history else response.url,
            "Response Size": len(response.text) if response.text else 0
        }


class Scan():
    def __init__(self, app_name:str=None, args:list=None):
        self.settings = Settings(app_name, args)
        self.env = Environment()
        self.ow = OutputWriter()
        
        if self.settings.output_file:
            self.ow.set_output_file(self.settings.output_file)
        
        self.modules = {
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
            self.ow.print_app_banner()

        operations = self.settings.operations if self.settings.operations else self.modules.keys()
        for op in operations:
            try:
                if op in self.modules.keys():
                    module = self.modules[op](self.settings)
                    print(self.ow.get_banner(module))
                    print(self.ow.get_formatted_string(module.run()))
                else:
                    print(self.ow.get_error_string(f"Unknown operation {op}. Skipped"))
            except EnumException as e:
                print(self.ow.get_error_string(e.fullErrStr))
        self.ow.close_resources()

if __name__ == '__main__':
    Scan().run()
