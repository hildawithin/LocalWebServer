#!/usr/bin/env python2.7

'''
This is a simple HTTP server only serves GET command.

The GetHTTPServer class has BaseHTTPServer embedded in. 
Specifically the following methods are from BaseHTTPServer:
(1) date_time_string
(2) handle
(3) send_error
(4) _quote_html
(5) send_header (adapted for spefic usage in this lab)
(6) version_string

Other methods are written specifically for this lab.

Aagin this is lab code. Not intended for real-world application.

'''

__version__ = "0.1"

__all__ = ["GetHTTPRequestHandler", "ThreadedTCPServer"]

import sys
import os
# from datetime import datetime
import socket
import time
import shutil
import SocketServer
import mimetools
import threading # for synchronization

# Default error message template
DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Error response</title>
</head>
<body>
<h1>Error response</h1>
<p>Error code %(code)d.
<p>Message: %(message)s.
<p>Error code explanation: %(code)s = %(explain)s.
</body>
"""

DEFAULT_ERROR_CONTENT_TYPE = "text/html"

def _quote_html(html):
    return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

class GetHTTPRequestHandler(SocketServer.StreamRequestHandler):
    '''
    The protocol
    recognizes three parts of a request:

    1. One line identifying the request type and path
    2. An optional set of RFC-822-style headers
    3. An optional data part

    The headers and data are separated by a blank line.

    The first line of the request has the form

    <command> <path> <version>

    where <command> is a (case-sensitive) keyword such as GET or POST,
    <path> is a string containing path information for the request,
    and <version> should be the string "HTTP/1.0" or "HTTP/1.1".

    Note: 
    (1) The command this server is going to handle is limited to GET only
    and it is case sensitive;
    (2) If the version is left out blank, we consider the request as "bad".


    The reply form of the HTTP 1.x protocol again has three parts:

    1. One line giving the response code
    2. An optional set of RFC-822-style headers
    3. The data
    '''
    sys_version = "Python/" + sys.version.split()[0]
    server_version = "GetHTTP/" + __version__
    default_request_version = "HTTP/1.0"
    root_dir = 'Upload' # Get items from UPLOAD directory and its subdirectories

    def parse(self):
        """
        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.
        """
        self.command = None
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        HTTPREQUEST = self.raw_requestline
        print(HTTPREQUEST)
        HTTPREQUEST = HTTPREQUEST.rstrip('\r\n')
        self.requestline = HTTPREQUEST
        fields = HTTPREQUEST.split()
        if len(fields) == 3:
            # only the header line is transmitted
            command, path, version = fields
            if version not in ['HTTP/1.0', 'HTTP/1.1']:
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            if command != 'GET':
                self.send_error(405, "Unsupported command (%r)" % command)
                return False
        elif len(fields) <= 2:
            self.send_error(400, "Bad request syntax (%r)" % HTTPREQUEST)
            return False
        self.command, self.path, self.request_version = command, path, version

        # Check header of the request
        self.headers = self.MessageClass(self.rfile, 0)

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.0"):
            self.close_connection = 0
        return True
    
    def guess_content_type(self, path):
        base = path.split('/')
        ext = base[-1].split('.')
        ext = ext[-1]
        if len(ext) < 1 :
            return 'text/html'
        content_type = ext.lower()
        if content_type in ['html', 'htm']:
            return 'text/html'
        elif content_type in ['txt', 'text', 'py', 'h', 'c']:
            return 'text/plain'
        elif content_type in ['jpeg', 'jpg']:
            return 'image/jpeg'
        elif content_type in ['png']:
            return 'image/png'
        elif content_type in ['gif']:
            return 'image/gif'
        elif content_type in ['pdf']:
            return 'application/pdf'
        elif content_type in ['zip']:
            return 'application/zip'
        else:
            return None

    def get_all_files(self, dir):
        list_file = os.listdir(dir)
        allfiles = []
        entry_list = []
        for entry in list_file:
            fullpath = os.path.join(dir, entry)
            if os.path.isdir(fullpath):
                a, b = self.get_all_files(fullpath)
                allfiles = allfiles + a
                entry_list = entry_list + b
            else:
                allfiles.append(fullpath)
                entry_list.append(entry)
        return (allfiles, entry_list)

    def get(self):
        ctype = self.guess_content_type(self.path)
        # print(ctype)
        if ctype==None:
            # set to default
            ctype = 'text/html'
        strt = self.path.rfind('/')
        if len(self.path) == strt + 1:
            # if no explicit filename present, return base html
            f = open("Upload/index.html",'rb')
        else:
            # locate the requested file
            file_to_find = self.path[strt+1:len(self.path)]
            # files = os.listdir('Upload')
            filepaths, files = self.get_all_files(self.root_dir)
            if file_to_find in files:
                fp = filepaths[files.index(file_to_find)]
                # check file permission 
                if os.access(fp, os.R_OK):
                    f = open(fp,'rb')
                else:
                    self.send_error(401)
                    return None
            else:
                self.send_error(404)
                return None
        try:
            self.send(status_code=200, message=None)
            self.send_header("Content-Type", ctype)
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.wfile.write("\r\n")
        except:
            f.close()
            raise
        if f:
            try:
                shutil.copyfileobj(f, self.wfile)
            finally:
                f.close()

    def handle_one_get(self):
        # print("handle one get request ..")
        
        # handle a single HTTP GET request.
        try:
            # read in the request
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                # request too long
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                # empty request
                self.close_connection = 1
                return
            if not self.parse():
                # error in parsing
                # command error also handled explicitly during parsing
                return
            
            # GET is the only command we are going to handle 
            self.get()
            self.wfile.flush() # actually send the response if not already done.
        except socket.timeout as e:
            print("Request timed out: %r", e)
            self.close_connection = 1
            return

    # overriding the handle method for BaseRequestHandler
    def handle(self):
        self.close_connection = 1
        cur_thread = threading.current_thread()
        print(cur_thread.name)
        self.handle_one_get()
        while not self.close_connection:
            self.handle_one_get()
        ''' For testing multithread'''
        # data = self.request.recv(1024)
        # cur_thread = threading.current_thread()
        # response = "{}: {}".format(cur_thread.name, data)
        # self.request.sendall(response)

    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE
 
    protocol_version = "HTTP/1.0"

    MessageClass = mimetools.Message
 
    # Only 200, 400, 401, 404, 405 is used for this lab
    responses = {
        100: ('Continue', 'Request received, please continue'),
        101: ('Switching Protocols',
              'Switching to new protocol; obey Upgrade header'),

        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted',
              'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
        204: ('No Content', 'Request fulfilled, nothing follows'),
        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),

        300: ('Multiple Choices',
              'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified',
              'Document has not changed since given time'),
        305: ('Use Proxy',
              'You must use proxy specified in Location to access this '
              'resource.'),
        307: ('Temporary Redirect',
              'Object moved temporarily -- see URI list'),

        400: ('Bad Request',
              'Bad request syntax or unsupported method'),
        401: ('Unauthorized',
              'No permission -- see authorization schemes'),
        402: ('Payment Required',
              'No payment -- see charging schemes'),
        403: ('Forbidden',
              'Request forbidden -- authorization will not help'),
        404: ('Not Found', 'Nothing matches the given URI'),
        405: ('Method Not Allowed',
              'Specified method is invalid for this resource.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required', 'You must authenticate with '
              'this proxy before proceeding.'),
        408: ('Request Timeout', 'Request timed out; try again later.'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone',
              'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',
              'Cannot satisfy request range.'),
        417: ('Expectation Failed',
              'Expect condition could not be satisfied.'),

        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Not Implemented',
              'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service Unavailable',
              'The server cannot process the request due to a high load'),
        504: ('Gateway Timeout',
              'The gateway server did not receive a timely response'),
        505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
        }
    
    def send_error(self, status_code, message=None):
        try:
            short, full = self.responses[status_code]
        except KeyError:
            short, full = '???', '???'
        if message is None:
            message = short
        explain = full
        # print("code %d, message %s", status_code, message)
        self.send(status_code, message)
        self.send_header('Connection', 'close')
        
        # message body
        content = None
        if status_code >= 200 and status_code not in (204, 205, 304):
            # HTML encode to prevent Cross Site Scripting attacks
            # (see bug #1100201)
            content = (self.error_message_format % {
                'code': status_code,
                'message': _quote_html(message),
                'explain': explain
            })
            self.send_header("Content-Type", self.error_content_type)
        self.wfile.write("\r\n")

        if content:
            self.wfile.write(content)

    def send(self, status_code, message, content_type=None, data=None):
        # write message to the buffer 
        if message is None: 
            if status_code in self.responses:
                message = self.responses[status_code][0]
            else:
                message = ''
        self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, status_code, message))
        # print (self.protocol_version, status_code, message)
        # if content_type == None:
        #     content_type = 'text/html'

        # automatic headers: server, date
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())#datetime.now().strftime('%a, %B %d, %Y %I:%M%p'))
        # self.send_header('Content-Type', content_type)
        # self.send_header('Content-Length', len(data))
        # self.wfile.write("\r\n")
    
    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))
        # close the channel if asked to 
        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = 1
            elif value.lower() == 'keep-alive':
                self.close_connection = 0

    def version_string(self):
        return self.server_version+ ' ' + self.sys_version
    
    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

# for synchronization and lock a thread in use
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

# for testing only
def client(addr, port, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    try:
        s.sendall(message)
        response = s.recv(1024)
        print("Received: {}".format(response))
    finally:
        s.close()

def test(HandlerClass = GetHTTPRequestHandler,
         ServerClass = ThreadedTCPServer, protocol="HTTP/1.0"):
    if sys.argv[1:]:
        PORT = int(sys.argv[1])
    else:
        PORT = 50000
    
    HOST = '10.187.72.62'# socket.gethostbyname(socket.gethostname())
    server_address = (HOST, PORT)
    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...")
    httpd.serve_forever()

''' For testing multithread
    # HOST, PORT = "localhost", 0

    # server = ServerClass((HOST, PORT), HandlerClass)
    # ip, port = server.server_address

    # # Start a thread with the server -- that thread will then start one
    # # more thread for each request
    # server_thread = threading.Thread(target=server.serve_forever)
    # # Exit the server thread when the main thread terminates
    # server_thread.daemon = True
    # server_thread.start()
    # print "Server loop running in thread:", server_thread.name

    # client(ip, port, "Hello World 1")
    # client(ip, port, "Hello World 2")
    # client(ip, port, "Hello World 3")

    # server.shutdown()
    # server.server_close()
'''

if __name__ == '__main__':
    test()