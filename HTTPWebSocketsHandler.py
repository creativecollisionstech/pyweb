'''
The MIT License (MIT)

Copyright (C) 2014, 2015 Seven Watt <info@sevenwatt.com>
<http://www.sevenwatt.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import json
from SimpleHTTPServer import SimpleHTTPRequestHandler
import struct
from base64 import b64encode
from hashlib import sha1
from mimetools import Message
import os
import posixpath
from StringIO import StringIO
import errno, socket #for socket exceptions
import threading
import urllib
import re

# **** Local Imports ****
from JsonMessage import *
from LogHelper import *
from NomatykConfiguration import *
from NomatykControllers import *

# TODO: Move the nomatyk logic into it's own so don't have to import
#       the main program.
from nomatyk import *

PATH_GET_IMAGES = '/get_images'
PATH_GET_MANAGED_FOLDERS = '/get_managed_folders'

DEBUG_FILE_UPLOAD = False
DEFAULT_TIME_SPAN = -1

controller_paths = [ PATH_GET_IMAGES, PATH_GET_MANAGED_FOLDERS ]

def manageUploadFile(sourcePath):

    logger = LogHelper( "Nomatyk", "test.log", "." )

    # Create an array to keep track of the destination directories
    destination_paths = []
    destination_paths.append( "/Users/pfarrell/Pictures/NomatykTest" )

    nomatyk_media_manager = NomatykMediaManager( sourcePath, destination_paths, -1, logger )

    media_info_json = nomatyk_media_manager.getMediaInfoForFile( sourcePath )

    # Send a message that indicates how many files we are about to transfer so client/UI can update
    #  their status as we continue along.
    message = JsonMessage.createMediaStatusMessage( media_info_json )
    logger.nomatyk( json.dumps( message ) )

    result = nomatyk_media_manager.manageFiles( media_info_json )


class WebSocketError(Exception):
    pass

class HTTPWebSocketsHandler(SimpleHTTPRequestHandler):
    _ws_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    _opcode_continu = 0x0
    _opcode_text = 0x1
    _opcode_binary = 0x2
    _opcode_close = 0x8
    _opcode_ping = 0x9
    _opcode_pong = 0xa

    mutex = threading.Lock()
    
    def on_ws_message(self, message):
        """Override this handler to process incoming websocket messages."""
        pass
        
    def on_ws_connected(self):
        """Override this handler."""
        pass
        
    def on_ws_closed(self):
        """Override this handler."""
        pass
        
    def send_message(self, message):
        self._send_message(self._opcode_text, message)

    def setup(self):
        SimpleHTTPRequestHandler.setup(self)
        self.connected = False
                
    # def finish(self):
        # #needed when wfile is used, or when self.close_connection is not used
        # #
        # #catch errors in SimpleHTTPRequestHandler.finish() after socket disappeared
        # #due to loss of network connection
        # try:
            # SimpleHTTPRequestHandler.finish(self)
        # except (socket.error, TypeError) as err:
            # self.log_message("finish(): Exception: in SimpleHTTPRequestHandler.finish(): %s" % str(err.args))

    # def handle(self):
        # #needed when wfile is used, or when self.close_connection is not used
        # #
        # #catch errors in SimpleHTTPRequestHandler.handle() after socket disappeared
        # #due to loss of network connection
        # try:
            # SimpleHTTPRequestHandler.handle(self)
        # except (socket.error, TypeError) as err:
            # self.log_message("handle(): Exception: in SimpleHTTPRequestHandler.handle(): %s" % str(err.args))

    def checkAuthentication(self):

        auth = self.headers.get('Authorization')
        if auth != "Basic %s" % self.server.auth:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Plugwise"')
            self.end_headers();
            return False
        return True
        
    def do_GET(self):

        if self.headers.get("Upgrade", None) == "websocket":

            self._handshake()
            #This handler is in websocket mode now.
            #do_GET only returns after client close or socket error.
            self._read_messages()
        else:
            SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        """Serve a POST request."""

        r, info = self.handle_post_data()

        print r, info, "by: ", self.client_address

        # Check the result of the how the post data was handled
        #  and if there was an error, send it back to the user
        if r == True:
            """
            We just want to tell the client that everything with the file upload
            went okay and send them a JSON message back for how to deal with the result.
            """

            file_path = info
            basepath, filename = os.path.split(file_path)

            f = StringIO()
            # Redirect the user back to the gallery file.
            f_redirect_file = open( "../../public/index.html", "r" )

            f.write( f_redirect_file.read() )
            f_redirect_file.close()

            length = f.tell()
            f.seek(0)

            self.send_response(302)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(length))
            self.end_headers()

            if f:
                self.copyfile(f, self.wfile)
                f.close()

        else:
            # Send 500 that there was an error
            message_response = JsonMessage.createErrorMessage( "reply", "upload_complete", "File could not be written")

            f = StringIO()
            f.write(json.dumps(message_response))

            length = f.tell()
            f.seek(0)

            self.send_response(500)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", str(length))
            self.end_headers()

            if f:
                self.copyfile(f, self.wfile)
                f.close()

    def handle_post_data(self):
        """
        Handles the data coming in a POST for file upload
        """

        boundary = self.headers.plisttext.split("=")[1]
        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)

        if DEBUG_FILE_UPLOAD == True:
            print( "boundary (%d) = %s" % (len(boundary), boundary) )
            print( "line (%d)= %s" % (len(line), line) )

        if not boundary in line:
            return (False, "Content does NOT begin with boundary")

        line = self.rfile.readline()
        remainbytes -= len(line)

        if DEBUG_FILE_UPLOAD == True:
            print( "line (%d) 1: %s" % (len(line), line) )

        fn = re.findall(r'Content-Disposition.*name="(.*)"; filename="(.*)"', line)
        if not fn:
            return (False, "Can't find out file name...")
        else:
            if DEBUG_FILE_UPLOAD == True:
                print fn

        input_name = fn[0][0]
        file_name = fn[0][1]

        line = self.rfile.readline()
        if DEBUG_FILE_UPLOAD == True:
            print( "line (%d) 2: %s" % (len(line), line) )

        remainbytes -= len(line)
        line = self.rfile.readline()
        remainbytes -= len(line)
        if DEBUG_FILE_UPLOAD == True:
            print( "line (%d) 3: %s" % (len(line), line) )

        # First we need to check if the upload folder exists and if not create it.
        upload_folder_path = "/Users/pfarrell/projects/ccg/MediaManagerCore/public"

        if upload_folder_path == None:
            return (False, "Cannot create upload folder")

        # Second we need to check if there already is a file present in the upload folder
        #  that has the same name.
        #file_name = TM1FileConvertHelper.checkAndAdjustFileName(upload_file_path)

        # Adjust the upload file path incase there was a change to the filename because of
        #  a duplicate file.
        print "upload_folder_path = %s" % upload_folder_path
        print "file_name = %s" % file_name
        upload_file_path = os.path.join(upload_folder_path, file_name)

        try:
            print "opening file with path, upload_file_path = %s " % upload_file_path 

            out = open(upload_file_path, 'wb')
        except IOError:
            return (False, "Can't create file to write, do you have permission to write?")

        preline = self.rfile.readline()
        remainbytes -= len(preline)

        if DEBUG_FILE_UPLOAD == True:
            print( "preline (%d) 3: %s" % (len(preline), preline) )
            print( "remainbytes = %d" % remainbytes )

        # Now receive the bytes for the file and write them to the open file descriptor
        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)

            if boundary in line:
                preline = preline[0:-1]

                if preline.endswith('\r'):
                    preline = preline[0:-1]

                out.write(preline)
                out.close()

                # TODO: Move this somewhere better
                print "calling manageUploadFile"
                manageUploadFile( upload_file_path )

                # Return success and the name of the file we just uploaded
                return (True, file_name)
            else:
                out.write(preline)
                preline = line

        return (False, "Unexpect Ends of data.")
                 
    def _read_messages(self):

        while self.connected == True:
            try:
                self._read_next_message()
            except (socket.error, WebSocketError), e:
                #websocket content error, time-out or disconnect.
                self.log_message("RCV: Close connection: Socket Error %s" % str(e.args))
                self._ws_close()
            except Exception as err:
                #unexpected error in websocket connection.
                self.log_error("RCV: Exception: in _read_messages: %s" % str(err.args))
                self._ws_close()

    def _read_next_message(self):
        #self.rfile.read(n) is blocking.
        #it returns however immediately when the socket is closed.
        try:
            self.opcode = ord(self.rfile.read(1)) & 0x0F
            length = ord(self.rfile.read(1)) & 0x7F
            if length == 126:
                length = struct.unpack(">H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self.rfile.read(8))[0]
            masks = [ord(byte) for byte in self.rfile.read(4)]
            decoded = ""
            for char in self.rfile.read(length):
                decoded += chr(ord(char) ^ masks[len(decoded) % 4])
            self._on_message(decoded)
        except (struct.error, TypeError) as e:
            #catch exceptions from ord() and struct.unpack()
            if self.connected:
                raise WebSocketError("Websocket read aborted while listening")
            else:
                #the socket was closed while waiting for input
                self.log_error("RCV: _read_next_message aborted after closed connection")
                pass
        
    def _send_message(self, opcode, message):

        try:
            #use of self.wfile.write gives socket exception after socket is closed. Avoid.
            self.request.send(chr(0x80 + opcode))
            length = len(message)
            if length <= 125:
                self.request.send(chr(length))
            elif length >= 126 and length <= 65535:
                self.request.send(chr(126))
                self.request.send(struct.pack(">H", length))
            else:
                self.request.send(chr(127))
                self.request.send(struct.pack(">Q", length))
            if length > 0:
                self.request.send(message)

        except socket.error, e:
            #websocket content error, time-out or disconnect.
            self.log_message("SND: Close connection: Socket Error %s" % str(e.args))
            self._ws_close()
        except Exception as err:
            #unexpected error in websocket connection.
            self.log_error("SND: Exception: in _send_message: %s" % str(err.args))
            self._ws_close()

    def _handshake(self):

        headers=self.headers
        if headers.get("Upgrade", None) != "websocket":
            return
        key = headers['Sec-WebSocket-Key']
        digest = b64encode(sha1(key + self._ws_GUID).hexdigest().decode('hex'))
        self.send_response(101, 'Switching Protocols')
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', str(digest))
        self.end_headers()
        self.connected = True
        #self.close_connection = 0
        self.on_ws_connected()
    
    def _ws_close(self):

        #avoid closing a single socket two time for send and receive.
        self.mutex.acquire()
        try:
            if self.connected:
                self.connected = False
                #Terminate BaseHTTPRequestHandler.handle() loop:
                self.close_connection = 1
                #send close and ignore exceptions. An error may already have occurred.
                try: 
                    self._send_close()
                except:
                    pass
                self.on_ws_closed()
            else:
                self.log_message("_ws_close websocket in closed state. Ignore.")
                pass
        finally:
            self.mutex.release()
            
    def _on_message(self, message):
        #self.log_message("_on_message: opcode: %02X msg: %s" % (self.opcode, message))
        
        # close
        if self.opcode == self._opcode_close:
            self.connected = False
            #Terminate BaseHTTPRequestHandler.handle() loop:
            self.close_connection = 1
            try:
                self._send_close()
            except:
                pass
            self.on_ws_closed()
        # ping
        elif self.opcode == self._opcode_ping:
            _send_message(self._opcode_pong, message)
        # pong
        elif self.opcode == self._opcode_pong:
            pass
        # data
        elif (self.opcode == self._opcode_continu or 
                self.opcode == self._opcode_text or 
                self.opcode == self._opcode_binary):
            self.on_ws_message(message)

    def _send_close(self):

        #Dedicated _send_close allows for catch all exception handling
        msg = bytearray()
        msg.append(0x80 + self._opcode_close)
        msg.append(0x00)
        self.request.send(msg)

    def translate_path(self, path):
        """This function translates the path that is inside of the html file to
           a path based on where we have specified the HTML files to be."""

        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = self.base_path

        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            path = os.path.join(path, word)

        return path
