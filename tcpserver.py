#-------------------------------------------------------------------------------
# Micro Service threaded socket server
#
# Copyright (c) 2022 Robert I. Gike
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------

import socket
import socketserver
import sys
import threading
import time

from envvars import cEnvVars
from httphandler import cHttpRequest, cHttpResponse

g_debug         = False
g_handler       = None
g_request_count = 0
g_shutdown      = False

#-------------------------------------------------------------------------------
class cThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
	def handle(self):
		global g_request_count, g_shutdown
		g_request_count += 1
		try:
			request = cHttpRequest(self.request.recv(1024))
			request.printDataIn()
			if g_handler is None:
				response = cHttpResponse("Request from {}\r\n".format(self.client_address))
			else:
				response = g_handler(request)
			if g_debug: response.printDataOut()
			self.request.sendall(response.bytesOut())
		except Exception as error:
			print(error)
			output = "Exception!"
			g_shutdown = True

#-------------------------------------------------------------------------------
class cThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True

#-------------------------------------------------------------------------------
def ServerMain(service_name, handler=None):
	global g_handler, g_request_count, g_shutdown
	g_handler = handler

	server = cThreadedTCPServer((cEnvVars.MS_IPTABLES_HOST, cEnvVars.MS_IPTABLES_PORT), cThreadedTCPRequestHandler)

	# start the server thread
	# additional threads will created to handle each request
	server_thread = threading.Thread(target=server.serve_forever)

	# exit the server thread when the main thread terminates
	server_thread.daemon = True
	server_thread.start()
	print("Micro Service {} running in: {}".format(service_name, server_thread.name))

	loop_count = 0
	while not g_shutdown:
		try:
			time.sleep(5)
			loop_count += 1
		except KeyboardInterrupt:
			print("\nKeyboardInterrupt: loop count={} requests={}".format(loop_count,g_request_count))
			g_shutdown = True

	print("Micro Service {} shutdown now".format(service_name))
	server.shutdown()

