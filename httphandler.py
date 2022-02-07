#-------------------------------------------------------------------------------
# Micro Server - HTTP request and response types
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

import datetime, json, pprint, re, sys, time

from envvars import cEnvVars

#-------------------------------------------------------------------------------
# cHttpError
#-------------------------------------------------------------------------------
class cHttpError(Exception):
	def __init__(self, request, status, message):
		self.response = cHttpResponse()
		self.response.headerStatus(status)
		self.response.headerDefaults()
		self.response.errorResponse(instance=request.path, detail=message)
		self.response.construct()

#-------------------------------------------------------------------------------
# cHttpRequest
#-------------------------------------------------------------------------------
class cHttpRequest:
	def __init__(self, data):
		self.data_in = str(data, "ascii")
		lines = self.data_in.split('\n')
		self.extractMethodPath(lines.pop(0))
		self.extractHeaderFields(lines)
		self.splitPath()
		self.extractFilter()

	def extractFilter(self):
		self.filter_name = None
		self.filter_arg = None
		if self.path_args is not None:
			filter_parts = self.path_args.split('=')
			if len(filter_parts)>0:
				self.filter_name = filter_parts[0]
			if len(filter_parts)>1 and len(filter_parts[1])>0:
				self.filter_arg = filter_parts[1]
		if cEnvVars.verbose_debug:
			print("filter: name {} arg {}".format(self.filter_name, self.filter_arg))

	def extractHeaderFields(self, lines):
		self.header_fields = dict()
		for line in lines:
			# drop the trailing '\r'
			m = re.match(r'([^:]+):[\s]?(.*)$', line[:-1])
			if(m):
				self.header_fields[m.group(1)] = m.group(2)
			else:
				pass # error malformed header field?

	def extractMethodPath(self, line):
		m = re.match(r'([^\s]+)\s([^\s]+)\s', line)
		if(m):
			self.method = m.group(1)
			self.path = m.group(2)
		else:
			pass # error malformed request?

	def printDataIn(self):
		print(self.data_in)
		#print(self.method)
		#print(self.path)
		#pprint.pprint(self.header_fields, width=128)

	def splitPath(self):
		path_args = self.path.split('?')
		self.path_args = path_args[1] if len(path_args)>1 else None
		self.path_parts = path_args[0].split('/')
		self.path_parts.pop(0) # discard (always) empty part
		if cEnvVars.verbose_debug:
			pprint.pprint(self.path_args)
			pprint.pprint(self.path_parts)

#-------------------------------------------------------------------------------
# cHttpResponse
#-------------------------------------------------------------------------------
class cHttpResponse:
	def __init__(self, data=""):
		self.content_out = None
		self.data_out = data
		self.header_lines = dict()

	def bytesOut(self):
		return(bytes("{}".format(self.data_out), "ascii"))

	def construct(self):
		self.data_out += self.header_status
		for k in sorted(self.header_lines):
			self.data_out += "{}: {}\r\n".format(k, self.header_lines[k])
		self.data_out += "\r\n"
		if self.content_out is not None: self.data_out += self.content_out

	def headerDefaults(self):
		self.header_lines["Cache-Control"] = "no-cache"
		self.header_lines["Content-Type"] = "application/json; charset=utf-8"
		self.header_lines["Content-Length"] = 0
		self.header_lines["Date"] = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")

	def headerStatus(self, status):
		self.status = status
		self.header_status = "HTTP/1.1 {} {}\r\n".format(status, self.standardResponseText(status))

	def printDataOut(self):
		print(self.data_out)

	def errorResponse(self, **kwargs):
		details = { "status": self.status }
		for kw in kwargs:
			details[kw] = kwargs[kw]

		# handle missing "type" value
		kw_type = details.get("type", None)
		if kw_type is None:
			#details["type"] = "about:blank"
			details["title"] = self.standardResponseText(self.status)

		# construct JSON content
		self.content_out = json.dumps(details)
		self.content_out += "\r\n"
		self.header_lines["Content-Length"] = len(self.content_out)

# See RFC7807
#{
#    "type": "/errors/incorrect-user-pass",
#    "title": "Incorrect username or password.",
#    "status": 401,
#    "detail": "Authentication failed due to incorrect username or password.",
#    "instance": "/login/log/abc123"
#}

	def setContent(self, content):
		self.content_out = content
		self.header_lines["Content-Length"] = len(self.content_out)

	# set the content length for method HEAD
	def setContentLength(self, content):
		self.header_lines["Content-Length"] = len(content)

	def standardResponseText(self, status):
		switch = {
		200: "OK",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		500: "Internal Server Error",
		503: "Service Unavailable",
		}
		return switch.get(status, "Internal Server Error")

