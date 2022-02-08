#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# IPtables control API implemented as a micro service
#
# No sorting or paging features due to the small data set.
#
# curl -i -X DELETE localhost:60001/more
# curl -i -X GET    localhost:60001/more
# curl -i -X POST   localhost:60001/more
# curl -i -X PUT    localhost:60001/more
# curl -i --head    localhost:60001/more
#
# iptables -S INPUT
# iptables -t filter -L INPUT --line-numbers -n
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

import json, pprint, re, sys

from envvars      import cEnvVars
from httphandler  import cHttpError, cHttpRequest, cHttpResponse
from iptables     import cIPTables
from tcpserver    import ServerMain
from threading    import Lock, Thread

g_debug = False
g_http = "http"
g_lock = Lock()
g_version = "v1"

#-------------------------------------------------------------------------------
def constructGetMethodResponseData(ipvx, ipt, request, content_out):
	# rule set by key
	def extract_rule_1(lookup, src, dest, error_message):
		if lookup is None: raise cHttpError(request, 400, error_message)
		dest["rules"] = []
		for rule_number in lookup:
			pprint.pprint(dest)
			dest["rules"].append(src[rule_number])

	# rule with unique value
	def extract_rule_2(value, lookup, src, dest, error_message):
		rule_number = lookup.get(value, None)
		if rule_number is None: raise cHttpError(request, 400, error_message)
		dest["rules"] = [ src[rule_number] ]

	# construct the top level dictionary: ipv4 or ipv6
	content_out[ipvx] = { "datetime": ipt[ipvx]["datetime"], "rules": dict() }

	# is a single rule identified by request path part 4 (request.path_parts[3])
	if len(request.path_parts) >= 4:
		rule_number = int(request.path_parts[3])
		try:
			content_out[ipvx]["rules"] = [ ipt[ipvx]["rules"][rule_number] ]
		except:
			raise cHttpError(request, 404, "Invalid rule number")
		return

	# apply filter
	if request.filter_name is None:
		content_out[ipvx]["rules"] = ipt[ipvx]["rules"] # all rules
	elif request.filter_name == "action":
		action = {
		"accept": ipt[ipvx]["accept"],
		"drop": ipt[ipvx]["drop"]
		}
		extract_rule_1(action.get(request.filter_arg, None),
		               ipt[ipvx]["rules"],
		               content_out[ipvx],
		               "Invalid filter action. Valid actions: accept drop")
	elif request.filter_name == "comment":
		extract_rule_2(request.filter_arg,
		               ipt[ipvx]["bycomment"],
		               ipt[ipvx]["rules"],
		               content_out[ipvx],
		               "Comment not found.")
	elif request.filter_name == "port":
		if request.filter_arg is None: raise cHttpError(request, 400, "Port number missing")
		extract_rule_2(int(request.filter_arg),
		               ipt[ipvx]["byport"],
		               ipt[ipvx]["rules"],
		               content_out[ipvx],
		               "Port number not found.")
	elif request.filter_name == "protocol":
		protocol = {
		"icmp": ipt[ipvx]["icmp"],
		"tcp": ipt[ipvx]["tcp"],
		"udp": ipt[ipvx]["udp"]
		}
		extract_rule_1(protocol.get(request.filter_arg, None),
		               ipt[ipvx]["rules"],
		               content_out[ipvx],
		               "Invalid filter protocol. Valid protocols: icmp tcp udp")
	else:
		raise cHttpError(request, 400, "Invalid filter name. Valid names: action comment port protocol")

	if g_debug:
		print("====================================================================")
		pprint.pprint(content_out)
		print("--------------------------------------------------------------------")

#-------------------------------------------------------------------------------
# Construct action href's
def constructHrefs(ipvx, ipt, request):
	rules_in = ipt[ipvx]["rules"]
	bycomment = ipt[ipvx]["bycomment"]
	for comment in bycomment:
		rule_number = bycomment[comment]
		base_url = "{}://{}/{}/rules/{}/{}/".format(g_http, request.header_fields["Host"], g_version, ipvx, rule_number)
		rules_in[rule_number]["xopen"]  = base_url+"open"
		rules_in[rule_number]["xclose"] = base_url+"close"

#-------------------------------------------------------------------------------
def execOpenClose(request):
	if cEnvVars.verbose_debug:
		print("execOpenClose() {}".format(request.data_in))
	if len(request.path_parts) != 5:
		raise cHttpError(request, 400, "URI path is invalid for open/close")
	if request.path_parts[4] not in ["open", "close"]:
		raise cHttpError(request, 400, "Invalid operation. Valid operations: open close")

	rule_number = int(request.path_parts[3])
	try:
		with g_lock:
			if request.path_parts[4] == "open":
				cIPTables().open(int(request.path_parts[2][-1:]), rule_number)
			else:
				cIPTables().close(int(request.path_parts[2][-1:]), rule_number)
	except:
		raise cHttpError(request, 404, "Invalid rule number")

#-------------------------------------------------------------------------------
# Fetch content based on the path and filter arguments, return in json format
#
# Only one filter per request
#
# /v1/rules
# /v1/rules?action=[accept|drop]
# /v1/rules?protocol=[icmp|tcp|udp]
# /v1/rules/ipv4
# /v1/rules/ipv4?comment=Public_HTTPS
# /v1/rules/ipv6
# /v1/rules/ipv6?port=443
#
def getContent(request):
	with g_lock:
		ipt = cIPTables().rules()

	# construct the response content based on the URI and any filters
	content_out = dict()

	if len(request.path_parts)==2 or (len(request.path_parts)>2 and request.path_parts[2]=="ipv4"):
		constructHrefs("ipv4", ipt, request)
		constructGetMethodResponseData("ipv4", ipt, request, content_out)

	if len(request.path_parts)==2 or (len(request.path_parts)>2 and request.path_parts[2]=="ipv6"):
		constructHrefs("ipv6", ipt, request)
		constructGetMethodResponseData("ipv6", ipt, request, content_out)

	return json.dumps(content_out)

#-------------------------------------------------------------------------------
def handleDelete(request):
	raise cHttpError(request,
	                 400,
	                 "Deleting rules is not supported".format(request.method))

#-------------------------------------------------------------------------------
def handleGet(request):
	content = getContent(request)
	response = cHttpResponse()
	response.headerStatus(200)
	response.headerDefaults()
	response.setContent(content)
	response.construct()
	return response

#-------------------------------------------------------------------------------
def handleHead(request):
	content = getContent(request)
	response = cHttpResponse()
	response.headerStatus(200)
	response.headerDefaults()
	response.setContentLength(content)
	response.construct()
	return response

#-------------------------------------------------------------------------------
def handleInvalidMethod(request):
	raise cHttpError(request,
	                 400,
	                 "HTTP method '{}' not supported".format(request.method))

#-------------------------------------------------------------------------------
def handlePost(request):
	raise cHttpError(request,
	                 400,
	                 "Adding rules is not supported".format(request.method))

#-------------------------------------------------------------------------------
def handlePut(request):
	execOpenClose(request)
	response = cHttpResponse()
	response.headerStatus(200)
	response.headerDefaults()
	response.setContent("")
	response.construct()
	return response

#-------------------------------------------------------------------------------
def iptablesHandler(request):
	try:
		validatePath(request)
		switch = {
		"DELETE": handleDelete,
		"GET":    handleGet,
		"HEAD":   handleHead,
		"POST":   handlePost,
		"PUT":    handlePut,
		}
		return switch.get(request.method, handleInvalidMethod)(request)
	except cHttpError as e:
		return e.response

#-------------------------------------------------------------------------------
def validatePath(request):
	# validate path length
	if len(request.path_parts) < 2:
		raise cHttpError(request, 400, "URI path is invalid")

	# validate service version
	if request.path_parts[0] != "v1":
		raise cHttpError(request, 400, "Supported version: v1")

	# validate the resource path
	if request.path_parts[1] != "rules":
		raise cHttpError(request, 404, "Resource path {} not found".format(request.path))

	# resource path part 3 must be ipv4 or ipv6
	if len(request.path_parts) >= 3 and request.path_parts[2] not in ["ipv4", "ipv6"]:
		raise cHttpError(request, 404, "Resource path {} not found".format(request.path))

	# part 4 must be an integer
	if len(request.path_parts) >= 4:
		m = re.match(r'[0-9]+/?', request.path_parts[3])
		if not m: raise cHttpError(request, 404, "Resource path {} not found".format(request.path))

	# >5 too many parts
	if len(request.path_parts) > 5:
		raise cHttpError(request, 400, "URI path is invalid")

#-------------------------------------------------------------------------------
if __name__ == "__main__":
	exit_code = 0
	try:
		if len(sys.argv) > 1 and sys.argv[1] == "-v":
			cEnvVars.verbose_debug = True
		ServerMain("IPTables", iptablesHandler)
	except Exception as error:
		print("FATAL Exception:", error)
		exit_code = 1
	sys.exit(exit_code)

