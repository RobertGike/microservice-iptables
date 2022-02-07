#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# Format and print json response data from curl
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

import json, os, pprint, sys

if os.isatty(sys.stdin.fileno()):
    print("Usage: curl -i -s -X GET http://localhost:60001/v1/rules |", sys.argv[0])
    print("       curl -i -s -X GET http://localhost:60001/v1/rules/ipv4 |", sys.argv[0])
    print("       curl -i -s -X GET http://localhost:60001/v1/rules/ipv4/5 |", sys.argv[0])
    print("       curl -i -s -X PUT http://localhost:60001/v1/rules/ipv4/5/open |", sys.argv[0])
else:
	for line in sys.stdin:
		if line[0:1] == '{':
			pprint.pprint(json.loads(line), width=200) # sort_dicts=False added in v3.8
		else:
			print(line[:-2])

