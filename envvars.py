#-------------------------------------------------------------------------------
# Micro Server - Environment variables
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

import os
import sys

#-------------------------------------------------------------------------------
# cEnvVars
#-------------------------------------------------------------------------------
class cEnvVars:
	# Constants
	CMDSRV_HOST = "localhost"
	CMDSRV_PORT = 60000

	IPTABLES_4_OPEN  = "ACCEPT"
	IPTABLES_4_CLOSE = "LOG_DROP2"

	IPTABLES_6_OPEN  = "ACCEPT"
	IPTABLES_6_CLOSE = "LOG_DROP2"

	MS_IPTABLES_HOST = "localhost"
	MS_IPTABLES_PORT = 60001

	# Runtime
	verbose_debug = False

	# Returns the directory the current script (or interpreter) is running in
	def get_script_directory():
		path = os.path.realpath(sys.argv[0])
		if os.path.isdir(path):
			return path
		else:
			return os.path.dirname(path)

