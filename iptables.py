#-------------------------------------------------------------------------------
# IP Tables Control
#
# Parse IPv4 and IPv6 rules
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

import datetime, json, os, pprint, re, subprocess, sys, traceback

from envvars import cEnvVars

sample_rules_ipv4 = """
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -i enp1s0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i enp1s0 -p icmp -m icmp --icmp-type 8 -m comment --comment Public_ECHO -j ACCEPT
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 22 -m comment --comment Public_SSH -j ACCEPT
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 80 -m comment --comment Public_HTTP -j LOG_DROP2
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 443 -m comment --comment Public_HTTPS -j LOG_DROP2
-A INPUT -d 224.0.0.1/32 -i enp1s0 -j LOG_DROP3
-A INPUT -i enp1s0 -p udp -m udp --dport 137 -j LOG_DROP2
-A INPUT -i enp1s0 -p udp -m udp --dport 138 -j LOG_DROP2
-A INPUT -j LOG_DROP2
"""

sample_rules_ipv6 = """
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -i enp1s0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i enp1s0 -p ipv6-icmp -m comment --comment Public_ICMP -j LOG_DROP2
-A INPUT -s fe80::/10 -i enp1s0 -p udp -m state --state NEW -m udp --dport 546 -m comment --comment DHCP_546 -j ACCEPT
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 22 -m comment --comment Public_SSH -j ACCEPT
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 80 -m comment --comment Public_HTTP -j LOG_DROP2
-A INPUT -i enp1s0 -p tcp -m state --state NEW -m tcp --dport 443 -m comment --comment Public_HTTPS -j LOG_DROP2
-A INPUT -j LOG_DROP2
"""

#-------------------------------------------------------------------------------
# cIPTables
#-------------------------------------------------------------------------------
class cIPTables:
	def __init__(self):
		self.is_root = True if os.getuid()==0 else False
		self.fetch_ipv4_rules()
		self.fetch_ipv6_rules()

	def close(self, ver, rule_number):
		if ver not in [4, 6]: raise Exception("cIPTables.close() IP version {}", ver)
		if ver == 4:
			close_rule = self.update_action(self.ipv4_rules["rules"][rule_number]["text"], cEnvVars.IPTABLES_4_CLOSE)
			command = "/sbin/iptables -R INPUT {} {}".format(rule_number, close_rule)
		else:
			close_rule = self.update_action(self.ipv6_rules["rules"][rule_number]["text"], cEnvVars.IPTABLES_6_CLOSE)
			command = "/sbin/ip6tables -R INPUT {} {}".format(rule_number, close_rule)

		if self.is_root:
			ret = exec(command)
		else:
			print("cIPTables.close():", command)

	def fetch_ipv4_rules(self):
		if self.is_root:
			ret = exec("/sbin/iptables -S INPUT")
			self.ipv4_rules = self.parse_iptables_rules(ret["stdout"])
		else:
			self.ipv4_rules = self.parse_iptables_rules(sample_rules_ipv4)
		if cEnvVars.verbose_debug: pprint.pprint(self.ipv4_rules, width=160)

	def fetch_ipv6_rules(self):
		if self.is_root:
			ret = exec("/sbin/ip6tables -S INPUT")
			self.ipv6_rules = self.parse_iptables_rules(ret["stdout"])
		else:
			self.ipv6_rules = self.parse_iptables_rules(sample_rules_ipv6)
		if cEnvVars.verbose_debug: pprint.pprint(self.ipv6_rules, width=160)

	def open(self, ver, rule_number):
		if ver not in [4, 6]: raise Exception("cIPTables.open() IP version {}", ver)
		if ver == 4:
			open_rule = self.update_action(self.ipv4_rules["rules"][rule_number]["text"], cEnvVars.IPTABLES_4_OPEN)
			command = "/sbin/iptables -R INPUT {} {}".format(rule_number, open_rule)
		else:
			open_rule = self.update_action(self.ipv6_rules["rules"][rule_number]["text"], cEnvVars.IPTABLES_6_OPEN)
			command = "/sbin/ip6tables -R INPUT {} {}".format(rule_number, open_rule)

		if self.is_root:
			ret = exec(command)
		else:
			print("cIPTables.open():", command)

	def parse_iptables_rules(self, text):
		rules_in = text.split('\n')
		#if cEnvVars.verbose_debug: pprint.pprint(rules_in)
		rules_out = {
		"datetime":  datetime.datetime.utcnow().strftime("%Y.%m.%d-%H:%M:%S.%f UTC"),
		"rules":     [],
		"accept":    [],
		"drop":      [],
		"icmp":      [],
		"tcp":       [],
		"udp":       [],
		"bycomment": dict(),
		"byport":    dict(),
		}
		rule_number = 0
		for line in rules_in:
			if len(line) < 4: continue
			# ACCEPT rules
			m = re.search(r'-j\sACCEPT', line)
			if m: rules_out["accept"].append(rule_number)
			# LOG_DROP rules
			m = re.search(r'-j\sLOG_DROP', line)
			if m: rules_out["drop"].append(rule_number)
			# icmp protocol rules
			m = re.search(r'-p\sicmp|-p\sipv6-icmp', line)
			if m: rules_out["icmp"].append(rule_number)
			# tcp protocol rules
			m = re.search(r'-p\stcp', line)
			if m: rules_out["tcp"].append(rule_number)
			# udp protocol rules
			m = re.search(r'-p\sudp', line)
			if m: rules_out["udp"].append(rule_number)
			# lookup by comment
			m = re.search(r'--comment\s([^\s]+)', line)
			if m: rules_out["bycomment"][m.group(1)] = int(rule_number)
			# lookup by port
			m = re.search(r'--dport\s([^\s]+)', line)
			if m: rules_out["byport"][int(m.group(1))] = int(rule_number)
			# the rule text
			rules_out["rules"].append({"number": rule_number, "text": line})
			rule_number += 1
		return rules_out

	def rules(self):
		return { "ipv4": self.ipv4_rules, "ipv6": self.ipv6_rules }

	def update_action(self, rule, action):
		m = re.match(r'^-A\sINPUT\s(.*)\s-j\s(.+)$', rule)
		if m:
			return m.group(1)+" -j "+action
		else:
			raise Exception("cIPTables.update_action()")

#-------------------------------------------------------------------------------
# exec - execute a command line, return [exception flag, stderr, stdout]
#-------------------------------------------------------------------------------
def exec(cmdline):
	stderror  = None
	stdoutput = None
	exception = False
	try:
		if cEnvVars.verbose_debug:
			print("cmdline=[{}]\n        {}".format(cmdline, cmdline.split()))
		proc = subprocess.run(cmdline.split(),
							  stdout=subprocess.PIPE,
							  stderr=subprocess.PIPE)
		if proc.stderr is not None and len(proc.stderr) > 0:
			stderror  = proc.stderr.decode()
		if proc.stdout is not None and len(proc.stdout) > 0:
			stdoutput = proc.stdout.decode()
	except FileNotFoundError as e:
		exception = True
		stderror = traceback.print_exc()
		stdoutput = "{}".format(e)
	return { "exception":exception, "stderr":stderror, "stdout":stdoutput }

#-------------------------------------------------------------------------------
if __name__ == "__main__":
	# debug parsing
	ipt = cIPTables()

