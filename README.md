# Microservice IPTables
This project implements a small microservice which supports querying the configured IPv4 and IPv6 iptables INPUT rules via a RESTful API. The service also handles iptables port open and close requests. The service is restricted to those operations. Adding and removing rules or editing existing rules beyond changing the rule action is not permitted.
## Dependencies
- Python 3.x
- iptables v1.8.2
- ip6tables v1.8.2
## Installation
TBD
## Using the Service
The microservice was tested by sending HTTP requests via the curl command line tool. The following sample command lines will exercise the service generating an appropriate HTTP header response with the iptables command results returned in a json structure. The curl output is piped to a script which pretty prints the json data.
#### Display INPUT Rules
| Test Command | Target |
| ------------ | ------ |
| curl -i -s -X GET http://localhost:60001/v1/rules \| ./printresp.py | Fetch all INPUT rules
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4 \| ./printresp.py | Fetch all IPv4 INPUT rules
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv6 \| ./printresp.py | Fetch all IPv6 INPUT rules
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4/4 \| ./printresp.py | Fetch IPv4 INPUT rule number 4
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv6/5 \| ./printresp.py | Fetch IPv6 INPUT rule number 5
#### Using Filters
| Test Command | Target |
| ------------ | ------ |
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4?action=accept | Fetch IPv4 INPUT rules with action = ACCEPT
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4?comment=Public_HTTP | Fetch IPv4 INPUT rule with comment = Public_HTTP
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4?port=80 | Fetch IPv4 INPUT rule where destination port = 80
| curl -i -s -X GET http://localhost:60001/v1/rules/ipv4?protocol=tcp | Fetch IPv4 INPUT rules where protocol = tcp
#### Open and Close Ports
| Test Command | Target |
| ------------ | ------ |
| curl -i -s -X PUT http://localhost:60001/v1/rules/ipv4/5/open | Set the action for IPv4 INPUT rule 5 to ACCEPT
| curl -i -s -X PUT http://localhost:60001/v1/rules/ipv4/5/close | Set the action for IPv4 INPUT rule 5 to DROP
#### HTTP Head Method
| Test Command | Target |
| ------------ | ------ |
| curl -i -s --head http://localhost:60001/v1/rules | Fetch the HTTP HEAD response for all INPUT rules

The microservice is normally run as user root and when it is the GET requests will return the actual rules configured on the server machine, and the PUT requests will update the configured action for the target rule. When run as a normal user (as during development) a set of static rules are hard coded in the image so that GET requests will return useful information. Since the non root user cannot update the currently active rules the microserver will print the appropriate iptables update command on the console.

## License and Acknowledgements
- The Microservice IPTables program is Copyright Robert I. Gike under the Apache 2.0 license.
