"""
Read internet trace and make requests to a given 
HTTP server for each line in the trace file

Download trace files here:
http://ita.ee.lbl.gov/html/contrib/UCB.home-IP-HTTP.html

Run using the tracefile as:
zcat TRACEFILE | tools/showtrace | python client.py

"""

import httplib
import sys
import time

SERVER_IP = "localhost"
SERVER_PORT = 9090

def main():
  for line in sys.stdin:
    make_http_request(line)

def make_http_request(line):
  '''parse a line'''
  parts = line.split()
  d = {}
  d['time_start'] = parts[0]
  d['time_byte_first'] = parts[1]
  d['time_byte_last'] = parts[2]
  d['addr_client'] = parts[3]
  d['addr_server'] = parts[4]
  d['head_client'] = parts[5]
  d['head_server'] = parts[6]
  d['head_ifmodified'] = parts[7]
  d['head_expires'] = parts[8]
  d['head_lastmodified'] = parts[9]
  d['len_head'] = parts[10]
  d['len_body'] = parts[11]
  d['len_url'] = parts[12]
  d['method'] = parts[13]
  d['url'] = parts[14]

  '''
  make an HTTP request containing the
  length of the desired response
  '''

  tstart = time.time()
  h = httplib.HTTPConnection(SERVER_IP, SERVER_PORT)
  h.request("GET", "/%s?%s&%s" % (d['url'], d['len_head'], d['len_body']))

  r = h.getresponse()
  if r.status != 200:
    raise RuntimeError("Request failed on %s with code" % (d['url'], r.status))

  data = r.read()
  h.close()
  tend = time.time()

  print "%s %s %s %s %d" % (d['len_head'], d['len_body'], tstart, tend)

if __name__ == "__main__":
  main()
  
