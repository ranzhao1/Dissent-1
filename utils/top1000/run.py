#!/usr/bin/python

import os
import sys

def main():
  for line in sys.stdin:
    (rank,url) = line.split(',')
    http = "http://www.%s/" % url.strip()
    sys.stdout.write("%s..." % http)
    sys.stdout.flush()

    res = os.system("wget -q -E -H -p -P /tmp/wget/ -U \"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\" %s" % http)
    if res == 0:
      print "OK"
    else:
      print "Failed"
      return 

if __name__ == "__main__":
  main()
