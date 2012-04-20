#!/usr/bin/python

import os
import shutil
import subprocess
import sys
import tempfile

def main():

  for line in sys.stdin:
    tmpdir = tempfile.mkdtemp()
   
    (rank,url) = line.split(',')
    http = "http://%s/" % url.strip()
    sys.stdout.write("%s,%s," % (rank,http))
    sys.stdout.flush()

    args = ["wget", 
        "-q", "-E", "-H", "-p", "-nd", \
        "-P", tmpdir, \
        "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
        http]
    subprocess.check_call(args)

    output = subprocess.check_output(["du", "-b", "-s", tmpdir])
    (size, path) = output.split() 

    sys.stdout.write("%d\n" % int(size))
    shutil.rmtree(tmpdir)

if __name__ == "__main__":
  main()
