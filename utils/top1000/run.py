#!/usr/bin/python

import os
import shutil
import subprocess
import sys
import tempfile
import time

def main():

  for line in sys.stdin:
    tmpdir = tempfile.mkdtemp()
   
    (rank,url) = line.split(',')
    url = url.strip()
    http = "http://%s/" % url
    sys.stdout.write("%s,%s," % (rank,url))
    sys.stdout.flush()

    args = ["wget", 
        "-q", "-E", "-H", "-p", "-nd", \
        "-P", tmpdir, \
        "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
        http]

    tstart = time.time()
    subprocess.check_call(args)
    tend = time.time()

    output = subprocess.check_output(["du", "-b", "-s", tmpdir])
    (size, path) = output.split() 

    sys.stdout.write("%d,%f,%f\n" % (int(size), tstart, tend))
    shutil.rmtree(tmpdir)

if __name__ == "__main__":
  main()
