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
    http = "%s" % url
    sys.stdout.write("%s,%s," % (rank,url))
    sys.stdout.flush()

    '''
    args = ["wget", 
        "-E", "-H", "-p", "-nd", "--no-check-certificate",\
        "-e", "robots=off", "-P", tmpdir, \
        "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
        http]
    '''
    args = ["/users/henrycg/build/mulk", "-H", "-q",
      "-p", "5",
      "-m", "50",
      "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
      "http://www.%s/" % http]

    tstart = time.time()

    ok = True
    try:
      subprocess.check_call(args, cwd=tmpdir)
    except subprocess.CalledProcessError as e:
      sys.stderr.write("%s\n" % e)
      ok = False

    tend = time.time()

    shutil.rmtree(os.path.join(tmpdir, ".tmp-mulk"))
    (output, stderr) = subprocess.Popen(["du", "-b", "-s", tmpdir], 
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate()
      
    (size, path) = output.split() 
  
    if int(size) == 4096:
      ok = False

    sys.stdout.write("%d,%f,%f,%s\n" % (int(size), tstart, tend, "OK" if ok else "Error(s)"))
      

    shutil.rmtree(tmpdir)

if __name__ == "__main__":
  main()
