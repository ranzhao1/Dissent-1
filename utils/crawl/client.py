#!/usr/bin/python

from collections import deque
from HTMLParser import HTMLParser, HTMLParseError
from Queue import Queue
from threading import Thread, Lock
import threading
import time
import socks
import socket
import sys
import urllib2 
import urlparse

if len(sys.argv) != 5:
  raise Exception("Usage: %s socks_ip socks_port server_ip server_port" % sys.argv[0])

# Route through SOCKS proxy
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, sys.argv[1], int(sys.argv[2]), True)
socket.socket = socks.socksocket

# Global queue of dicts (uid, parent_id, depth, url)
q = Queue()

asset_data_lock = Lock()
asset_children = {}
asset_data = {}

N_THREADS = 10

class NullException(Exception):
  pass

def fetch_url(mydata):
  start = time.time()
  r = urllib2.Request("http://%s:%s/index" % (sys.argv[3], sys.argv[4]), 
        headers=\
          {
            'User-Agent': "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11",
            'X-URL': mydata['url'],
            'X-Time': "%0.2f" % mydata['time'],
            'X-Length': "%d" % mydata['length']
          })
  f = urllib2.urlopen(r)
  end = time.time()

  data = f.read()
  sys.stderr.write("Got %d bytes in %0.2fs\n" % (len(data), end-start))

# Consumer
def worker():
  while True:
    try:
      idx = q.get()
      mydata = None
      with asset_data_lock:
        mydata = asset_data[idx]

      # Get this asset
      fetch_url(mydata)

      # Get dependent assets
      with asset_data_lock:
        for c in asset_children[mydata['id']]:
          q.put(c) 

    except NullException as e:
      raise e
    finally:
      q.task_done()

def process_lines(lines):
  global q
  bytecount = 0
  for l in lines:
    (uid, parent_id, depth, ctype, length, dur, url) = l.split(',', 6)
    asset_data[uid] = {'id': uid, 'length': int(length), 'time': float(dur), 'url': url.strip()}
    asset_children[uid] = set()
    
    if parent_id.strip() != uid.strip():
      asset_children[parent_id].add(uid)

    bytecount += int(length)

  start = time.time()

  q.put('0')
  q.join()   
  end = time.time()

  print "%0.2f,%d" % (end-start, bytecount)
  sys.stdout.flush()

def main():
  print "==URL Client=="
  print "time,total_bytes"
  for i in range(N_THREADS):
    t = Thread(target=worker)
    t.daemon = True
    t.start()

  lines = []
  last = None
 
  for line in sys.stdin:
    if line.startswith("=="):
      if len(lines):
        process_lines(lines)
        del lines[:]
        
    else:
      lines.append(line) 

if __name__ == "__main__":
  main()

