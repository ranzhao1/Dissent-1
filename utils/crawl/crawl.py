#!/usr/bin/python

from collections import deque
from HTMLParser import HTMLParser
from Queue import Queue
from threading import Thread, Lock
import sys
import urllib2 

N_THREADS = 5

# Global queue of URLs
q = Queue()
seen_lock = Lock()
seen = set()

class CrawlParser(HTMLParser):
  def handle_starttag():

def found_new_url(url):
  with seen_lock:
    if url not in seen:
     seen.add(url)
     q.put(url)

def fetch_url(url):
  r = urllib2.Request(url, headers={'User-Agent': "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"})
  f = urllib2.urlopen(r)
  return (f.info().gettype(), f.read())

def parse_html(content):
  print "Got %d bytes" % len(content)
  return []

def print_asset_info(item, content_type, content):
  print "%s, %s, %d" % (item, content_type, len(content))

# Consumer
def worker():
  while True:
    try:
      item = q.get()

      # Get URL
      (ctype, content) = fetch_url(item)

      if ctype == 'text/html':
        # Parse out sub URLS
        deps = parse_html(content)

        # For d in deps
        for url in deps:
          found_new_url(url)

      print_asset_info(item, ctype, content)  

    except Exception as e:
      print e
      raise e
    finally:
      q.task_done()


def main():
  if len(sys.argv) != 2:
    raise Exception("Usage: %s URL" % sys.argv[0])
  url = sys.argv[1]

  print "URL crawler: "


  for i in range(N_THREADS):
    t = Thread(target=worker)
    t.daemon = True
    t.start()

  found_new_url(url)

  q.join()   

if __name__ == "__main__":
  main()
