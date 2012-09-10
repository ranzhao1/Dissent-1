#!/usr/bin/python

from collections import deque
from HTMLParser import HTMLParser, HTMLParseError
from Queue import Queue
from threading import Thread, Lock
import time
import sys
import urllib2 
import urlparse

N_THREADS = 5

# Global queue of dicts (uid, parent_id, depth, url)
q = Queue()
seen_lock = Lock()
seen = set()

class NullException(Exception):
  pass

class CrawlParser(HTMLParser):
  def __init__(self, base_url, lst):
    self.base_url = base_url
    self.lst = lst
    HTMLParser.__init__(self)

  def handle_starttag(self, tag, attrs):
    if tag in ['img', 'script', 'link', 'embed']:
      self.get_src(attrs)

  def get_src(self, attrs):
    for (k, v) in attrs:
      if k == 'src': 
        self.lst.append(urlparse.urljoin(self.base_url, v))
        break 

def found_new_url(d):
  with seen_lock:
    if d['url'] not in seen:
     seen.add(d['url'])
     q.put(d)

def fetch_url(url):
  start = time.time()
  r = urllib2.Request(url, headers=\
      {'User-Agent': "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"})
  try:
    f = urllib2.urlopen(r)
  except urllib2.HTTPError as e:
    sys.stderr.write("On <%s> %s\n" % (url, e))
    return None
  end = time.time()
  return (f.info().gettype(), f.read(), end-start)

def parse_html(base_url, content):
  urllst = []
  h = CrawlParser(base_url, urllst)
  try:
    h.feed(content.decode('ascii', 'ignore'))
  except HTMLParseError as e:
    sys.stderr.write("Parse error on %s\n" % base_url)
  return urllst

def print_asset_info(item, content_type, content, dur):
  print "%(id)s,%(parent_id)s,%(depth)d," % item,
  print "%s,%d,%0.3f" % (content_type, len(content), dur)

# Consumer
def worker():
  while True:
    try:
      item = q.get()

      # Get URL
      res = fetch_url(item['url'])
      if not res: continue

      (ctype, content, dur) = res

      if ctype == 'text/html':
        # Parse out sub URLS
        deps = parse_html(item['url'], content)

        # For d in deps
        for i,url in enumerate(deps):
          found_new_url({'depth': item['depth']+1, 
              'url': url,
              'parent_id': item['id'],
              'id': "%s.%s" % (item['parent_id'], i)
          })

      print_asset_info(item, ctype, content, dur)  

    except Exception as e:
      print e
      raise e
    finally:
      q.task_done()


def main():
  print "==URL crawler=="

  for line in sys.stdin:
    for i in range(N_THREADS):
      t = Thread(target=worker)
      t.daemon = True
      t.start()

    (num, url) = line.split(",")
    url = url.strip()
    full_url = url if url.startswith("http") else ("http://www.%s/" % url) 
    sys.stdout.write("==%s,%s==\n" % (num, full_url))
    found_new_url({'depth':0, 'id': 0, 'parent_id': 0, 'url': full_url})

    q.join()   
    sys.stdout.flush()

if __name__ == "__main__":
  main()
