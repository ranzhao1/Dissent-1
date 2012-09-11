import os
import random
import SimpleHTTPServer
import SocketServer
import sys
import time
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer

"""
This is the trace server. Run it like
this:

  python server.py port

The server will listen on all interfaces at
the specified port for incoming requests
from client.py.

"""
class BenchHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

  def do_GET(self):
    print self.headers
    print self.path

    b = int(self.headers["X-Length"])
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(b))
    self.end_headers()
    if self.wfile:
      dur = float(self.headers["X-Time"])
      print "Sleeping for %0.2f" % dur
      time.sleep(dur)
      self.wfile.write(os.urandom(b))
      self.wfile.close()

class ThreadedServer(ThreadingMixIn, SocketServer.TCPServer):
  pass

def main():
  if len(sys.argv) != 2:
    raise Exception("Usage: %s server_port" % sys.argv[0])

  httpd = ThreadedServer(("", int(sys.argv[1])), BenchHandler)

  print "serving at port %s" % sys.argv[1]
  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    sys.exit()

if __name__ == "__main__":
  main()
