
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <QByteArray>
#include <QTextStream>

int main(int argc, char* argv[]) {
  QTextStream err(stderr, QIODevice::WriteOnly);

  if(argc != 2) {
    err << "Usage: " << argv[0] << " pbits\n";
    return 1;
  }

  // Get one witness

  // Run the protocol

  // Verify the proof

  return 0;
}

