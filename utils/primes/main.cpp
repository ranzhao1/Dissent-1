
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <QByteArray>
#include <QTextStream>

#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>

QByteArray PrintInteger(const CryptoPP::Integer &i) 
{
  const int len = i.MinEncodedSize();
  char *bytes = (char*)malloc(sizeof(char) * len);
  if(!bytes) exit(1); 
  
  i.Encode((byte*)bytes, len);
  QByteArray b(bytes, len);

  return b;
}

QByteArray Format(QByteArray num)
{
  QByteArray out = "\"0x";
  num = num.toHex();

  for(int i=0; i<num.count(); i++) {
    out.append(num[i]);
    if(i && ((i % 64) == 0)) out.append("\"\n\"");
  }

  out.append("\"");

  return out;
}

int main(int argc, char* argv[]) {
  QTextStream err(stderr, QIODevice::WriteOnly);
  if(argc != 2) {
    err << "Usage: " << argv[0] << " pbits\n";
    return 1;
  }

  int pbits;
  QTextStream in(argv[1], QIODevice::ReadOnly);
  in >> pbits;

  if(pbits < 10) {
    err << "pbits must be greater than 10\n";
    return 1;
  }

  QTextStream out(stdout, QIODevice::WriteOnly);
  out << "--- Prime Number Utility ---\n";
  out << "p = 2q+1 (for prime p and q)\n";
  out << "g generates the group of quadratic residues mod p\n";
  out << "Bits: " << pbits << "\n";
  out << "\n\n";

  CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng(false, true);
  CryptoPP::PrimeAndGenerator pand(1, rng, pbits);

  QByteArray p, q, g;

  out << "==> p\n";
  out << Format(PrintInteger(pand.Prime())) << "\n\n";
  out << "==> q\n";
  out << Format(PrintInteger(pand.SubPrime())) << "\n\n";
  out << "==> g\n";
  out << Format(PrintInteger(pand.Generator())) << "\n\n";

  return 0;
}

