#include <stdio.h>

#include <QDebug>
#include <QTextStream>
#include <QxtCommandOptions>

#include "Dissent.hpp"

int main(int argc, char **argv)
{
  QxtCommandOptions options;
  options.add("help", "display this help message");
  options.add("nkeys", "number of keys to put in roster (>0)", QxtCommandOptions::Required);
  options.alias("nkeys", "n");

  options.parse(argc, argv);

  if(options.count("help") || options.showUnrecognizedWarning() 
      || !options.value("nkeys").canConvert(QVariant::Int)) {
    options.showUsage();
    return -1;
  }

  int nkeys = options.value("nkeys").toInt();

  if(nkeys < 1) {
    options.showUsage();
    return -1;
  }

  QTextStream qout(stdout, QIODevice::WriteOnly); 

  Library *lib = CryptoFactory::GetInstance().GetLibrary();

  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  Hash *hash = lib->GetHashAlgorithm();

  for(int i=0; i<nkeys; i++) {
    QByteArray id = hash->ComputeHash(QByteArray::number(i));
    key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));

    QByteArray keyhex = key->GetByteArray().toHex();
    qout << i << " " << key->GetByteArray().toHex() << " " << 
      dh->GetPublicComponent().toHex() << " " << dh->GetPrivateComponent().toHex() << endl;    
  } 

  return 0;
}
