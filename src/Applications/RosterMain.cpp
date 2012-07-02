#include <iostream>

#include <QDebug>
#include <QDir>
#include <QTextStream>
#include <QxtCommandOptions>

#include "Dissent.hpp"

static const char *CL_HELP = "help";
static const char *CL_NKEYS = "nkeys";
static const char *CL_PUBDIR = "pubdir";
static const char *CL_PRIVDIR = "privdir";

static const char *DEFAULT_PUBDIR = "./keys/pub";
static const char *DEFAULT_PRIVDIR = "./keys/priv";


void ExitWithWarning(const QxtCommandOptions &options, const char* warning)
{
  std::cerr << "Error: " << warning << std::endl;
  options.showUsage();
  exit(-1);
}

int main(int argc, char **argv)
{
  QxtCommandOptions options;
  QString name_privdir, name_pubdir;

  options.add(CL_HELP, "display this help message");
  options.add(CL_NKEYS, "number of keys to put in roster (>0)", QxtCommandOptions::Required);
  options.add(CL_PUBDIR, "directory in which to put public keys (default=./keys/pub)");
  options.add(CL_PRIVDIR, "directory in which to put private keys (default=./keys/priv)");

  options.alias(CL_NKEYS, "n");

  options.parse(argc, argv);

  if(options.count(CL_HELP) || options.showUnrecognizedWarning()) {
    options.showUsage();
    return -1;
  }

  // NKEYS 
  if(!options.value(CL_NKEYS).canConvert(QVariant::Int))
    ExitWithWarning(options, "Invalid nkeys value");

  int nkeys = options.value(CL_NKEYS).toInt();

  if(nkeys < 1)
    ExitWithWarning(options, "Negative nkeys value");

  // PUBDIR 
  if(options.count(CL_PUBDIR)) {
    if(options.value(CL_PUBDIR).canConvert(QVariant::String)) {
      name_pubdir = options.value(CL_PUBDIR).toString();
    } else {
      ExitWithWarning(options, "Invalid pubdir value");
    }
  } else {
    name_pubdir = DEFAULT_PUBDIR;
  }

  QDir pubdir(name_pubdir);
  if(!pubdir.exists()) {
    ExitWithWarning(options, "Specified pubdir does not exist");
  }

  // PRIVDIR 
  if(options.count(CL_PRIVDIR)) {
    if(options.value(CL_PRIVDIR).canConvert(QVariant::String)) {
      name_pubdir = options.value(CL_PRIVDIR).toString();
    } else {
      ExitWithWarning(options, "Invalid privdir value");
    }
  } else {
    name_privdir = DEFAULT_PRIVDIR;
  }

  QDir privdir(name_privdir);
  if(!privdir.exists()) {
    ExitWithWarning(options, "Specified privdir does not exist");
  }


  QTextStream qout(stdout, QIODevice::WriteOnly); 

  Library *lib = CryptoFactory::GetInstance().GetLibrary();

  QSharedPointer<AsymmetricKey> rsa;
  QSharedPointer<DiffieHellman> dh;

  Hash *hash = lib->GetHashAlgorithm();

  for(int i=0; i<nkeys; i++) {
    QString keyprefix = QString::number(i);
    QByteArray id = hash->ComputeHash(keyprefix.toAscii());

    rsa = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));

    PrivateIdentity ident(Id(id), rsa, dh, false);
    PublicIdentity pident = GetPublicIdentity(ident);

    QString pubkey = pubdir.filePath(keyprefix + ".pub");
    QString privkey = privdir.filePath(keyprefix + ".priv");

    if(!ident.Save(privkey)) {
      qFatal("Could not save private identity");
    }

    if(!pident.Save(pubkey)) {
      qFatal("Could not save public identity"); 
    }
  } 

  return 0;
}
