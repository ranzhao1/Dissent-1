#include <QDateTime>
#include "Benchmark.hpp"

namespace Dissent {
namespace Benchmarks {

  typedef struct {
    int n_gen;
    int n_verify;
  } verifyN_params;

  typedef struct {
    // proof type
    // group type
    // nelms
    // plaintext bytes per elm
    // ciphertext len
    int cipher_len;
    // time generate M
    double time_gen;
    // time verify N 
    double time_verify;

  } verifyN_stats;

  void ComputeSecrets(QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PrivateKey> > &client_sks_in,
      const QList<QSharedPointer<const PrivateKey> > &server_sks_in,
      const QList<QSharedPointer<const PublicKey> > &client_pks_in,
      const QList<QSharedPointer<const PublicKey> > &server_pks_in,
      QList<QSharedPointer<const PrivateKey> > &client_sks_out,
      QList<QSharedPointer<const PrivateKey> > &server_sks_out,
      QList<QSharedPointer<const PublicKey> > &client_pks_out,
      QList<QSharedPointer<const PublicKey> > &server_pks_out)
  {
    Parameters::ProofType t = params->GetProofType();
    if(t == Parameters::ProofType_HashingGenerator) {
    // If we're using hashed, we have to use pre-computed shared secrets
      for(int i=0; i<client_sks_in.count(); i++) { 
        QSharedPointer<const PrivateKey> priv = BlogDropUtils::GetMasterSharedSecret(params, 
            client_sks_in[i], server_pks_in);
        QSharedPointer<const PublicKey> pub(new PublicKey(priv));

        client_pks_out.append(pub);
        client_sks_out.append(priv);
      }

      for(int i=0; i<server_sks_in.count(); i++) { 
        QSharedPointer<const PrivateKey> priv = BlogDropUtils::GetMasterSharedSecret(params, 
            server_sks_in[i], client_pks_in);
        QSharedPointer<const PublicKey> pub(new PublicKey(priv));

        server_pks_out.append(pub);
        server_sks_out.append(priv);
      }

    } else if(t == Parameters::ProofType_ElGamal || t == Parameters::ProofType_Pairing) {
    // If we're using ElGamal, we don't need extra shared secrets
      client_sks_out = client_sks_in;
      server_sks_out = server_sks_in;
      client_pks_out = client_pks_in;
      server_pks_out = server_pks_in;
    } else {
      qFatal("Unknown proof type");
    }
  }

  // Verify N proofs
  // Print ciphertext size
  void VerifyNTimes(QSharedPointer<Parameters> params, 
      verifyN_params *p, verifyN_stats *s)
  {
    const int nservers = 10;
    const int nclients = 1000;
    const int author_idx = 1;

    // Generate an author PK
    const QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    const QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    // Generate list of server pks
    QList<QSharedPointer<const PublicKey> > server_pks;
    QList<QSharedPointer<const PrivateKey> > server_sks;

    for(int i=0; i<nservers; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_sks.append(priv);
      server_pks.append(pub);
    }

    // Generate list of client pks
    QList<QSharedPointer<const PublicKey> > client_pks;
    QList<QSharedPointer<const PrivateKey> > client_sks;
    for(int i=0; i<nclients; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      client_sks.append(priv);
      client_pks.append(pub);
    }

    // for each server/client
    QList<QSharedPointer<const PrivateKey> > master_client_sks;
    QList<QSharedPointer<const PublicKey> > master_client_pks;
    QList<QSharedPointer<const PrivateKey> > master_server_sks;
    QList<QSharedPointer<const PublicKey> > master_server_pks;

    ComputeSecrets(params,
        client_sks, server_sks, 
        client_pks, server_pks,
        master_client_sks, master_server_sks, 
        master_client_pks, master_server_pks);

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));
    
    ///// Loop here
    int nelms = 1;
    while(Plaintext::CanFit(params)<1024*4) {  
      params->SetNElements(nelms);

      // Get a random plaintext
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

      BlogDropAuthor auth(params, master_client_sks[author_idx], server_pk_set, author_priv);

      QByteArray msg(auth.MaxPlaintextLength(), 0);
      rand->GenerateBlock(msg);

      BlogDropServer server(params, master_server_sks[0], server_pk_set, author_pk);

      // Generate client ciphertext and give it to all servers
      QByteArray c;
      
      qint64 start, end; 
      
      start = QDateTime::currentMSecsSinceEpoch();
      for(int i=0; i<p->n_gen; i++) {
        c = BlogDropClient(params, master_client_sks[0], server_pk_set, 
            author_pk).GenerateCoverCiphertext();
      }
      end = QDateTime::currentMSecsSinceEpoch();
      s->time_gen = (end-start)/1000.0;

      start = QDateTime::currentMSecsSinceEpoch();
      for(int i=0; i<p->n_verify; i++) {
        server.AddClientCiphertext(c, master_client_pks[0]);  
      }
      end = QDateTime::currentMSecsSinceEpoch();

      s->time_verify = (end-start)/1000.0;
      s->cipher_len = c.count();

      qDebug() << ","
        << p->n_gen << "," 
        << p->n_verify << "," 
        << Parameters::ProofTypeToString(params->GetProofType()) << ","
        << params->GetKeyGroup()->GetSecurityParameter() << ","
        << params->GetKeyGroup()->ToString() << "," 
        << params->GetNElements() << ","
        << Plaintext::CanFit(params) << ","
        << s->cipher_len << ","
        << s->time_gen << ","
        << s->time_verify << ",";

      if(nelms < 8) nelms += 1;
      else if(nelms < 16) nelms += 2;
      else if(nelms < 32) nelms += 4;
      else if(nelms < 64) nelms += 8;
      else if(nelms < 128) nelms += 16;
      else if(nelms < 256) nelms += 32;
      else if(nelms < 512) nelms += 64;
      else nelms += 128;
    }
  }

  // Given parameters, change message lengths
  void VerifyNTimesDiffLen(QSharedPointer<Parameters> params, verifyN_params *p)
  {
    verifyN_stats s;
   
    VerifyNTimes(params, p, &s);

    // proof type
    // nbits
    // group type
    // nelms
    // plaintext bytes 
    // ciphertext len
    // time verify N
  }

  // Cycle through proof types
  void VerifyNTimesDiffLenLibrary(verifyN_params *p, bool use_openssl)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(use_openssl ? CryptoFactory::OpenSSL : CryptoFactory::CryptoPP);

    // paring
    VerifyNTimesDiffLen(Parameters::PairingProductionFixed(), p);

    // hashing
      // integer
    VerifyNTimesDiffLen(Parameters::IntegerHashingProductionFixed(), p);
    
      // open ec
    VerifyNTimesDiffLen(Parameters::OpenECHashingProductionFixed(), p);
      // cpp ec
    VerifyNTimesDiffLen(Parameters::CppECHashingProductionFixed(), p);

    // elgamal
      // integer
    VerifyNTimesDiffLen(Parameters::IntegerElGamalProductionFixed(), p);

      // open ec
    VerifyNTimesDiffLen(Parameters::OpenECElGamalProductionFixed(), p);

      // cpp ec
    VerifyNTimesDiffLen(Parameters::CppECElGamalProductionFixed(), p);
    cf.SetLibrary(cname);
  }

  // Cycle through integer types
  TEST(Micro, VerifyN) {

    verifyN_params p;
    p.n_gen = 10;
    p.n_verify = 10;

    qDebug() << ", n_gen, n_verify, proof type, nbits, group type, nelms, plaintext bytes, ciphertext len, time gen n, time verify n";
    VerifyNTimesDiffLenLibrary(&p, false);

    // Don't use OpenSSL integers
    // VerifyNTimesDiffLenLibrary(&p, true);

    QSharedPointer<const AbstractGroup::AbstractGroup> integer = IntegerGroup::Production2048Fixed();
  }
}
}
