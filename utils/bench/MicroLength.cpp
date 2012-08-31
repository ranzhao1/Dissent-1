#include <QDateTime>
#include "Benchmark.hpp"

namespace Dissent {
namespace Benchmarks {

  typedef struct {
    // proof type
    // group type
    // nelms
    // plaintext bytes per elm
    // ciphertext len
    int len;
    // time verify 1000
    double time;

  } verify1000_stats;

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

  // Verify 1000 proofs
  // Print ciphertext size
  void Verify1000Times(QSharedPointer<const Parameters> params, verify1000_stats *s)
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

    // Get a random plaintext
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    BlogDropAuthor auth(params, master_client_sks[author_idx], server_pk_set, author_priv);

    QByteArray msg(auth.MaxPlaintextLength(), 0);
    rand->GenerateBlock(msg);

    BlogDropServer server(params, master_server_sks[0], server_pk_set, author_pk);

    // Generate client ciphertext and give it to all servers
    QByteArray c = BlogDropClient(params, master_client_sks[0], server_pk_set, 
        author_pk).GenerateCoverCiphertext();

    const qint64 start = QDateTime::currentMSecsSinceEpoch();
    for(int i=0; i<1000; i++) {
      server.AddClientCiphertext(c, master_client_pks[0]);  
    }
    const qint64 end = QDateTime::currentMSecsSinceEpoch();

    double diff = end-start;
    s->time = diff/1000.0;
    s->len = c.count();
  }

  // Given parameters, change message lengths
  void Verify1000TimesDiffLen(QSharedPointer<Parameters> params)
  {
    verify1000_stats s;
    
    for(int nelms=1; Plaintext::CanFit(params)<1024*1; nelms++) {  
      params->SetNElements(nelms);
      Verify1000Times(params, &s);

      qDebug() << ","
        << Parameters::ProofTypeToString(params->GetProofType()) << ","
        << params->GetKeyGroup()->GetSecurityParameter() << ","
        << params->GetKeyGroup()->ToString() << "," 
        << params->GetNElements() << ","
        << Plaintext::CanFit(params) << ","
        << s.len << ","
        << s.time << ",";
    }

    // proof type
    // nbits
    // group type
    // nelms
    // plaintext bytes 
    // ciphertext len
    // time verify 1000
  }

  // Cycle through proof types
  void Verify1000TimesDiffLenLibrary(bool use_openssl)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(use_openssl ? CryptoFactory::OpenSSL : CryptoFactory::CryptoPP);

    // paring
    Verify1000TimesDiffLen(Parameters::PairingProductionFixed());

    // hashing
      // integer
    Verify1000TimesDiffLen(Parameters::IntegerHashingProductionFixed());
    
      // open ec
    Verify1000TimesDiffLen(Parameters::OpenECHashingProductionFixed());

      // cpp ec
    Verify1000TimesDiffLen(Parameters::CppECHashingProductionFixed());

    // elgamal
      // integer
    Verify1000TimesDiffLen(Parameters::IntegerElGamalProductionFixed());

      // open ec
    Verify1000TimesDiffLen(Parameters::OpenECElGamalProductionFixed());

      // cpp ec
    Verify1000TimesDiffLen(Parameters::CppECElGamalProductionFixed());


    cf.SetLibrary(cname);
  }

  // Cycle through integer types
  TEST(Micro, Length) {
    qDebug() << "proof type, nbits, group type, nelms, plaintext bytes, ciphertext len, time verify 1000";
    Verify1000TimesDiffLenLibrary(false);
    Verify1000TimesDiffLenLibrary(true);

    QSharedPointer<const AbstractGroup::AbstractGroup> integer = IntegerGroup::Production2048Fixed();
  }
}
}
