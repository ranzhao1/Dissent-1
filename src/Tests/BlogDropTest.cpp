#include "DissentTest.hpp"
#include <cryptopp/ecp.h>
#include <cryptopp/nbtheory.h>

namespace Dissent {
namespace Tests {

  void TestPlaintextEmpty(QSharedPointer<const Parameters> params)
  {
    Plaintext p(params);
    QByteArray out;
    EXPECT_FALSE(p.Decode(out));
    EXPECT_EQ(QByteArray(), out);
  }

  TEST(BlogDrop, IntegerPlaintextEmpty) {
    TestPlaintextEmpty(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECPlaintextEmpty) 
  {
    TestPlaintextEmpty(Parameters::Parameters::ECProductionFixed());
  }

  void TestPlaintextShort(QSharedPointer<const Parameters> params)
  {
    Plaintext p(params);

    QByteArray shorts("shorts");
    p.Encode(shorts);

    QByteArray out;
    EXPECT_TRUE(p.Decode(out));
    EXPECT_EQ(shorts, out);
  }

  TEST(BlogDrop, IntegerPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::ECProductionFixed());
  }

  void TestPlaintextRandom(QSharedPointer<const Parameters> params, int divby)
  {
    Plaintext p(params);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int i=0; i<1000; i++) {
      QByteArray msg(Plaintext::CanFit(params)/divby, 0);
      rand->GenerateBlock(msg);

      p.Encode(msg);

      QByteArray output;
      EXPECT_TRUE(p.Decode(output));
      EXPECT_TRUE(output.count() > 0);
      EXPECT_TRUE(output.count() < (params->GetNElements()*
            (params->GetGroup()->GetOrder().GetByteCount()/divby)));
      EXPECT_TRUE(output.count() > (params->GetNElements()*
            ((params->GetGroup()->GetOrder().GetByteCount()-5)/divby)));
      EXPECT_EQ(msg, output);
    }
  }

  TEST(BlogDrop, IntegerPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 4);
  }

  TEST(BlogDrop, ECPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::ECProductionFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::ECProductionFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::ECProductionFixed(), 4);
  }

  void TestKeys(QSharedPointer<const Parameters> params)
  {
    for(int i=0; i<20; i++) {
      PrivateKey priv(params);
      Integer x = priv.GetInteger();

      PublicKey pub(priv);
      Element gx = pub.GetElement();

      ASSERT_TRUE(x < params->GetGroup()->GetOrder());
      ASSERT_TRUE(x > 0);
      ASSERT_EQ(gx, params->GetGroup()->Exponentiate(params->GetGroup()->GetGenerator(), x));
    }
  }

  TEST(BlogDrop, IntegerKeys) {
    TestKeys(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECKeys) {
    TestKeys(Parameters::Parameters::ECProductionFixed());
  }

  void TestPublicKeySet(QSharedPointer<const Parameters> params)
  {
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QList<QSharedPointer<const PublicKey> > keys;
    Element prod = params->GetGroup()->GetIdentity();
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      keys.append(pub);

      prod = params->GetGroup()->Multiply(prod, pub->GetElement());
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetElement());
  }

  TEST(BlogDrop, IntegerPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::ECProductionFixed());
  }

  void TestServerCiphertext(QSharedPointer<const Parameters> params)
  {
    for(int t=0; t<10; t++) {
      const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

      QList<QSharedPointer<const PublicKeySet> > sets;
      for(int j=0; j<params->GetNElements(); j++) {
        QList<QSharedPointer<const PublicKey> > client_pks;
        for(int i=0; i<nkeys; i++) {
          QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
          QSharedPointer<const PublicKey> pub(new PublicKey(priv));
          client_pks.append(pub);
        }
        sets.append(QSharedPointer<const PublicKeySet>(new PublicKeySet(params, client_pks)));
      }

      QSharedPointer<const PrivateKey> server_sk(new PrivateKey(params));
      QSharedPointer<const PublicKey> server_pk(new PublicKey(server_sk));

      ServerCiphertext c(params, sets);
      c.SetProof(server_sk);

      for(int j=0; j<params->GetNElements(); j++) {
        Element expected = params->GetGroup()->Exponentiate(sets[j]->GetElement(), 
            server_sk->GetInteger());
        expected = params->GetGroup()->Inverse(expected);
        ASSERT_EQ(expected, c.GetElements()[j]);
      }

      ASSERT_TRUE(c.VerifyProof(server_pk));
    }
  }

  TEST(BlogDrop, IntegerServerCiphertext) {
    TestServerCiphertext(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECServerCiphertext) {
    TestServerCiphertext(Parameters::Parameters::ECProductionFixed());
  }

  void TestClientOnce(QSharedPointer<const Parameters> params)
  {

    // Generate an author PK
    QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(priv));

    // Generate list of server pks
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    QList<QSharedPointer<const PublicKey> > server_pks;
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_pks.append(pub);
    }

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    // Generate ciphertext
    ClientCiphertext c(params, server_pk_set, author_pk);
    c.SetProof();

    const Integer q = params->GetGroup()->GetOrder();
    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < q);
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < q);

    ASSERT_EQ(params->GetNElements()+1, c.GetResponses().count());
    foreach(const Integer &i, c.GetResponses()) {
      ASSERT_TRUE(i > 0 || i < q);
    }

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    foreach(const Integer &i, c.GetResponses()) {
      set.insert(i.GetByteArray());
    }

    ASSERT_EQ(params->GetNElements()+3, set.count());

    ASSERT_TRUE(c.VerifyProof());
  }

  TEST(BlogDrop, IntegerClientProof) {
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::IntegerTestingFixed());
    }
  }

  TEST(BlogDrop, ECClientProof) {
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::ECProductionFixed());
    }
  }

  void TestAuthorOnce(QSharedPointer<const Parameters> params) 
  {

    // Generate an author PK
    QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    QList<QSharedPointer<const PublicKey> > server_pks;
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_pks.append(pub);
    }

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    // Get a random plaintext
    Plaintext m(params);
    m.SetRandom();

    // Generate ciphertext
    ClientCiphertext c(params, server_pk_set, author_pk);
    c.SetAuthorProof(author_priv, m);

    const Integer q = params->GetGroup()->GetOrder();
    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < q);
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < q);

    ASSERT_EQ(params->GetNElements()+1, c.GetResponses().count());
    foreach(const Integer &i, c.GetResponses()) {
      ASSERT_TRUE(i > 0 || i < q);
    }

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    foreach(const Integer &i, c.GetResponses()) {
      set.insert(i.GetByteArray());
    }

    ASSERT_EQ(params->GetNElements()+3, set.count());

    ASSERT_TRUE(c.VerifyProof());
  }

  TEST(BlogDrop, IntegerAuthorProof) {
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::IntegerTestingFixed());
    }
  }

  TEST(BlogDrop, ECAuthorProof) {
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::ECProductionFixed());
    }
  }
  
  void TestReveal(QSharedPointer<const Parameters> params) 
  {
    // Generate an author PK
    QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    QList<QSharedPointer<const PrivateKey> > server_sks;
    QList<QSharedPointer<const PublicKey> > server_pks;
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_sks.append(priv);
      server_pks.append(pub);
    }

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    // Get a random plaintext
    Plaintext m(params);
    m.SetRandom();

    // Generate author ciphertext
    ClientCiphertext c(params, server_pk_set, author_pk);
    c.SetAuthorProof(author_priv, m);

    // Generate non-author ciphertext
    QList<QSharedPointer<const ClientCiphertext> > cover;
    const int ncover = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<ncover; i++) {
      QSharedPointer<ClientCiphertext> cov(new ClientCiphertext(params, server_pk_set, author_pk));
      cov->SetProof();
      cover.append(cov);
    }

    // Get client pk set
    QList<QList<QSharedPointer<const PublicKey> > > client_pks;
    client_pks.append(c.GetOneTimeKeys());
    for(int i=0; i<ncover; i++) {
      client_pks.append(cover[i]->GetOneTimeKeys());
    }

    QList<QSharedPointer<const PublicKeySet> > sets = PublicKeySet::CreateClientKeySets(params, client_pks);

    const Integer q = params->GetGroup()->GetOrder();
    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < q);
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < q);

    ASSERT_EQ(params->GetNElements()+1, c.GetResponses().count());
    foreach(const Integer &i, c.GetResponses()) {
      ASSERT_TRUE(i > 0 || i < q);
    }

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    foreach(const Integer &i, c.GetResponses()) {
      set.insert(i.GetByteArray());
    }
    ASSERT_EQ(params->GetNElements()+3, set.count());

    ASSERT_TRUE(c.VerifyProof());

    Plaintext out(params);
    out.Reveal(c.GetElements());

    for(int i=0; i<nkeys; i++) {
      ServerCiphertext s(params, sets);
      s.SetProof(server_sks[i]);

      ASSERT_TRUE(s.VerifyProof(server_pks[i]));

      out.Reveal(s.GetElements()); 
    }

    for(int i=0; i<ncover; i++) {
      out.Reveal(cover[i]->GetElements());
    }

    ASSERT_EQ(m.GetElements(), out.GetElements());
  }

  TEST(BlogDrop, IntegerReveal) {
    for(int i=0; i<10; i++) {
      TestReveal(Parameters::Parameters::IntegerTestingFixed());
    }
  }

  TEST(BlogDrop, ECReveal) {
    for(int i=0; i<10; i++) {
      TestReveal(Parameters::Parameters::ECProductionFixed());
    }
  }

  void EndToEndOnce(QSharedPointer<const Parameters> params)
  {
    const int nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    const int nclients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    const int author_idx = Random::GetInstance().GetInt(0, nclients);

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

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    QList<BlogDropServer> servers;
    for(int i=0; i<nservers; i++) {
      servers.append(BlogDropServer(params, server_pk_set, author_pk, server_sks[i]));
    }

    // Get a random plaintext
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    BlogDropAuthor auth(params, server_pk_set, author_priv);

    QByteArray msg(auth.MaxPlaintextLength(), 0);
    rand->GenerateBlock(msg);

    QList<QList<QByteArray> > for_servers;
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      for_servers.append(QList<QByteArray>());
    }

    // Generate client ciphertext and give it to all servers
    for(int client_idx=0; client_idx<nclients; client_idx++) {
      QByteArray c = BlogDropClient(params, server_pk_set, 
            author_pk).GenerateCoverCiphertext();

      if(client_idx == author_idx) {
        ASSERT_TRUE(auth.GenerateAuthorCiphertext(c, msg)); 
      }

      for(int server_idx=0; server_idx<nservers; server_idx++) {
        for_servers[server_idx].append(c);
      }
    }

    for(int server_idx=0; server_idx<nservers; server_idx++) {
      servers[server_idx].AddClientCiphertexts(for_servers[server_idx]);
    }

    // Generate server ciphertext and pass it to all servers
    QList<QByteArray> s;
    for(int i=0; i<nservers; i++) {
      s.append(servers[i].CloseBin());
    }
    for(int i=0; i<nservers; i++) {
      for(int j=0; j<nservers; j++) {
        ASSERT_TRUE(servers[j].AddServerCiphertext(servers[i].GetPublicKey(), s[i]));
      }
    }

    // Reveal the plaintext
    for(int i=0; i<nservers; i++) {
      QByteArray out;
      ASSERT_TRUE(servers[i].RevealPlaintext(out));
      ASSERT_EQ(msg, out);
    }
  }

  TEST(BlogDrop, IntegerEndToEndNoThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::SingleThreaded);
    EndToEndOnce(Parameters::Parameters::IntegerTestingFixed());
    cf.SetThreading(t);
  }

  TEST(BlogDrop, IntgerEndToEndThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::MultiThreaded);
    EndToEndOnce(Parameters::Parameters::IntegerTestingFixed());
    cf.SetThreading(t);
  }

  TEST(BlogDrop, ECEndToEndNoThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::SingleThreaded);
    EndToEndOnce(Parameters::Parameters::ECProductionFixed());
    cf.SetThreading(t);
  }

  TEST(BlogDrop, ECEndToEndThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::MultiThreaded);
    EndToEndOnce(Parameters::Parameters::ECProductionFixed());
    cf.SetThreading(t);
  }

}
}
