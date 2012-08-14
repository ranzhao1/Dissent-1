#include "DissentTest.hpp"
#include <cryptopp/ecp.h>
#include <cryptopp/nbtheory.h>

namespace Dissent {
namespace Tests {
  TEST(BlogDrop, ParamsTesting) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();

    EXPECT_EQ(Integer(1), params->GetG().Pow(params->GetQ(), params->GetP()));
  }

  TEST(BlogDrop, ParamsIsElement) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params->IsElement(params->RandomElement()));
    }
  }

  TEST(BlogDrop, ParamsRandomExponent) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params->IsElement(params->GetG().Pow(
              params->RandomExponent(), params->GetP())));
    }
  }

  TEST(BlogDrop, ParamsNotElement) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();

    int count = 0;
    for(int i=0; i<100; i++) {
      if(params->IsElement(Integer::GetRandomInteger(0, params->GetP()))) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }

  TEST(BlogDrop, PlaintextEmpty) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();
    Plaintext p(params);
    QByteArray out;
    EXPECT_FALSE(p.Decode(out));
    EXPECT_EQ(QByteArray(), out);
  }

  TEST(BlogDrop, PlaintextShort) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();
    Plaintext p(params);

    QByteArray shorts("shorts");
    EXPECT_EQ(QByteArray(), p.Encode(shorts));

    QByteArray out;
    EXPECT_TRUE(p.Decode(out));
    EXPECT_EQ(shorts, out);
  }

  TEST(BlogDrop, PlaintextRandom) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();
    Plaintext p(params);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(2048, 0);
    rand->GenerateBlock(msg);

    QByteArray leftover = p.Encode(msg);
    EXPECT_TRUE(leftover.count() < msg.count());

    QByteArray output;
    EXPECT_TRUE(p.Decode(output));
    EXPECT_TRUE(output.count() > 0);
    EXPECT_TRUE(output.count() < params->GetQ().GetByteCount());
    EXPECT_TRUE(output.count() > (params->GetQ().GetByteCount()-5));
    EXPECT_EQ(msg, output+leftover);
  }

  TEST(BlogDrop, Keys) 
  {
    QSharedPointer<Parameters> params = Parameters::Parameters::Testing();

    PrivateKey priv(params);
    Integer x = priv.GetInteger();

    PublicKey pub(priv);
    Integer gx = pub.GetInteger();

    ASSERT_TRUE(x < params->GetQ());
    ASSERT_TRUE(x > 0);
    ASSERT_TRUE(gx < params->GetP());
    ASSERT_TRUE(gx > 0);
    ASSERT_EQ(gx, params->GetG().Pow(x, params->GetP()));
  }

  TEST(BlogDrop, PublicKeySet) 
  {
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

    QList<QSharedPointer<const PublicKey> > keys;
    Integer prod = 1;
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      keys.append(pub);

      prod = (prod * pub->GetInteger()) % params->GetP();
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetInteger());
  }

  TEST(BlogDrop, ServerCiphertext) 
  {
    for(int t=0; t<10; t++) {
      const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

      QList<QSharedPointer<const PublicKey> > client_pks;
      for(int i=0; i<nkeys; i++) {
        QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
        QSharedPointer<const PublicKey> pub(new PublicKey(priv));
        client_pks.append(pub);
      }

      QSharedPointer<const PublicKeySet> client_pk_set(new PublicKeySet(params, client_pks));

      QSharedPointer<const PrivateKey> server_sk(new PrivateKey(params));
      QSharedPointer<const PublicKey> server_pk(new PublicKey(server_sk));

      ServerCiphertext c(params, client_pk_set);
      c.SetProof(server_sk);

      Integer expected = client_pk_set->GetInteger().Pow(server_sk->GetInteger(), 
          params->GetP()).ModInverse(params->GetP());
      ASSERT_EQ(expected, c.GetElement());

      ASSERT_TRUE(c.VerifyProof(server_pk));
    }
  }

  void TestClientOnce() {
    QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

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

    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < params->GetQ());
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < params->GetQ());
    ASSERT_TRUE(c.GetResponse1() > 0 || c.GetResponse1() < params->GetQ());
    ASSERT_TRUE(c.GetResponse2() > 0 || c.GetResponse2() < params->GetQ());

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    set.insert(c.GetResponse1().GetByteArray());
    set.insert(c.GetResponse2().GetByteArray());
    ASSERT_EQ(4, set.count());

    ASSERT_TRUE(c.VerifyProof());
  }

  TEST(BlogDrop, ClientProof) 
  {
    for(int i=0; i<10; i++) {
      TestClientOnce();
    }
  }

  void TestAuthorOnce() {
    QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

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

    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < params->GetQ());
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < params->GetQ());
    ASSERT_TRUE(c.GetResponse1() > 0 || c.GetResponse1() < params->GetQ());
    ASSERT_TRUE(c.GetResponse2() > 0 || c.GetResponse2() < params->GetQ());

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    set.insert(c.GetResponse1().GetByteArray());
    set.insert(c.GetResponse2().GetByteArray());
    ASSERT_EQ(4, set.count());

    ASSERT_TRUE(c.VerifyProof());
  }

  TEST(BlogDrop, AuthorProof) 
  {
    for(int i=0; i<10; i++) {
      TestAuthorOnce();
    }
  }
  
  TEST(BlogDrop, Reveal) {
    QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

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
    QList<ClientCiphertext> cover;
    const int ncover = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<ncover; i++) {
      ClientCiphertext cov(params, server_pk_set, author_pk);
      cov.SetProof();
      cover.append(cov);
    }

    // Get client pk set
    QList<QSharedPointer<const PublicKey> > client_pks;
    client_pks.append(c.GetOneTimeKey());
    for(int i=0; i<ncover; i++) {
      client_pks.append(cover[i].GetOneTimeKey());
    }

    QSharedPointer<const PublicKeySet> client_pk_set(new PublicKeySet(params, client_pks));

    ASSERT_TRUE(c.GetChallenge1() > 0 || c.GetChallenge1() < params->GetQ());
    ASSERT_TRUE(c.GetChallenge2() > 0 || c.GetChallenge2() < params->GetQ());
    ASSERT_TRUE(c.GetResponse1() > 0 || c.GetResponse1() < params->GetQ());
    ASSERT_TRUE(c.GetResponse2() > 0 || c.GetResponse2() < params->GetQ());

    // Make sure all values are distinct
    QSet<QByteArray> set;
    set.insert(c.GetChallenge1().GetByteArray());
    set.insert(c.GetChallenge2().GetByteArray());
    set.insert(c.GetResponse1().GetByteArray());
    set.insert(c.GetResponse2().GetByteArray());
    ASSERT_EQ(4, set.count());

    ASSERT_TRUE(c.VerifyProof());

    Plaintext out(params);
    out.Reveal(c.GetElement());

    for(int i=0; i<nkeys; i++) {
      ServerCiphertext s(params, client_pk_set);
      s.SetProof(server_sks[i]);

      ASSERT_TRUE(s.VerifyProof(server_pks[i]));

      out.Reveal(s.GetElement()); 
    }

    for(int i=0; i<ncover; i++) {
      out.Reveal(cover[i].GetElement());
    }

    ASSERT_EQ(m.GetInteger(), out.GetInteger());
  }

  void EndToEndOnce()
  {
    const int nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    const int nclients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    const int author_idx = Random::GetInstance().GetInt(0, nclients);
    QSharedPointer<const Parameters> params = Parameters::Parameters::Testing();

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

  TEST(BlogDrop, EndToEndNoThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::SingleThreaded);
    EndToEndOnce();
    cf.SetThreading(t);
  }

  TEST(BlogDrop, EndToEndThreads) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType t = cf.GetThreadingType();
    
    cf.SetThreading(CryptoFactory::MultiThreaded);
    EndToEndOnce();
    cf.SetThreading(t);
  }

  TEST(BlogDrop, BenchmarkIntegerGroup) {
    // Use full parameters (not testing)
    QSharedPointer<const Parameters> params = Parameters::Parameters::Fixed();

    // Get random integer a in [1, q)
    Integer a = params->RandomExponent();

    // a = take b^a 
    Integer b = params->GetG();
    for(int i=0; i<1000; i++) {
      b = b.Pow(a, params->GetP());
      EXPECT_TRUE(a>0);
    }
  }

  TEST(BlogDrop, BenchmarkEllipticCurveGroup) {
    // RFC 5903 - 256-bit curve
    const char *modulus = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    const char *b = "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";

    const char *q = "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    const char *gx = "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    const char *gy = "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

    CryptoPP::Integer m(modulus);
    ASSERT_TRUE(CryptoPP::IsPrime(m));

    // a = -3
    CryptoPP::ECP ecp(CryptoPP::Integer(modulus), CryptoPP::Integer(-3L), CryptoPP::Integer(b));

    CryptoPP::Integer i_gx(gx);
    CryptoPP::Integer i_gy(gy);
    CryptoPP::ECPPoint g(i_gx, i_gy);

    ASSERT_TRUE(ecp.VerifyPoint(g));
    
    // Get random integer a in [1, q)
    Integer tmp = Integer::GetRandomInteger(0, Integer(QByteArray(q)), false); 
    CryptoPP::Integer exp_a(tmp.GetByteArray().constData());

    // a = take g^a 
    CryptoPP::ECPPoint point_b = g;
    for(int i=0; i<4000; i++) {
      point_b = ecp.ScalarMultiply(point_b, exp_a);
    }
  }

}
}
