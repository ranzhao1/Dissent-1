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
    TestPlaintextEmpty(Parameters::Parameters::CppECProductionFixed());
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
    TestPlaintextShort(Parameters::Parameters::CppECProductionFixed());
  }

  void TestPlaintextRandom(QSharedPointer<const Parameters> params, int divby)
  {
    Plaintext p(params);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    EXPECT_EQ(params->GetGroupOrder(), params->GetKeyGroup()->GetOrder());
    EXPECT_EQ(params->GetGroupOrder(), params->GetMessageGroup()->GetOrder());

    for(int i=0; i<1000; i++) {
      QByteArray msg(Plaintext::CanFit(params)/divby, 0);
      rand->GenerateBlock(msg);

      p.Encode(msg);

      QByteArray output;
      EXPECT_TRUE(p.Decode(output));
      EXPECT_TRUE(output.count() > 0);
      EXPECT_TRUE(output.count() < (params->GetNElements()*
            (params->GetMessageGroup()->GetOrder().GetByteCount()/divby)));
      EXPECT_TRUE(output.count() > (params->GetNElements()*
            ((params->GetMessageGroup()->GetOrder().GetByteCount()-5)/divby)));
      EXPECT_EQ(msg, output);
    }
  }

  TEST(BlogDrop, IntegerPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::IntegerTestingFixed(), 4);
  }

  TEST(BlogDrop, ECPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::CppECProductionFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::CppECProductionFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::CppECProductionFixed(), 4);
  }

  void TestKeys(QSharedPointer<const Parameters> params)
  {
    for(int i=0; i<20; i++) {
      PrivateKey priv(params);
      Integer x = priv.GetInteger();

      PublicKey pub(priv);
      Element gx = pub.GetElement();

      ASSERT_TRUE(x < params->GetKeyGroup()->GetOrder());
      ASSERT_TRUE(x > 0);
      ASSERT_EQ(gx, params->GetKeyGroup()->Exponentiate(params->GetKeyGroup()->GetGenerator(), x));

      PrivateKey priv2(params);
      PublicKey pub2(priv);

      QByteArray proof = pub.ProveKnowledge(priv);
      ASSERT_TRUE(pub.VerifyKnowledge(proof));

      QByteArray proof2 = pub.ProveKnowledge(priv2);
      ASSERT_FALSE(pub.VerifyKnowledge(proof2));
    }
  }

  TEST(BlogDrop, IntegerKeys) {
    TestKeys(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECKeys) {
    TestKeys(Parameters::Parameters::CppECProductionFixed());
  }

  void TestPublicKeySet(QSharedPointer<const Parameters> params)
  {
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QList<QSharedPointer<const PublicKey> > keys;
    Element prod = params->GetKeyGroup()->GetIdentity();
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      keys.append(pub);

      prod = params->GetKeyGroup()->Multiply(prod, pub->GetElement());
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetElement());
  }

  TEST(BlogDrop, IntegerPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::CppECProductionFixed());
  }

  void TestElGamalServerCiphertext(QSharedPointer<const Parameters> params)
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

      EXPECT_FALSE(params.isNull());
      ElGamalServerCiphertext c(params, sets);
      c.SetProof(server_sk);

      for(int j=0; j<params->GetNElements(); j++) {
        Element expected = params->GetMessageGroup()->Exponentiate(sets[j]->GetElement(), 
            server_sk->GetInteger());
        expected = params->GetMessageGroup()->Inverse(expected);
        ASSERT_EQ(params->GetNElements(), c.GetElements().count());
        ASSERT_EQ(expected, c.GetElements()[j]);
      }

      ASSERT_TRUE(c.VerifyProof(server_pk));
    }
  }

  TEST(BlogDrop, IntegerServerCiphertext) {
    TestElGamalServerCiphertext(Parameters::Parameters::IntegerTestingFixed());
  }

  TEST(BlogDrop, ECServerCiphertext) {
    TestElGamalServerCiphertext(Parameters::Parameters::CppECProductionFixed());
  }

  void TestElGamalClientOnce(QSharedPointer<const Parameters> params)
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
    ElGamalClientCiphertext c(params, server_pk_set, author_pk);
    c.SetProof();

    const Integer q = params->GetGroupOrder();
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
      TestElGamalClientOnce(Parameters::Parameters::IntegerTestingFixed());
    }
  }

  TEST(BlogDrop, ECClientProof) {
    for(int i=0; i<10; i++) {
      TestElGamalClientOnce(Parameters::Parameters::CppECProductionFixed());
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
    ElGamalClientCiphertext c(params, server_pk_set, author_pk);
    c.SetAuthorProof(author_priv, m);

    const Integer q = params->GetGroupOrder();
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
      TestAuthorOnce(Parameters::Parameters::CppECProductionFixed());
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
    ElGamalClientCiphertext c(params, server_pk_set, author_pk);
    c.SetAuthorProof(author_priv, m);

    // Generate non-author ciphertext
    QList<QSharedPointer<const ElGamalClientCiphertext> > cover;
    const int ncover = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<ncover; i++) {
      QSharedPointer<ElGamalClientCiphertext> cov(new ElGamalClientCiphertext(params, server_pk_set, author_pk));
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

    const Integer q = params->GetGroupOrder();
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
      ElGamalServerCiphertext s(params, sets);
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
      TestReveal(Parameters::Parameters::CppECProductionFixed());
    }
  }

  void EndToEndOnce(QSharedPointer<const Parameters> params, bool random = true)
  {
    int nservers; 
    int nclients; 
    int author_idx;
    if(random) {
      nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      nclients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      author_idx = Random::GetInstance().GetInt(0, nclients);
    } else {
      nservers = 10;
      nclients = 100;
      author_idx = 0;
    }

    // Generate an author PK
    const QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    const QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    qDebug() << "SERVER_PK";
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

    qDebug() << "CREATE_SERVER";
    QList<BlogDropServer> servers;
    for(int i=0; i<nservers; i++) {
      servers.append(BlogDropServer(params, server_pk_set, author_pk, server_sks[i]));
    }

    qDebug() << "RANDOM_PLAINTEXT";
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

    qDebug() << "CLIENTS";
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

    qDebug() << "ADD_CLIENT_TO_SERVER";
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      servers[server_idx].AddClientCiphertexts(for_servers[server_idx]);
    }

    qDebug() << "CLOSE_BIN";
    // Generate server ciphertext and pass it to all servers
    QList<QByteArray> s;
    for(int i=0; i<nservers; i++) {
      s.append(servers[i].CloseBin());
    }

    qDebug() << "ADD_SERVER_TO_SERVER";
    for(int i=0; i<nservers; i++) {
      for(int j=0; j<nservers; j++) {
        ASSERT_TRUE(servers[j].AddServerCiphertext(servers[i].GetPublicKey(), s[i]));
      }
    }

    qDebug() << "REVEAL";
    // Reveal the plaintext
    for(int i=0; i<nservers; i++) {
      qDebug() << "REVEAL" << i;
      QByteArray out;
      ASSERT_TRUE(servers[i].RevealPlaintext(out));
      ASSERT_EQ(msg, out);
    }
  }

  TEST(BlogDrop, IntgerEndToEnd) 
  {
    EndToEndOnce(Parameters::Parameters::IntegerProductionFixed(), false);
  }

  TEST(BlogDrop, CppECEndToEnd) 
  {
    EndToEndOnce(Parameters::Parameters::CppECProductionFixed(), false);
  }

  TEST(BlogDrop, OpenECEndToEnd) 
  {
    EndToEndOnce(Parameters::Parameters::OpenECProductionFixed(), false);
  }

  void BenchmarkGroup(QSharedPointer<const Parameters> params,
      QSharedPointer<const AbstractGroup> group)
  {
    Element a1 = group->RandomElement();
    Integer e1 = group->RandomExponent();
    Element a2 = group->RandomElement();
    Integer e2 = group->RandomExponent();
    for(int i=0; i<(100*params->GetNElements()); i++) {
      Element res = group->CascadeExponentiate(a1, e1, a2, e2);
      //Element res = group->Exponentiate(a1, e1);
    }
  }

  void Benchmark(QSharedPointer<const Parameters> params)
  {
    BenchmarkGroup(params, params->GetMessageGroup());
    BenchmarkGroup(params, params->GetKeyGroup());
  }

  TEST(BlogDrop, BenchmarkInteger) 
  {
    Benchmark(Parameters::Parameters::IntegerProductionFixed());
  }

  TEST(BlogDrop, BenchmarkCppEC) 
  {
    Benchmark(Parameters::Parameters::CppECProductionFixed());
  }

  TEST(BlogDrop, BenchmarkOpenEC) 
  {
    Benchmark(Parameters::Parameters::OpenECProductionFixed());
  }

  TEST(BlogDrop, BenchmarkIntegerRaw) 
  {
    const char *bytes_p = "0xfddb8c605ec022e00980a93695b6e16f776f8db658c40163d"
                          "2cfb2f57d0d685076311697065cf78657fa6819000e9ea923c1"
                          "b488cd734f7c8585e97f7515bad667ecba98c4c271db8126703"
                          "a4d4e62238aad384d69f5ccb77fa0fb2569879ca672be6a9228"
                          "0ada08627be1b96371964b35f0e8ac655014a9293ac9dcf1e26"
                          "c9a43a4027ee504d06d60d3819dabaec3268b950932376d146a"
                          "75debb715b366e6fbc3efbb31960382798496dab78f03460b99"
                          "cf204153084ea8e6a6a32fcefa8106f0a1e24246681ba0e2e47"
                          "365d7e84016fd3e2f3ed72022a61c981c3194206d727fceab01"
                          "781cdcc0d3b2c680aa7573471fe781c2e081354cbcf7e94a6a1"
                          "c9df";
    const char *bytes_g = "0x02";

    CryptoPP::Integer p(bytes_p);
    CryptoPP::Integer g(bytes_g);

    CryptoPP::Integer b = g;
    for(int i=0; i<10000; i++) {
      // Get random integer a in [1, q)
      Integer tmp = Integer::GetRandomInteger(0, 
          Integer((Integer(QByteArray::fromHex(bytes_p))-1)/2), false); 
      CryptoPP::Integer exp_a(tmp.GetByteArray().constData());
      // a = take g^a 
      b = a_exp_b_mod_c(g, exp_a, p);
    }
  }
   
  TEST(BlogDrop, BenchmarkECRaw) {
    // RFC 5903 - 256-bit curve
    const char *modulus = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFF"
                          "FFFFFFFFFFFFFFF";
    const char *b =       "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63"
                          "BCE3C3E27D2604B";
    const char *q =       "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F"
                          "3B9CAC2FC632551";
    const char *gx =      "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F"
                          "4A13945D898C296";
    const char *gy =      "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECEC"
                          "BB6406837BF51F5";

    CryptoPP::Integer m(modulus);
    ASSERT_TRUE(CryptoPP::IsPrime(m));

    // a = -3
    CryptoPP::ECP ecp(CryptoPP::Integer(modulus), 
        CryptoPP::Integer(-3L), CryptoPP::Integer(b));

    CryptoPP::Integer i_gx(gx);
    CryptoPP::Integer i_gy(gy);
    CryptoPP::ECPPoint g(i_gx, i_gy);

    ASSERT_TRUE(ecp.VerifyPoint(g));

    // a = take g^a 
    CryptoPP::ECPPoint point_b;
    for(int i=0; i<10000; i++) {
      // Get random integer a in [1, q)
      Integer tmp = Integer::GetRandomInteger(0, Integer(QByteArray(q)), false); 
      CryptoPP::Integer exp_a(tmp.GetByteArray().constData());

      point_b = ecp.ScalarMultiply(g, exp_a);
    }
  }
}
}

