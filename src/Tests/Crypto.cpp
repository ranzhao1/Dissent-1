#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void AsymmetricKeyTest(Library *lib)
  {
    QScopedPointer<AsymmetricKey> key0(lib->CreatePrivateKey());
    EXPECT_TRUE(key0->IsValid());
    QScopedPointer<AsymmetricKey> pu_key0(key0->GetPublicKey());
    EXPECT_TRUE(pu_key0->IsValid());

    EXPECT_TRUE(key0->Save("private_key"));
    QScopedPointer<AsymmetricKey> key0_0(
        lib->LoadPrivateKeyFromFile(QString("private_key")));
    EXPECT_TRUE(key0_0->IsValid());
    QFile("private_key").remove();

    EXPECT_TRUE(pu_key0->Save("public_key"));
    QScopedPointer<AsymmetricKey> pu_key0_0(
        lib->LoadPublicKeyFromFile(QString("public_key")));
    EXPECT_TRUE(pu_key0_0->IsValid());
    QFile("public_key").remove();

    QScopedPointer<AsymmetricKey> key1(lib->CreatePrivateKey());
    EXPECT_TRUE(key1->IsValid());
    QScopedPointer<AsymmetricKey> pu_key1(key1->GetPublicKey());
    EXPECT_TRUE(pu_key1->IsValid());

    EXPECT_FALSE(pu_key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(pu_key0->VerifyKey(*pu_key1));
    EXPECT_TRUE(pu_key0->VerifyKey(*key0));
    EXPECT_FALSE(pu_key0->VerifyKey(*key1));

    EXPECT_FALSE(pu_key1->VerifyKey(*pu_key0));
    EXPECT_FALSE(pu_key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(pu_key1->VerifyKey(*key0));
    EXPECT_TRUE(pu_key1->VerifyKey(*key1));

    EXPECT_TRUE(key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(key0->VerifyKey(*pu_key1));
    EXPECT_FALSE(key0->VerifyKey(*key0));
    EXPECT_FALSE(key0->VerifyKey(*key1));

    EXPECT_FALSE(key1->VerifyKey(*pu_key0));
    EXPECT_TRUE(key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(key1->VerifyKey(*key0));
    EXPECT_FALSE(key1->VerifyKey(*key1));

    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1500, 0);
    rng->GenerateBlock(data);
    QByteArray small_data(10, 0);
    rng->GenerateBlock(small_data);
    QByteArray empty;

    QScopedPointer<AsymmetricKey> bad_key_mem(
        lib->LoadPrivateKeyFromByteArray(data));
    EXPECT_TRUE(!bad_key_mem->IsValid());
    QScopedPointer<AsymmetricKey> empty_key(bad_key_mem->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());

    QString filename = "test_private_key_load";
    EXPECT_FALSE(QFile(filename).exists());
    QScopedPointer<AsymmetricKey> bad_key_file(
        lib->LoadPrivateKeyFromFile(filename));

    EXPECT_FALSE(bad_key_file->IsValid());
    empty_key.reset(bad_key_file->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());

    if(key0->SupportsVerification()) {
      QByteArray sig0 = key0->Sign(data);
      QByteArray sig1 = key0_0->Sign(data);

      EXPECT_TRUE(pu_key0->Verify(data, sig0));
      EXPECT_TRUE(pu_key0->Verify(data, sig1));
      EXPECT_TRUE(pu_key0_0->Verify(data, sig0));
      EXPECT_TRUE(pu_key0_0->Verify(data, sig1));

      EXPECT_TRUE(pu_key0->Sign(data).isEmpty());
      EXPECT_TRUE(pu_key1->Sign(data).isEmpty());

      EXPECT_TRUE(key0->Verify(data, sig0));
      EXPECT_TRUE(key0->Verify(data, sig1));
      EXPECT_TRUE(key0_0->Verify(data, sig0));
      EXPECT_TRUE(key0_0->Verify(data, sig1));

      QByteArray sig = key1->Sign(data);
      EXPECT_TRUE(key1->Verify(data, sig));
      EXPECT_FALSE(key0->Verify(data, sig));
      sig = key1->Sign(small_data);
      EXPECT_TRUE(key1->Verify(small_data, sig));
      EXPECT_FALSE(key0->Verify(small_data, sig));
      sig = key1->Sign(empty);
      EXPECT_TRUE(key1->Verify(empty, sig));
      EXPECT_FALSE(key0->Verify(empty, sig));

      EXPECT_FALSE(key0->Verify(data, empty));
      EXPECT_FALSE(key0->Verify(data, small_data));
      EXPECT_FALSE(key0->Verify(data, data));

      EXPECT_FALSE(bad_key_mem->Verify(data, bad_key_mem->Sign(data)));
      EXPECT_FALSE(bad_key_file->Verify(data, bad_key_file->Sign(data)));
    }

    if(key0->SupportsEncryption()) {
      QByteArray out0_0 = key0->Encrypt(data);
      QByteArray out1_0 = key0_0->Encrypt(data);
      QByteArray out0_1 = key0->Decrypt(out0_0);
      QByteArray out1_1 = key0_0->Decrypt(out1_0);

      QByteArray other(1500, 0);
      rng->GenerateBlock(other);

      EXPECT_NE(out0_0, out1_0);
      EXPECT_EQ(data, out0_1);
      EXPECT_EQ(data, out1_1);
      EXPECT_NE(other, out0_1);
      EXPECT_NE(other, out1_1);
      EXPECT_NE(data, other);

      out0_0 = pu_key0->Encrypt(data);
      out1_0 = pu_key0_0->Encrypt(data);
      out0_1 = key0->Decrypt(out0_0);
      out1_1 = key0_0->Decrypt(out1_0);

      EXPECT_NE(out0_0, out1_0);
      EXPECT_EQ(data, out0_1);
      EXPECT_EQ(data, out1_1);
      EXPECT_NE(other, out0_1);
      EXPECT_NE(other, out1_1);
      EXPECT_NE(data, other);

      EXPECT_TRUE(pu_key0->Decrypt(out0_0).isEmpty());
      EXPECT_TRUE(pu_key0_0->Decrypt(out0_0).isEmpty());

      EXPECT_TRUE(key0->Decrypt(data).isEmpty());
      EXPECT_TRUE(key1->Decrypt(small_data).isEmpty());
      EXPECT_TRUE(key1->Decrypt(empty).isEmpty());

      QByteArray ciphertext = key0->Encrypt(data);
      EXPECT_TRUE(key1->Decrypt(ciphertext).isEmpty());

      ciphertext = key1->Encrypt(empty);
      EXPECT_EQ(key1->Decrypt(ciphertext), empty);

      EXPECT_TRUE(bad_key_mem->Encrypt(data).isEmpty());
      EXPECT_TRUE(bad_key_mem->Decrypt(key1->Encrypt(data)).isEmpty());

      EXPECT_TRUE(bad_key_file->Encrypt(data).isEmpty());
      EXPECT_TRUE(bad_key_file->Decrypt(key1->Encrypt(data)).isEmpty());
    }
  }

  void AsymmetricKeySerialization()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pkey(key->GetPublicKey());
    QSharedPointer<AsymmetricKey> key0, pkey0;
    EXPECT_NE(*key, *pkey);
    EXPECT_TRUE(key.data() != 0);
    EXPECT_TRUE(pkey.data() != 0);
    EXPECT_TRUE(key0.data() == 0);
    EXPECT_TRUE(pkey0.data() == 0);

    QByteArray data;
    QDataStream istream(&data, QIODevice::WriteOnly);
    istream << key << pkey;

    QDataStream ostream(data);
    ostream >> key0 >> pkey0;

    EXPECT_EQ(*key, *key0);
    EXPECT_EQ(*pkey, *pkey0);

    QByteArray msg(1024, 0);
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    rng->GenerateBlock(msg);

    QByteArray sig = key->Sign(msg);
    EXPECT_TRUE(pkey0->Verify(msg, sig));
    EXPECT_EQ(sig.size(), pkey0->GetSignatureLength());
  }

  void RngSpeedTest(Library *lib, int count)
  {
    QByteArray data(4096, 0);
    for(int idx = 0; idx < count; idx++) {
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator());
      rng->GenerateBlock(data);
    }
  }

  TEST(Crypto, RngSpeedTest1024)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    RngSpeedTest(lib.data(), 1024);
  }

  TEST(Crypto, RngSpeedTest2048)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    RngSpeedTest(lib.data(), 2048);
  }

  TEST(Crypto, RngSpeedTest4096)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    RngSpeedTest(lib.data(), 4096);
  }

  TEST(Crypto, RngSpeedTest8192)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    RngSpeedTest(lib.data(), 8192);
  }

  void KeySignSpeedTest(Library *lib)
  {
    QSharedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1024, 0);
    rng->GenerateBlock(data);

    for(int idx = 0; idx < 1024; idx++) {
      rng->GenerateBlock(data);
      key->Sign(data);
    }
  }

  void KeyVerificationSpeedTest(Library *lib)
  {
    QSharedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1024, 0);
    rng->GenerateBlock(data);

    for(int idx = 0; idx < 1024; idx++) {
      rng->GenerateBlock(data);
      QByteArray sig = key->Sign(data);
      EXPECT_TRUE(key->Verify(data, sig));
    }
  }

  TEST(Crypto, DSASignSpeedTest)
  {
    QScopedPointer<Library> lib(new CppDsaLibrary());
    KeySignSpeedTest(lib.data());
  }

  TEST(Crypto, DSAVerifySpeedTest)
  {
    QScopedPointer<Library> lib(new CppDsaLibrary());
    KeyVerificationSpeedTest(lib.data());
  }

  TEST(Crypto, RSASignSpeedTest)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    KeySignSpeedTest(lib.data());
  }

  TEST(Crypto, RSAVerifySpeedTest)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    KeyVerificationSpeedTest(lib.data());
  }

  void KeyGenerationFromIdTest(Library *lib)
  {
    Dissent::Connections::Id id0;
    Dissent::Connections::Id id1;
    EXPECT_NE(id0, id1);

    QScopedPointer<AsymmetricKey> pr_key0(lib->GeneratePrivateKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pu_key0(lib->GeneratePublicKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key1(lib->GeneratePrivateKey(id1.GetByteArray()));
    QScopedPointer<AsymmetricKey> pu_key1(lib->GeneratePublicKey(id1.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key0_0(lib->GeneratePrivateKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key1_0(lib->GeneratePrivateKey(id1.GetByteArray()));

    EXPECT_TRUE(pr_key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_TRUE(pr_key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_EQ(*pr_key0, *pr_key0_0);
    EXPECT_EQ(*pr_key1, *pr_key1_0);
    EXPECT_FALSE(*pr_key0 == *pr_key1);

    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1500, 0);
    rng->GenerateBlock(data);

    QScopedPointer<AsymmetricKey> pu_key0_0(pr_key0->GetPublicKey());
    EXPECT_EQ(pu_key0->GetByteArray(), pu_key0_0->GetByteArray());
    EXPECT_EQ(pr_key0->GetByteArray(), pr_key0_0->GetByteArray());

    if(pu_key0->SupportsEncryption()) {
      QByteArray enc = pu_key0->Encrypt(data);
      QByteArray dec0 = pr_key0->Decrypt(enc);
      QByteArray dec0_0 = pr_key0_0->Decrypt(enc);
      EXPECT_EQ(data, dec0);
      EXPECT_EQ(data, dec0_0);
    }

    if(pu_key0->SupportsVerification()) {
      QByteArray sig0 = pr_key0->Sign(data);
      QByteArray sig0_0 = pr_key0_0->Sign(data);
      EXPECT_TRUE(pu_key0->Verify(data, sig0));
      EXPECT_TRUE(pu_key0->Verify(data, sig0_0));
    }
  }

  void DiffieHellmanTest(Library *lib)
  {
    QScopedPointer<DiffieHellman> dh0(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dh1(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dh2(lib->CreateDiffieHellman());

    QByteArray shared_0_1 = dh0->GetSharedSecret(dh1->GetPublicComponent());
    QByteArray shared_1_0 = dh1->GetSharedSecret(dh0->GetPublicComponent());
    QByteArray shared_0_2 = dh0->GetSharedSecret(dh2->GetPublicComponent());
    QByteArray shared_2_0 = dh2->GetSharedSecret(dh0->GetPublicComponent());
    QByteArray shared_1_2 = dh1->GetSharedSecret(dh2->GetPublicComponent());
    QByteArray shared_2_1 = dh2->GetSharedSecret(dh1->GetPublicComponent());
    EXPECT_EQ(shared_0_1, shared_1_0);
    EXPECT_EQ(shared_0_2, shared_2_0);
    EXPECT_EQ(shared_1_2, shared_2_1);
    EXPECT_NE(shared_0_1, shared_0_2);
    EXPECT_NE(shared_0_1, shared_1_2);

    QScopedPointer<DiffieHellman> dh0_0(lib->LoadDiffieHellman(dh0->GetPrivateComponent()));
    EXPECT_EQ(dh0->GetPublicComponent(), dh0_0->GetPublicComponent());
    EXPECT_EQ(dh0->GetPrivateComponent(), dh0_0->GetPrivateComponent());

    Id id;
    QScopedPointer<DiffieHellman> dh3_0(lib->GenerateDiffieHellman(id.GetByteArray()));
    QScopedPointer<DiffieHellman> dh3_1(lib->GenerateDiffieHellman(id.GetByteArray()));
    EXPECT_EQ(dh3_0->GetPublicComponent(), dh3_1->GetPublicComponent());
    EXPECT_EQ(dh3_0->GetPrivateComponent(), dh3_1->GetPrivateComponent());
  }

  void ZeroKnowledgeTest(Library* lib, bool test_bit_flip) 
  {
    QScopedPointer<DiffieHellman> dhA(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dhB(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dhC(lib->CreateDiffieHellman());

    QByteArray shared_A_B = dhA->GetSharedSecret(dhB->GetPublicComponent());
    QByteArray shared_B_A = dhB->GetSharedSecret(dhA->GetPublicComponent());
    EXPECT_EQ(shared_A_B, shared_B_A);

    QByteArray proof_A = dhA->ProveSharedSecret(dhB->GetPublicComponent());
    QByteArray verif_A = dhC->VerifySharedSecret(dhA->GetPublicComponent(), dhB->GetPublicComponent(), proof_A);
    EXPECT_EQ(shared_A_B, verif_A);

    if(test_bit_flip) {
      int idx = proof_A.size()-1;
      proof_A[idx] = !proof_A[idx];
      QByteArray verif_A2 = dhC->VerifySharedSecret(dhA->GetPublicComponent(), dhB->GetPublicComponent(), proof_A);
      EXPECT_EQ(QByteArray(), verif_A2);
    }
  }

  TEST(Crypto, CppAsymmetricKey)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    AsymmetricKeyTest(lib.data());

    QScopedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    EXPECT_EQ(key->GetKeySize(),
        std::max(AsymmetricKey::DefaultKeySize, lib->MinimumKeySize()));
  }

  TEST(Crypto, CppKeySerialization)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    AsymmetricKeySerialization();
    cf.SetLibrary(cname);
  }

  TEST(Crypto, CppDsaAsymmetricKey)
  {
    QScopedPointer<Library> lib(new CppDsaLibrary());
    AsymmetricKeyTest(lib.data());

    QScopedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    EXPECT_EQ(key->GetKeySize(),
        std::max(AsymmetricKey::DefaultKeySize, lib->MinimumKeySize()));
  }

  TEST(Crypto, CppDsaKeySerialization)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPPDsa);
    AsymmetricKeySerialization();
    cf.SetLibrary(cname);
  }

  TEST(Crypto, NullAsymmetricKey)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    AsymmetricKeyTest(lib.data());
  }

  TEST(Crypto, NullKeySerialization)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::Null);
    AsymmetricKeySerialization();
    cf.SetLibrary(cname);
  }

  TEST(Crypto, CppDiffieHellman)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    DiffieHellmanTest(lib.data());
  }

  TEST(Crypto, NullDiffieHellman)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    DiffieHellmanTest(lib.data());
  }

  TEST(Crypto, NullZeroKnowledgeDhTest)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    ZeroKnowledgeTest(lib.data(), false);
  }

  TEST(Crypto, CppZeroKnowledgeDhTest)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    ZeroKnowledgeTest(lib.data(), false);
  }
}
}
