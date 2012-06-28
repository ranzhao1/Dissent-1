#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Authenticator, Null) {

    NullAuthenticator auth;
    QSharedPointer<MockSource> source(new MockSource());
    QSharedPointer<MockSender> sender(new MockSender(source));
    Group group;
    PrivateIdentity prover, verifier;

    QVariantHash chal = auth.MakeChallenge(group, sender);
    QVariantHash resp = auth.MakeResponse(group, prover, chal);

    EXPECT_TRUE(auth.VerifyResponse(verifier, group, sender, resp));
  }

  TEST(Authenticator, PubKey) {

    PubKeyAuthenticator auth;
    QSharedPointer<MockSource> source(new MockSource());
    QSharedPointer<MockSender> sender(new MockSender(source));
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    PrivateIdentity prover(Id::Zero(),
        QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey("abc")),
        QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman("abc")));
    PrivateIdentity verifier(Id::Zero(),
        QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey("def")),
        QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman("def")));

    QVector<PublicIdentity> roster;
    roster.append(GetPublicIdentity(verifier));

    Group group(roster);

    QVariantHash chal = auth.MakeChallenge(group, sender);
    QVariantHash resp = auth.MakeResponse(group, prover, chal);

    EXPECT_TRUE(auth.VerifyResponse(verifier, group, sender, resp));
  }
}
}
