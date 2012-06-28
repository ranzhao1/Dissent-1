#include "Identity/PrivateIdentity.hpp"
#include "PubKeyAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Auth {

  PubKeyAuthenticator::PubKeyAuthenticator() :
    Authenticator(),
    _crypto(Crypto::CryptoFactory::GetInstance().GetLibrary())
  {}

  QVariantHash PubKeyAuthenticator::MakeChallengeLogic(const Group &, const QSharedPointer<ISender>)
  {
    QVariantHash hash;
  
    QByteArray bytes(64, '0'); 
    _crypto->GetRandomNumberGenerator()->GenerateBlock(bytes);
    hash["nonce"] = bytes;

    return hash;
  }

  QVariantHash PubKeyAuthenticator::MakeResponseLogic(const Group &group, 
      const PrivateIdentity &ident, const QVariantHash &chal)
  {
    QVariantHash data;

    // Get shared secret with the group leader
    QByteArray dh_secret = ident.GetDhKey()->GetSharedSecret(group.GetPublicDiffieHellman(group.GetLeader()));

    QByteArray ident_bytes;
    QDataStream stream(&ident_bytes, QIODevice::WriteOnly);
    stream << GetPublicIdentity(ident);

    data["ident"] = ident_bytes;

    Crypto::Hash* hash = _crypto->GetHashAlgorithm();
    hash->Restart();
    hash->Update(chal["nonce"].toByteArray());  // r
    hash->Update(dh_secret);                    // g^ab
    hash->Update(ident.GetDhKey()->GetPublicComponent());     // g^a

    data["resp"] = hash->ComputeHash();

    return data;
  }

  bool PubKeyAuthenticator::VerifyResponseLogic(const PrivateIdentity &verifier,
    const Group &, const QSharedPointer<ISender>, 
    const QVariantHash &chal, const QVariantHash &resp)
  {
   
    QDataStream stream(resp["ident"].toByteArray());
    PublicIdentity ident;
    stream >> ident;

    // Get shared secret with the group leader
    QByteArray dh_secret = verifier.GetDhKey()->GetSharedSecret(ident.GetDhKey());

    Crypto::Hash* hash = _crypto->GetHashAlgorithm();
    hash->Restart();
    hash->Update(chal["nonce"].toByteArray());  // r
    hash->Update(dh_secret);                    // g^ab
    hash->Update(ident.GetDhKey());     // g^a

    return (resp["resp"].toByteArray() == hash->ComputeHash());
  }
}
}
}
