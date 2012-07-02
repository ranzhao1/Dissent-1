
#include "Crypto/Library.hpp"
#include "RosterAuthenticate.hpp"
#include "RosterAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  RosterAuthenticator::RosterAuthenticator(const PrivateIdentity &ident,
      const QList<PublicIdentity> &roster) :
    _ident(ident),
    _roster(roster),
    _lib(Crypto::CryptoFactory::GetInstance().GetLibrary()) 
  {
    QDataStream stream(&_pub_ident_bytes, QIODevice::WriteOnly);
    stream << GetPublicIdentity(ident);
  }

  QVariant RosterAuthenticator::RequestChallenge(const Id &member, const QVariant &data)
  {
    QList<QVariant> in;
    QList<QVariant> out;

    if(!data.canConvert(QVariant::List)) {
      qWarning() << "Invalid challenge request";
      return QVariant();
    }

    in = data.toList();
    if(in.count() != 2 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray)) {
      qWarning() << "Invalid challenge request";
      return QVariant();
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    nonce = a random challenge value
     *    pub   = authenticating member's public identity
     */
    QByteArray nonce_1 = in[0].toByteArray();
    QByteArray other_ident = in[1].toByteArray();

    QByteArray nonce_2(RosterAuthenticate::ChallengeNonceLength, 0);
    _lib->GetRandomNumberGenerator()->GenerateBlock(nonce_2);

    QByteArray to_sign;
    to_sign.append(other_ident);
    to_sign.append(nonce_1);
    to_sign.append(nonce_2);

    out.append(_pub_ident_bytes);
    out.append(nonce_2);
    out.append(_ident.GetSigningKey()->Sign(to_sign));

    _nonces.remove(member);
    _nonces[member] = QPair<QByteArray,QByteArray>(other_ident, nonce_2);

    return out;
  }

  QPair<bool, PublicIdentity> RosterAuthenticator::VerifyResponse(const Id &member,
      const QVariant &data) {

    const QPair<bool, PublicIdentity> invalid(false, PublicIdentity());

    if(!_nonces.contains(member)) {
      qWarning() << "Got ChallengeResponse for unknown member";
      return invalid;
    }

    if(!data.canConvert(QVariant::ByteArray)) {
      qWarning() << "Got invalid ChallengeResponse data";
      return invalid;
    }

    QByteArray sig = data.toByteArray();

    QByteArray to_verify;
    to_verify.append(_pub_ident_bytes);
    to_verify.append(_nonces[member].second);

    PublicIdentity pub;
    QDataStream stream(&_nonces[member].first, QIODevice::ReadOnly);
    stream >> pub;

    _nonces.remove(member);

    if(!pub.GetVerificationKey()->Verify(to_verify, sig)) {
      qWarning() << "Invalid signature";
      return invalid;
    }

    return QPair<bool, PublicIdentity>(true, pub);
  }

}
}
}

