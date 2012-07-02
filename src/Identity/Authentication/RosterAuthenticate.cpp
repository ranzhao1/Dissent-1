#include <QList>
#include <QPair>

#include "Crypto/Library.hpp"
#include "RosterAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  RosterAuthenticate::RosterAuthenticate(const PrivateIdentity &ident,
      const PublicIdentity &leader) : 
    _ident(ident),
    _leader(leader),
    _lib(Crypto::CryptoFactory::GetInstance().GetLibrary()),
    _nonce_1(ChallengeNonceLength, 0)
  {
    QDataStream stream(&_ident_var, QIODevice::WriteOnly);
    stream << Identity::GetPublicIdentity(ident);

    QDataStream stream2(&_leader_bytes, QIODevice::WriteOnly);
    stream2 << _leader;
  }

  QVariant RosterAuthenticate::PrepareForChallenge()
  {
    QList<QVariant> list;
    _lib->GetRandomNumberGenerator()->GenerateBlock(_nonce_1);

    list.append(QVariant(_nonce_1));
    list.append(QVariant(_ident_var));

    return list;
  }

  QPair<bool, QVariant> RosterAuthenticate::ProcessChallenge(const QVariant &data)
  {
    const QPair<bool,QVariant> invalid(false, QVariant());
    QList<QVariant> in;

    if(!data.canConvert(QVariant::List)) {
      qWarning() << "Invalid challenge";
      return invalid;
    }

    in = data.toList();
    if(in.count() != 3 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray) ||
        !in[2].canConvert(QVariant::ByteArray)) {
      qWarning() << "Invalid challenge";
      return invalid;
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    pub    = leader's public identity
     *    nonce2 = session nonce
     *    sig    = sig{my_pk, nonce_1, nonce_2}
     */
    QByteArray in_leader_ident = in[0].toByteArray();
    QByteArray in_nonce_2 = in[1].toByteArray();
    QByteArray in_sig = in[2].toByteArray();


   
    QByteArray my_leader_ident;
    QDataStream stream(&my_leader_ident, QIODevice::WriteOnly);
    stream << _leader;

    if(in_leader_ident != my_leader_ident) {
      qWarning() << "Mismatched leader IDs";
      return invalid;
    }

    QByteArray to_verify;
    to_verify.append(_ident_var);
    to_verify.append(_nonce_1);
    to_verify.append(in_nonce_2);

    bool okay = _leader.GetVerificationKey()->Verify(to_verify, in_sig);
    if(!okay) {
      qWarning() << "Invalid leader signature";
      return invalid;
    }

    QByteArray to_sign;
    to_sign.append(_leader_bytes);
    to_sign.append(in_nonce_2);

    QByteArray out = _ident.GetSigningKey()->Sign(to_sign);

    return QPair<bool, QVariant>(true, out);
  }

}
}
}
