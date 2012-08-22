
#include "CiphertextFactory.hpp"
#include "ElGamalClientCiphertext.hpp"
#include "ElGamalServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<ClientCiphertext> CiphertextFactory::CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub)
  {
    return QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
          params, server_pks, author_pub));
  }
 
  QSharedPointer<ClientCiphertext> CiphertextFactory::CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized)
  {
    return QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
          params, server_pks, author_pub, serialized));
  }

  QSharedPointer<ServerCiphertext> CiphertextFactory::CreateServerCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts)
  {
    // keys[client][element] = key
    QList<QList<QSharedPointer<const PublicKey> > > keys;
    const ElGamalClientCiphertext *eg;
    for(int client_idx=0; client_idx<client_ctexts.count(); client_idx++) {
      eg = dynamic_cast<const ElGamalClientCiphertext*>(client_ctexts[client_idx].data());

      keys.append(eg->GetOneTimeKeys());
    }

    // _client_pks[element] = PublicKeySet for element
    QList<QSharedPointer<const PublicKeySet> > client_pks = PublicKeySet::CreateClientKeySets(params, keys);

    return QSharedPointer<ServerCiphertext>(new ElGamalServerCiphertext(params, client_pks));
  }

  QSharedPointer<ServerCiphertext> CiphertextFactory::CreateServerCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts, 
      const QByteArray &serialized)
  {
    // keys[client][element] = key
    QList<QList<QSharedPointer<const PublicKey> > > keys;
    const ElGamalClientCiphertext *eg;
    for(int client_idx=0; client_idx<client_ctexts.count(); client_idx++) {
      eg = dynamic_cast<const ElGamalClientCiphertext*>(client_ctexts[client_idx].data());

      keys.append(eg->GetOneTimeKeys());
    }

    // _client_pks[element] = PublicKeySet for element
    QList<QSharedPointer<const PublicKeySet> > client_pks = PublicKeySet::CreateClientKeySets(params, keys);

    return QSharedPointer<ServerCiphertext>(new ElGamalServerCiphertext(params, client_pks, serialized));
  }

}
}
}
