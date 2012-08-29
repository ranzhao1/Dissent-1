
#include "CiphertextFactory.hpp"
#include "ElGamalClientCiphertext.hpp"
#include "ElGamalServerCiphertext.hpp"
#include "HashingGenClientCiphertext.hpp"
#include "PairingClientCiphertext.hpp"
#include "PairingServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<ClientCiphertext> CiphertextFactory::CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub)
  {
    QSharedPointer<ClientCiphertext> c;
    switch(params->GetProofType()) {
      case Parameters::ProofType_ElGamal:
        c = QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
              params, server_pks, author_pub));
        break;

      case Parameters::ProofType_Pairing:
        c = QSharedPointer<ClientCiphertext>(new PairingClientCiphertext(
              params, server_pks, author_pub));
        break;

      case Parameters::ProofType_HashingGenerator:
        c = QSharedPointer<ClientCiphertext>(new HashingGenClientCiphertext(
              params, server_pks, author_pub));
        break;

      default:
        qFatal("Invalid proof type");
    }
    
    return c;
  }
 
  QSharedPointer<ClientCiphertext> CiphertextFactory::CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized)
  {
    QSharedPointer<ClientCiphertext> c;
    switch(params->GetProofType()) {
      case Parameters::ProofType_ElGamal:
        c = QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
              params, server_pks, author_pub, serialized));
        break;

      case Parameters::ProofType_Pairing:
        c = QSharedPointer<ClientCiphertext>(new PairingClientCiphertext(
              params, server_pks, author_pub, serialized));
        break;

      case Parameters::ProofType_HashingGenerator:
        c = QSharedPointer<ClientCiphertext>(new HashingGenClientCiphertext(
              params, server_pks, author_pub, serialized));
        break;

      default:
        qFatal("Invalid proof type");
    }
    
    return c;
  }

  QSharedPointer<ServerCiphertext> CiphertextFactory::CreateServerCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> client_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts)
  {
    QSharedPointer<ServerCiphertext> s;
    if(params->UsesPairing()) {
      s = QSharedPointer<ServerCiphertext>(new PairingServerCiphertext(params, author_pub, client_pks));
    } else {
      // keys[client][element] = key
      QList<QList<QSharedPointer<const PublicKey> > > keys;
      const ElGamalClientCiphertext *eg;
      for(int client_idx=0; client_idx<client_ctexts.count(); client_idx++) {
        eg = dynamic_cast<const ElGamalClientCiphertext*>(client_ctexts[client_idx].data());

        keys.append(eg->GetOneTimeKeys());
      }

      // _client_pks[element] = PublicKeySet for element
      QList<QSharedPointer<const PublicKeySet> > client_pks = PublicKeySet::CreateClientKeySets(params, keys);
      s = QSharedPointer<ServerCiphertext>(new ElGamalServerCiphertext(params, author_pub, client_pks));
    }

    return s;
  }

  QSharedPointer<ServerCiphertext> CiphertextFactory::CreateServerCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> client_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts, 
      const QByteArray &serialized)
  {
    QSharedPointer<ServerCiphertext> s;
    if(params->UsesPairing()) {
      s = QSharedPointer<ServerCiphertext>(new PairingServerCiphertext(params, author_pub, client_pks, serialized));
    } else { 
      // keys[client][element] = key
      QList<QList<QSharedPointer<const PublicKey> > > keys;
      const ElGamalClientCiphertext *eg;
      for(int client_idx=0; client_idx<client_ctexts.count(); client_idx++) {
        eg = dynamic_cast<const ElGamalClientCiphertext*>(client_ctexts[client_idx].data());
        keys.append(eg->GetOneTimeKeys());
      }

      // _client_pks[element] = PublicKeySet for element
      QList<QSharedPointer<const PublicKeySet> > client_pks = PublicKeySet::CreateClientKeySets(params, keys);
      s = QSharedPointer<ServerCiphertext>(new ElGamalServerCiphertext(params, author_pub, client_pks, serialized));
    }
    
    return s;
  }

}
}
}
