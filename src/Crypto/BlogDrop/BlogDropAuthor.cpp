
#include "BlogDropAuthor.hpp"
#include "CiphertextFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropAuthor::BlogDropAuthor(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PrivateKey> author_priv) :
    BlogDropClient(params, server_pks, QSharedPointer<const PublicKey>(new PublicKey(author_priv))),
    _author_priv(author_priv)
  {
  }

  bool BlogDropAuthor::GenerateAuthorCiphertext(QByteArray &out,
      const QByteArray &in) const
  {
    const int can_fit = Plaintext::CanFit(GetParameters());
    if(in.count() > MaxPlaintextLength()) {
      qWarning() << "Plaintext is too long";
      return false; 
    }

    QByteArray data = in;

    Plaintext m(GetParameters()); 
    m.Encode(data.left(can_fit));

    if(data.count()) data = data.mid(can_fit);

    QSharedPointer<ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(
        GetParameters(), GetServerKeys(), GetAuthorKey());
    c->SetAuthorProof(_author_priv, m);
    out = c->GetByteArray();
    
    return !data.count();
  }

}
}
}
