
#include "BlogDropAuthor.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropAuthor::BlogDropAuthor(const QSharedPointer<Parameters> params, 
      const QSharedPointer<PublicKeySet> server_pks,
      const QSharedPointer<PrivateKey> author_priv) :
    BlogDropClient(params, server_pks, QSharedPointer<PublicKey>(new PublicKey(*author_priv))),
    _author_priv(author_priv)
  {
  }

  bool BlogDropAuthor::GenerateAuthorCiphertext(ClientCiphertext &out, const QByteArray &in) const
  {
    if(in.count() > MaxPlaintextLength()) return false;

    Plaintext m(*GetParameters()); 
    QByteArray extra = m.Encode(in);
    if(extra.count()) return false;

    out = ClientCiphertext(*GetParameters(), *GetServerKeys(), *GetAuthorKey());
    out.SetAuthorProof(*_author_priv, m);
    return true;
  }

}
}
}
