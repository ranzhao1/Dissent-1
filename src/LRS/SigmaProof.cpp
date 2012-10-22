
#include "SigmaProof.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  QVariant SigmaProof::IntegerToVariant(Integer i) const
  {
    return QVariant(i.GetByteArray());
  }

  Integer SigmaProof::VariantToInteger(QVariant v) const
  {
    return Integer(v.toByteArray());
  }

  QByteArray SigmaProof::CreateChallenge(QList<QByteArray> commits)
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    for(int i=0; i<commits.count(); i++) {
      hash->Update(commits[i]);
    }

    return hash->ComputeHash();
  }

}
}
