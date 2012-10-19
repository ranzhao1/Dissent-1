
#include "SigmaProtocol.hpp"

namespace Dissent {
namespace LRS {

  QVariant SigmaProtocol::IntegerToVariant(Integer i)
  {
    return QVariant(i.GetByteArray());
  }

  Integer SigmaProtocol::VariantToInteger(QVariant v)
  {
    return Integer(v.toByteArray());
  }

}
}
