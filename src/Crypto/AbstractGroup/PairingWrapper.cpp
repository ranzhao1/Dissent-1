
#include "PairingWrapper.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  PairingWrapper::PairingWrapper(QSharedPointer<const PairingG1Group> g1, 
      QSharedPointer<const PairingGTGroup> gT) :
    _g1(g1),
    _gT(gT),
    _pairing(g1->GetByteArray().constData(), g1->GetByteArray().count())
  {
    Q_ASSERT(_pairing.isPairingPresent());
    Q_ASSERT(g1->GetByteArray() == gT->GetByteArray());
    Q_ASSERT(_pairing.isSymmetric());
  };

  Element PairingWrapper::Apply(const Element &a1, const Element &a2) const
  {
    G1 g_a1(PairingElementData<G1>::GetElement(a1.GetData())); 
    G1 g_a2(PairingElementData<G1>::GetElement(a2.GetData())); 

    GT gt(_pairing.apply(g_a1, g_a2));
  
    return Element(new PairingElementData<GT>(gt));
  }

}
}
}
