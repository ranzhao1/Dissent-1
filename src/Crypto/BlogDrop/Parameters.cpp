#include <QByteArray>

#include <pbc/pbc.h>

#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Crypto/AbstractGroup/OpenECGroup.hpp"
#include "Crypto/AbstractGroup/PairingG1Group.hpp"
#include "Crypto/AbstractGroup/PairingGTGroup.hpp"
#include "Parameters.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerTestingFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::TestingFixed();
    return QSharedPointer<Parameters>(new Parameters(QByteArray(), fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::Production2048Fixed();
    return QSharedPointer<Parameters>(new Parameters(round_nonce, fixed, fixed, 1));
  }

  QSharedPointer<Parameters> Parameters::CppECProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = CppECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(new Parameters(round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::OpenECProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = OpenECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(new Parameters(round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::PairingProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> g1 = PairingG1Group::ProductionFixed();
    QSharedPointer<const AbstractGroup> gT = PairingGTGroup::ProductionFixed();
    return QSharedPointer<Parameters>(new Parameters(round_nonce, g1, gT, 8));
  }

  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() : _n_elements(0) {}

  Parameters::Parameters(QByteArray round_nonce,
      QSharedPointer<const AbstractGroup> key_group, 
      QSharedPointer<const AbstractGroup> msg_group, 
      int n_elements) :
    _round_nonce(round_nonce),
    _key_group(key_group),
    _msg_group(msg_group),
    _n_elements(n_elements)
  {
    Q_ASSERT(!_key_group.isNull());
    Q_ASSERT(!_msg_group.isNull());
    Q_ASSERT(key_group->IsProbablyValid());
    Q_ASSERT(msg_group->IsProbablyValid());
  }
  
  QByteArray Parameters::GetByteArray() const
  {
    QByteArray out;
    out += GetRoundNonce();
    out += GetKeyGroup()->GetByteArray();
    out += GetMessageGroup()->GetByteArray();
    out += _n_elements;
    return out;
  }

  bool Parameters::UsesPairing() const
  {
    const AbstractGroup *a1 = GetKeyGroup().data();
    const AbstractGroup *aT = GetMessageGroup().data();

    const PairingG1Group *g1p = dynamic_cast<const PairingG1Group*>(a1);
    const PairingGTGroup *gTp = dynamic_cast<const PairingGTGroup*>(aT);

    return ((g1p != NULL) && (gTp != NULL));
  }

  Element Parameters::ApplyPairing(const Element &a, const Element &b) const 
  {
    if(!UsesPairing()) qFatal("Parameters do not use pairing");

    const PairingGTGroup *gTp = dynamic_cast<const PairingGTGroup*>(GetMessageGroup().data());
    Q_ASSERT(gTp);

    return gTp->ApplyPairing(a, b);
  }
}
}
}
