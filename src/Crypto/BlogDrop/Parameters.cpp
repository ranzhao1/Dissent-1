#include <QByteArray>

#include <pbc/pbc.h>

#include "Crypto/AbstractGroup/ECGroup.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Crypto/AbstractGroup/PairingGroup.hpp"
#include "Parameters.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerTestingFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::TestingFixed();
    return QSharedPointer<Parameters>(new Parameters(fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerProductionFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::Production2048Fixed();
    return QSharedPointer<Parameters>(new Parameters(fixed, fixed, 1));
  }

  QSharedPointer<Parameters> Parameters::ECProductionFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = ECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(new Parameters(fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::PairingProductionFixed() 
  {
    QSharedPointer<const AbstractGroup> g1 = PairingGroup::ProductionG1Fixed();
    QSharedPointer<const AbstractGroup> gT = PairingGroup::ProductionGTFixed();
    return QSharedPointer<Parameters>(new Parameters(g1, gT, 8));
  }


  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() : _n_elements(0) {}

  Parameters::Parameters(QSharedPointer<const AbstractGroup> key_group, 
      QSharedPointer<const AbstractGroup> msg_group, int n_elements) :
    _key_group(key_group),
    _msg_group(msg_group),
    _n_elements(n_elements)
  {
    Q_ASSERT(!_key_group.isNull());
    Q_ASSERT(!_msg_group.isNull());
    Q_ASSERT(key_group->IsProbablyValid());
    Q_ASSERT(msg_group->IsProbablyValid());
  }
}
}
}
