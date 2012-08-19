#include <QByteArray>

#include "Crypto/AbstractGroup/ECGroup.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Parameters.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerTestingFixed() 
  {
    return QSharedPointer<Parameters>(new Parameters(IntegerGroup::TestingFixed(), 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerProductionFixed() 
  {
    return QSharedPointer<Parameters>(new Parameters(IntegerGroup::Production2048Fixed(), 1));
  }

  QSharedPointer<Parameters> Parameters::ECProductionFixed() 
  {
    return QSharedPointer<Parameters>(new Parameters(ECGroup::ProductionFixed(), 8));
  }

  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() : _n_elements(0) {}

  Parameters::Parameters(QSharedPointer<const AbstractGroup> group, int n_elements) :
    _group(group),
    _n_elements(n_elements)
  {
    Q_ASSERT(!group.isNull());
    Q_ASSERT(group->IsProbablyValid());
  }
}
}
}
