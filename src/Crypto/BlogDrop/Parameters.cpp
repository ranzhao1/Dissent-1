#include <QByteArray>

#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerTestingFixed() 
  {
    return QSharedPointer<Parameters>(new Parameters(IntegerGroup::TestingFixed()));
  }

  QSharedPointer<Parameters> Parameters::IntegerProductionFixed() 
  {
    return QSharedPointer<Parameters>(new Parameters(IntegerGroup::ProductionFixed()));
  }

  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() :
    _n_elements(ElementsPerCiphertext) {}

  Parameters::Parameters(QSharedPointer<const AbstractGroup> group) :
    _group(group),
    _n_elements(ElementsPerCiphertext)
  {
    Q_ASSERT(!group.isNull());
    Q_ASSERT(group->IsProbablyValid());
  }
}
}
}