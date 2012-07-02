
#include <QFile>

#include "PublicIdentity.hpp"

namespace Dissent {
namespace Identity {

  bool PublicIdentity::Save(const QString &filename) const
  {
    QFile file(filename);

    if(!file.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
      qWarning() << "Error (" << file.error() << ") saving file: " << filename;
      return false;
    }

    QDataStream stream(&file);

    stream << _id.GetByteArray();
    stream << _verification_key->GetByteArray();
    stream << _dh_key;
    stream << _super_peer;

    file.close();

    return true;
  }

}
}

