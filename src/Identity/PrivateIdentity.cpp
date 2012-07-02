#include <QDataStream>
#include <QFile>
#include "PrivateIdentity.hpp"

namespace Dissent {
namespace Identity {

  bool PrivateIdentity::Save(const QString &filename) const
  {
    QFile file(filename);

    if(!file.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
      qWarning() << "Error (" << file.error() << ") saving file: " << filename;
      return false;
    }

    QDataStream stream(&file);

    stream << _local_id << _signing_key->GetByteArray() << _dh_key->GetByteArray() << _super_peer;

    file.close();

    return true;
  }

  bool PrivateIdentity::InitFromFile(const QString &filename)
  {
    QFile file(filename);
    if(!file.exists()) {
      qWarning() << "File" << filename << "does not exist";
      return false;
    }

    if(!file.open(QIODevice::ReadOnly)) {
      qWarning() << "Error (" << file.error() << ") saving file: " << filename;
      return false;
    }

    QDataStream stream(&file);
    QByteArray id, signing_key, dh;
    stream >> _local_id >> signing_key >> dh >> _super_peer;

    if(!_signing_key->InitFromByteArray(signing_key)) return false;
    if(!_dh_key->InitFromByteArray(dh)) return false;
    
    file.close();
    
    return true;
  }

}
}
