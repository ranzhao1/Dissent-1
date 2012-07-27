
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Plaintext::Plaintext(const Parameters &params) :
    _params(params),
    _m(1)
  {}

  QByteArray Plaintext::Encode(const QByteArray &input)
  {
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = _params.GetP().GetByteCount() - 3;
    if(can_read < 1) qFatal("Illegal parameters");
   
    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(input.left(can_read));
    padded.append((char)0x00);

    // Change first byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    bool okay = false;
    const int last = padded.count()-1;
    for(unsigned char pad=0x00; pad < 0xff; pad++) {
      padded[last] = pad;
      _m = Integer(padded);
      if(_params.IsElement(_m)) {
        okay = true;
        break;
      }
    }

    if(!okay) {
      _m = 1;
      qFatal("Could not encode message as quadratic residue");
    }

    return input.mid(can_read);
  }

  QByteArray Plaintext::Decode() const 
  {
    QByteArray data = _m.GetByteArray();
    if(data.count() <= 2) return QByteArray();

    const unsigned char c = data[0];
    if(c != 0xff) return QByteArray();

    return data.mid(1, data.count()-2);
  }

}
}
}
