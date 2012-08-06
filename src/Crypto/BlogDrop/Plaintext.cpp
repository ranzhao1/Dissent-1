
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Plaintext::Plaintext(const Parameters params) :
    _params(params),
    _m(1)
  {}

  QByteArray Plaintext::Encode(const QByteArray &input)
  {
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = Plaintext::CanFit(_params);

    if(can_read < 1) qFatal("Illegal parameters");

    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(input.left(can_read));
    padded.append((char)0x00);
    padded.append(0xff);

    // Change byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    bool okay = false;
    const int last = padded.count()-2;
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

  bool Plaintext::Decode(QByteArray &ret) const 
  {
    QByteArray data = _m.GetByteArray();
    if(data.count() < 3) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << _m.GetByteArray().toHex();
      return false;
    }

    const unsigned char cfirst = data[0];
    const unsigned char clast = data.right(1)[0];
    if(cfirst != 0xff || clast != 0xff) {
      qWarning() << "Tried to decode invalid plaintext (bad padding)";
      return false;
    }

    ret = data.mid(1, data.count()-3);
    return true;
  }

  void Plaintext::SetRandom()
  {
    _m = _params.RandomElement();
  }

  void Plaintext::Reveal(const Integer &c)
  {
    _m = _m.MultiplyMod(c, _params.GetP());
  }

}
}
}
