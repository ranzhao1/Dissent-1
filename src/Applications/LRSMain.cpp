
#include "Dissent.hpp"

int main(int /*argc*/, char** /*argv[]*/) {
  QTextStream out(stdout, QIODevice::WriteOnly);

  QSharedPointer<AbstractGroup::AbstractGroup> group = CppECGroup::GetGroup(ECParams::NIST_P256);

  SchnorrProof sp(group);

  sp.FakeProve();

  bool valid = sp.Verify();

  if(valid) {
    out << "Proof ok" << endl;
  } else {
    out << "Proof failed" << endl;
  }

  return 0;
}

