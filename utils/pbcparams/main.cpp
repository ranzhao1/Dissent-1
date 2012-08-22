
#include <QTextStream>
#include <pbc/pbc.h>


int main(int argc, char* argv[]) {
  QTextStream err(stderr, QIODevice::WriteOnly);
  if(argc != 2) {
    err << "Usage: " << argv[0] << " qbits\n";
    return 1;
  }

  int qbits;
  QTextStream in(argv[1], QIODevice::ReadOnly);
  in >> qbits;

  if(qbits < 10) {
    err << "qbits must be greater than 10\n";
    return 1;
  }

  QTextStream out(stdout, QIODevice::WriteOnly);
  out << "--- PBC Parameter Utility ---\n";
  out << "r < q (for prime r and q)\n";
  out << "Bits: " << qbits << "\n";
  out << "\n\n";

  pbc_param_t params;
  pairing_t pairing;
  pbc_param_init_a_gen(params, qbits, qbits-2);
  pbc_param_out_str(stdout, params);

  pairing_init_pbc_param(pairing, params);

  element_t g1;
  element_t g2;
  element_t gt;
  element_t gr;

  element_init_G1(g1, pairing);
  element_init_G2(g2, pairing);
  element_init_GT(gt, pairing);
  element_init_Zr(gr, pairing);

  pbc_param_clear(params);
  pairing_clear(pairing);

  element_clear(g1);
  element_clear(g2);
  element_clear(gt);
  element_clear(gr);

  return 0;
}

