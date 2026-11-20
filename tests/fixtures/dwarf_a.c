int add(int a, int b) { return a + b; }

int mul(int a, int b) {
  int r = 0;
  for (int i = 0; i < b; i++) r = add(r, a);
  return r;
}
