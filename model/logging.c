
void CHECK(bool cond) {
  if (!cond) {
    __coverity_panic__();
  }
}

void CHECK_EQ(int l, int r) {
  if (l != r) {
    __coverity_panic__();
  }
}
