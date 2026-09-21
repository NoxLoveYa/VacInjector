// Lab target: one permanently RUNNING thread (hijack-v3 proves on runners;
// notepad threads park in kernel waits and exercise the CRT fallback).
#include <windows.h>
#include <stdio.h>
int main(void) {
  printf("busyloop pid=%lu (spin)\n", (unsigned long)GetCurrentProcessId());
  fflush(stdout);
  volatile unsigned long long n = 0;
  for (;;) { n += 1; if ((n & 0xFFFFFFF) == 0) Sleep(0); }
  return 0;
}
