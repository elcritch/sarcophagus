# Changes

## 0.15.2

- Fix intermittent HTTP integration test failures caused by random port
  collisions. Test servers now bind port zero and use the OS-assigned port.
- Add regression coverage for concurrent test servers and repeated startup.
