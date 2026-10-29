# Keyring test files

The `.knxkeys` files are ETS-exported keyrings from the xknx test suite
(<https://github.com/XKNX/xknx>, `test/secure_tests/resources`, xknx 4.0.0),
redistributed under xknx's MIT licence ([LICENSE.xknx](LICENSE.xknx)). They
contain only test projects and test passwords:

| File | Password |
|---|---|
| SecureTest.knxkeys | `test` |
| testcase.knxkeys | `password` |
| special_chars_secure_tunnel.knxkeys | `test` |
| DataSecure_usb.knxkeys | `test` |

go-knx's tests check the decrypted values against those xknx reads from the
same files.
