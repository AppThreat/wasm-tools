(module
  (memory 1)
  (data (i32.const 0) "https://evil.example.com/payload\00")
  (data (i32.const 64) "AKIAIOSFODNN7EXAMPLE\00")
  (data (i32.const 128) "-----BEGIN RSA PRIVATE KEY-----\00")
  (data (i32.const 256) "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\00")
  (data (i32.const 512) "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5\00")
  (data (i32.const 640) "just a plain harmless string for baseline coverage\00")
)
