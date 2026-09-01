;; GC rec-group fixture for type-index regression coverage.
;;
;; Build with the Rust wasm-tools, not WABT:
;;   wasm-tools parse tests/fixtures/gc_rec_group.wat -o tests/fixtures/gc_rec_group.wasm
;; WABT's wat2wasm text front-end cannot parse final GC text (no `rec` module
;; field, no abstract heap types such as `anyref`), even with --enable-gc.
;;
;; Type index space (each rec-group member occupies its own index):
;;   0: func (i32) -> (i32)
;;   1: struct {i32}        } rec group
;;   2: struct {i64}        }
;;   3: func (anyref) -> (i32)
(module
  (type $f0 (func (param i32) (result i32)))

  (rec
    (type $s1 (struct (field i32)))
    (type $s2 (struct (field i64)))
  )

  (type $f1 (func (param anyref) (result i32)))

  (func (type $f0)
    local.get 0
    i32.const 1
    i32.add
  )

  (func (type $f1)
    i32.const 7
  )
)
