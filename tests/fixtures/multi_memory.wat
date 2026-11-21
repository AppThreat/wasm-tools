;; Multiple memories (wasm 3.0, shipped Chrome 120 / Firefox 125 / Node 22):
;; two memories plus memory.copy and memory.fill with explicit memory
;; indices, and a data segment addressed to the second memory.
(module
  (memory $m0 1)
  (memory $m1 2)
  (data (memory $m1) (i32.const 0) "second")
  (func (export "copy_into_second") (param i32 i32 i32)
    (memory.copy $m1 $m0 (local.get 0) (local.get 1) (local.get 2))
  )
  (func (export "clear_second") (param i32 i32 i32)
    (memory.fill $m1 (local.get 0) (local.get 1) (local.get 2))
  )
  (func (export "peek_second") (param i32) (result i32)
    (i32.load8_u $m1 (local.get 0))
  )
)
