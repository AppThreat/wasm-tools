;; Two identical function bodies plus a distinct third: exercises the
;; per-function body_hash (identical mnemonic sequences hash identically)
;; and the feature block on simple straight-line functions.
(module
  (func (export "copy_a") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add
  )
  (func (export "copy_b") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add
  )
  (func (export "different") (param i32) (result i32)
    local.get 0
    i32.const 2
    i32.mul
  )
)
