;; A compute-bound module matching the structural cryptojacking profile:
;; one exported function, no imports, a tight f64 multiply-add loop with no
;; call graph and no branchy application logic. WASM-MIN-009's target shape.
(module
  (func (export "spin") (param f64) (result f64)
    (local $i i32)
    (local $acc f64)
    (loop $l
      local.get $acc
      local.get 0
      f64.mul
      local.get 0
      f64.add
      local.set $acc
      local.get $acc
      f64.sqrt
      local.set $acc
      local.get $acc
      local.get 0
      f64.sub
      local.set $acc
      local.get $i
      i32.const 1
      i32.add
      local.tee $i
      i32.const 1000000
      i32.lt_u
      br_if $l
    )
    local.get $acc
  )
)
