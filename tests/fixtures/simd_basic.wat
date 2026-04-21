;; Basic SIMD fixture – exercises v128.const, v128.load, i32x4.add, i32x4.splat
(module
  (memory 1)

  (func (export "simd_add") (result v128)
    ;; load two v128 values from memory and add them
    i32.const 0
    v128.load align=4

    i32.const 16
    v128.load align=4

    i32x4.add
  )

  (func (export "simd_const") (result v128)
    v128.const i32x4 1 2 3 4
  )

  (func (export "simd_splat") (param i32) (result v128)
    local.get 0
    i32x4.splat
  )
)

