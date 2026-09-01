;; GC operations fixture: struct/array/sub types and typed-reference opcodes.
;;
;; Build with the Rust wasm-tools, not WABT:
;;   wasm-tools parse tests/fixtures/gc_ops.wat -o tests/fixtures/gc_ops.wasm
;; WABT's wat2wasm text front-end cannot parse final GC text (no struct/array
;; instruction keywords such as `struct.new`, no abstract heap types).
(module
  ;; (sub ...) with no supertypes marks the type non-final so $sub_point can
  ;; extend it; plain (type ... (struct ...)) declarations are implicitly final.
  (type $point (sub (struct (field (mut i32)) (field i32))))
  (type $sub_point (sub $point (struct (field (mut i32)) (field i32))))
  (type $nums (array (mut i32)))

  (func (export "make_point") (result (ref $point))
    i32.const 1
    i32.const 2
    struct.new $point
  )

  (func (export "get_x") (param (ref null $point)) (result i32)
    local.get 0
    struct.get $point 0
  )

  (func (export "set_x") (param (ref null $point) i32)
    local.get 0
    local.get 1
    struct.set $point 0
  )

  (func (export "make_sub") (result (ref $sub_point))
    i32.const 3
    i32.const 4
    struct.new $sub_point
  )

  (func (export "arr_new") (result (ref $nums))
    i32.const 4
    array.new_default $nums
  )

  (func (export "arr_len") (param (ref null $nums)) (result i32)
    local.get 0
    array.len
  )

  (func (export "arr_get") (param (ref null $nums) i32) (result i32)
    local.get 0
    local.get 1
    array.get $nums
  )

  (func (export "arr_set") (param (ref null $nums) i32 i32)
    local.get 0
    local.get 1
    local.get 2
    array.set $nums
  )

  (func (export "is_point") (param anyref) (result i32)
    local.get 0
    ref.test (ref $point)
  )

  (func (export "cast_point") (param anyref) (result (ref null $point))
    local.get 0
    ref.cast (ref null $point)
  )

  (func (export "branch_cast") (param eqref) (result i32)
    (block $not_point (result eqref)
      local.get 0
      br_on_cast $not_point eqref (ref $point)
      ref.cast (ref $point)
      struct.get $point 0
      return
    )
    drop
    i32.const -1
  )

  (func (export "i31_roundtrip") (param i32) (result i32)
    local.get 0
    ref.i31
    i31.get_u
  )

  (func (export "externify") (param anyref) (result externref)
    local.get 0
    extern.convert_any
  )

  (func (export "unextern") (param externref) (result anyref)
    local.get 0
    any.convert_extern
  )
)
