(module
  (type $sig (func (param i32 i32 i32) (result i32)))
  (type $ret_i32 (func (result i32)))
  (type $ret_i64 (func (result i64)))
  (type $set_i32 (func (param i32)))

  (table 1 1 funcref)
  (memory i64 1)
  (global $g (mut i32) i32.const 0)

  (export "as-br_if-cond" (func 0))
  (export "as-select-cond" (func 1))
  (export "as-call_indirect-index" (func 2))
  (export "as-global.set-value" (func 3))
  (export "as-load64-address" (func 4))
  (export "as-store-value" (func 5))
  (export "as-memory.grow-size" (func 6))

  (elem (table 0) (i32.const 0) func $f)

  (func (;0;) (type $ret_i32) (result i32)
    block (result i32)
      i32.const 6
      i64.const 0
      i32.load offset=1099511627776
      br_if 0
      drop
      i32.const 7
    end
  )

  (func (;1;) (type $ret_i32) (result i32)
    i32.const 0
    i32.const 1
    i64.const 0
    i32.load offset=1099511627776
    select
  )

  (func $f (type $sig) (param i32 i32 i32) (result i32)
    i32.const -1
  )

  (func (;2;) (type $ret_i32) (result i32)
    i32.const 1
    i32.const 2
    i32.const 3
    i64.const 0
    i32.load offset=1099511627776
    call_indirect (type $sig)
  )

  (func (;3;) (type $set_i32) (param i32)
    i64.const 0
    i32.load offset=1099511627776
    global.set $g
  )

  (func (;4;) (type $ret_i64) (result i64)
    i64.const 0
    i64.load offset=1099511627776
  )

  (func (;5;) (type $set_i32) (param i32)
    i64.const 2
    i64.const 0
    i32.load offset=1099511627776
    i32.store offset=1099511627776
  )

  (func (;6;) (type $ret_i64) (result i64)
    i64.const 1
    memory.grow
  )
)

