(module
  (type $ii (func (param i32) (result i32)))
  (type $ll (func (param i64) (result i64)))
  (type $apply_t (func (param (ref $ii) i32) (result i32)))
  (type $null_t (func (result i32)))

  (global $fac_ref (ref $ll) ref.func $fac)

  (export "run" (func 3))
  (export "null" (func 4))
  (export "fac" (func $fac))

  ;; Keep ref.func targets valid under current validation rules.
  (elem declare func $square $neg $fac)

  (func $apply (type $apply_t) (param $f (ref $ii)) (param $x i32) (result i32)
    local.get $x
    local.get $f
    call_ref $ii
  )

  (func $square (type $ii) (param i32) (result i32)
    local.get 0
    local.get 0
    i32.mul
  )

  (func $neg (type $ii) (param i32) (result i32)
    i32.const 0
    local.get 0
    i32.sub
  )

  (func (;3;) (type $ii) (param $x i32) (result i32)
    (local $rf (ref null $ii))
    (local $rg (ref null $ii))

    ref.func $square
    local.set $rf
    ref.func $neg
    local.set $rg

    local.get $x
    local.get $rf
    call_ref $ii
    local.get $rg
    call_ref $ii
  )

  (func (;4;) (type $null_t) (result i32)
    i32.const 1
    ref.null $ii
    call_ref $ii
  )

  (func $fac (type $ll) (param i64) (result i64)
    local.get 0
    i64.eqz
    if (result i64)
      i64.const 1
    else
      local.get 0
      local.get 0
      i64.const 1
      i64.sub
      global.get $fac_ref
      call_ref $ll
      i64.mul
    end
  )
)

