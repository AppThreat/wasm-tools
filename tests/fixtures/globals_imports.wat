(module
  (import "env" "log" (func $log (param f64)))
  (import "env" "PI" (global $pi f64))
  (global $counter (mut f64) (f64.const 0.0))

  (func (export "increment")
    global.get $counter
    f64.const 1.5
    f64.add
    global.set $counter

    global.get $counter
    call $log
  )
)