;; Extended-const and GC constant expressions in globals, followed by a
;; plain global so a desynchronised decoder shows up as a wrong init.
(module
  (type $pair (struct (field i32) (field i32)))
  (type $arr (array i32))
  (global $g0 i32 (i32.const 5))
  (global $g1 i32 (i32.add (i32.const 1) (global.get $g0)))
  (global $g2 i64 (i64.mul (i64.const 3) (i64.sub (i64.const 10) (i64.const 4))))
  (global $g3 (ref $pair) (struct.new $pair (i32.const 1) (i32.const 2)))
  (global $g4 (ref $arr) (array.new_fixed $arr 3 (i32.const 7) (i32.const 8) (i32.const 9)))
  (global $g5 (ref i31) (ref.i31 (i32.const 42)))
  (global $g6 i32 (i32.const 99))
  (memory 1)
  (data (offset (i32.add (i32.const 16) (global.get $g0))) "ab")
  (data (i32.const 32) "cd"))
