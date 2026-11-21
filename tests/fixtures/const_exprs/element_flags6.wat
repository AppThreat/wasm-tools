;; Element segment with an explicit table index and expression-list
;; entries (flags 6), then a table with an initializer expression
;; (0x40 0x00 tabletype expr) followed by a plain table.
(module
  (type $f (func))
  (func $a)
  (func $b)
  (table $t0 1 funcref)
  (table $t1 2 (ref null $f) (ref.func $a))
  (table $t2 3 funcref)
  (elem (table $t2) (offset (i32.const 1)) funcref (ref.func $a) (ref.func $b))
  (elem declare func $b)
  (export "t2" (table $t2)))
