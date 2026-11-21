;; Block types that are reference value types (0x63/0x64 + heap type).
(module
  (type $f (func))
  (func $target)
  (elem declare func $target)
  (func (export "run") (result funcref)
    (block (result (ref null $f))
      (ref.func $target))
    drop
    (block $h
      (try_table (result (ref $f)) (catch_all $h)
        (ref.func $target))
      drop)
    (ref.null func)))
