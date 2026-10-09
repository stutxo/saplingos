;; A real generic predicate: evidence chooses an output whose value must meet
;; the immutable u64-LE minimum. It has no Ark or recovery special cases.
;; Compile explicitly: wat2wasm output_value_floor.wat -o output_value_floor.wasm
;; Set SAPIO_LIFECYCLE_WASM to that artifact when running the integration tests.
(module
	(memory (export "memory") 32)
	(global $heap (mut i32) (i32.const 4096))
	(func (export "sapio_alloc_v1") (param $length i32) (result i32)
		global.get $heap
		global.get $heap local.get $length i32.add global.set $heap)
	(func (export "sapio_evaluate_v1")
		(param $program i32) (param $program_len i32)
		(param $parameters i32) (param $parameters_len i32)
		(param $view i32) (param $view_len i32)
		(param $witness i32) (param $witness_len i32)
		(result i32)
		(local $cursor i32) (local $remaining i32) (local $index i32)
		local.get $program_len i32.eqz i32.eqz if unreachable end
		local.get $parameters_len i32.const 8 i32.ne if unreachable end
		local.get $witness_len i32.const 4 i32.ne if unreachable end
		local.get $view_len i32.const 16 i32.lt_u if unreachable end
		local.get $view i32.const 16 i32.add local.set $cursor
		local.get $view i32.load offset=12 local.set $remaining
		(block $inputs_done (loop $inputs
			local.get $remaining i32.eqz br_if $inputs_done
			local.get $cursor i32.load offset=48
			local.get $cursor i32.const 52 i32.add i32.add local.set $cursor
			local.get $remaining i32.const 1 i32.sub local.set $remaining
			br $inputs))
		local.get $witness i32.load local.set $index
		local.get $index local.get $cursor i32.load i32.ge_u
		if i32.const 0 return end
		local.get $cursor i32.const 4 i32.add local.set $cursor
		(block $output_found (loop $outputs
			local.get $index i32.eqz br_if $output_found
			local.get $cursor i32.load offset=8
			local.get $cursor i32.const 12 i32.add i32.add local.set $cursor
			local.get $index i32.const 1 i32.sub local.set $index
			br $outputs))
		local.get $cursor i64.load
		local.get $parameters i64.load
		i64.ge_u))
