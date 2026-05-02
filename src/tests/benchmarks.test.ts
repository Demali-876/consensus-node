import assert from "node:assert/strict";
import { integerParam, percentile } from "../runtime/benchmarks";


// null → Number(null) = 0 → was returning min (1), should return fallback (16)
assert.equal(integerParam(null, 16, 1, 1024), 16, "null must return fallback");

// false → Number(false) = 0 → same path
assert.equal(integerParam(false, 16, 1, 1024), 16, "false must return fallback");

// empty string → Number('') = 0 → same path
assert.equal(integerParam("", 16, 1, 1024), 16, "empty string must return fallback");

// undefined is already handled (Number(undefined) = NaN fails isInteger check),
// but confirm it still works
assert.equal(integerParam(undefined, 16, 1, 1024), 16, "undefined must return fallback");

// non-integer float → still returns fallback
assert.equal(integerParam(1.5, 16, 1, 1024), 16, "float must return fallback");

// valid inputs continue to work
assert.equal(integerParam(100, 16, 1, 1024), 100, "integer value accepted");
assert.equal(integerParam("50", 16, 1, 1024), 50, "integer string accepted");
assert.equal(integerParam(0, 16, 1, 1024), 1, "zero clamped to min");
assert.equal(integerParam(2000, 16, 1, 1024), 1024, "over-max clamped to max");

// ---------------------------------------------------------------------------
// Bug: percentile() with p=0 computes Math.ceil(n*0)-1 = -1, then
// sortedValues[-1] = undefined, falls through to ?? 0.  On unfixed code the
// first assertion below would fail.
// ---------------------------------------------------------------------------

// p=0 on a non-empty array must return the minimum (first) value
assert.equal(percentile([5, 10, 15], 0), 5, "p=0 must return minimum value, not 0");

// p=0 where the minimum is itself 0 – both buggy and fixed return 0, but for
// the right reason after the fix (it's the actual minimum, not undefined??0)
assert.equal(percentile([0, 10, 20], 0), 0, "p=0 of array starting with 0 returns 0");

// empty array always returns 0
assert.equal(percentile([], 0.95), 0, "empty array returns 0");
assert.equal(percentile([], 0), 0, "empty array with p=0 returns 0");

// p=0.95 still behaves correctly for various sizes
const ten = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
assert.equal(percentile(ten, 0.95), 10, "p95 of [1..10] is 10 (max for small n)");
assert.equal(percentile(ten, 0.5), 5, "p50 of [1..10] is 5");
assert.equal(percentile([1], 0.95), 1, "single-element array returns that element");

console.log("benchmarks ok");