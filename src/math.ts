import { CurveType, Constants } from './curve'
import { BigIntType, Integers } from './integers'

export class MathFunctions<BIT extends BigIntType> {
    constructor(private Ints: Integers<BIT>, private CURVE: CurveType<BIT>, private CONSTANTS: Constants<BIT>) {}

    toBigInt(n: number | string): BIT {
        return this.Ints.BigInt(n)
    }
    // Little-endian check for first LE bit (last BE bit);
    edIsNegative(num: BIT): boolean {
        return this.Ints.equal(this.Ints.bitwiseAnd(this.mod(num), this.toBigInt(1)), this.toBigInt(1))
    }

    mod(a: BIT, b: BIT = this.CURVE.P): BIT {
        const res = this.Ints.remainder(a, b)
        return this.Ints.greaterThanOrEqual(res, this.toBigInt(0)) ? res : this.Ints.add(b, res)
    }

    // Note: this egcd-based invert is faster than powMod-based one.
    // Inverses number over modulo
    invert(number: BIT, modulo: BIT = this.CURVE.P): BIT {
        if (this.Ints.equal(number, this.toBigInt(0)) || this.Ints.lessThanOrEqual(modulo, this.toBigInt(0))) {
            throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`)
        }
        // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
        let a = this.mod(number, modulo)
        let b = modulo
        let [x, y, u, v] = [this.toBigInt(0), this.toBigInt(1), this.toBigInt(1), this.toBigInt(0)]
        while (this.Ints.notEqual(a, this.toBigInt(0))) {
            const q = this.Ints.divide(b, a)
            const r = this.Ints.remainder(b, a)
            const m = this.Ints.subtract(x, this.Ints.multiply(u, q))
            const n = this.Ints.subtract(y, this.Ints.multiply(v, q))
            ;[b, a] = [a, r]
            ;[x, y] = [u, v]
            ;[u, v] = [m, n]
        }
        const gcd = b
        if (this.Ints.notEqual(gcd, this.toBigInt(1))) throw new Error('invert: does not exist')
        return this.mod(x, modulo)
    }

    invertBatch(nums: BIT[], n: BIT = this.CURVE.P): BIT[] {
        const len = nums.length
        const scratch = new Array(len)
        let acc = this.toBigInt(1)
        for (let i = 0; i < len; i++) {
            if (this.Ints.equal(nums[i], this.toBigInt(0))) continue
            scratch[i] = acc
            acc = this.mod(this.Ints.multiply(acc, nums[i]), n)
        }
        acc = this.invert(acc, n)
        for (let i = len - 1; i >= 0; i--) {
            if (this.Ints.equal(nums[i], this.toBigInt(0))) continue
            const tmp = this.mod(this.Ints.multiply(acc, nums[i]), n)
            nums[i] = this.mod(this.Ints.multiply(acc, scratch[i]), n)
            acc = tmp
        }
        return nums
    }

    // Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
    pow2(x: BIT, power: BIT): BIT {
        const { P } = this.CURVE
        let res = x
        while (this.Ints.greaterThan(power, this.toBigInt(0))) {
            power = this.Ints.subtract(power, this.toBigInt(1))
            res = this.Ints.multiply(res, res)
            res = this.Ints.remainder(res, P)
        }
        return res
    }

    // Power to (p-5)/8 aka x^(2^252-3)
    // Used to calculate y - the square root of y².
    // Exponentiates it to very big number.
    // We are unwrapping the loop because it's 2x faster.
    // (2n**252n-3n).toString(2) would produce bits [250x 1, 0, 1]
    // We are multiplying it bit-by-bit
    pow_2_252_3(x: BIT): BIT {
        const { P } = this.CURVE
        const x2 = this.Ints.remainder(this.Ints.multiply(x, x), P)
        const b2 = this.Ints.remainder(this.Ints.multiply(x2, x), P) // x^3, 11
        const b4 = this.Ints.remainder(this.Ints.multiply(this.pow2(b2, this.toBigInt(2)), b2), P) // x^15, 1111
        const b5 = this.Ints.remainder(this.Ints.multiply(this.pow2(b4, this.toBigInt(1)), x), P) // x^31
        const b10 = this.Ints.remainder(this.Ints.multiply(this.pow2(b5, this.toBigInt(5)), b5), P)
        const b20 = this.Ints.remainder(this.Ints.multiply(this.pow2(b10, this.toBigInt(10)), b10), P)
        const b40 = this.Ints.remainder(this.Ints.multiply(this.pow2(b20, this.toBigInt(20)), b20), P)
        const b80 = this.Ints.remainder(this.Ints.multiply(this.pow2(b40, this.toBigInt(40)), b40), P)
        const b160 = this.Ints.remainder(this.Ints.multiply(this.pow2(b80, this.toBigInt(80)), b80), P)
        const b240 = this.Ints.remainder(this.Ints.multiply(this.pow2(b160, this.toBigInt(80)), b80), P)
        const b250 = this.Ints.remainder(this.Ints.multiply(this.pow2(b240, this.toBigInt(10)), b10), P)
        const pow_p_5_8 = this.Ints.remainder(this.Ints.multiply(this.pow2(b250, this.toBigInt(2)), x), P)
        // ^ To pow to (p+3)/8, multiply it by x.
        return pow_p_5_8
    }

    // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
    // prettier-ignore
    uvRatio(u: BIT, v: BIT): {isValid: boolean, value: BIT} {
          const v3 = this.mod(this.Ints.multiply(this.Ints.multiply(v , v), v));                  // v³
          const v7 = this.mod(this.Ints.multiply(this.Ints.multiply(v3 , v3) , v));                // v⁷
          let x = this.mod(this.Ints.multiply(this.Ints.multiply(u , v3),  this.pow_2_252_3(this.Ints.multiply(u , v7))));  // (uv³)(uv⁷)^(p-5)/8
          const vx2 = this.mod(this.Ints.multiply(this.Ints.multiply(v , x ), x));                 // vx²
          const root1 = x;                            // First root candidate
          const root2 = this.mod(this.Ints.multiply(x , this.CONSTANTS.SQRT_M1));             // Second root candidate
          const useRoot1 = this.Ints.equal(vx2 , u);                 // If vx² = u (mod p), x is a square root
          const useRoot2 = this.Ints.equal(vx2 , this.mod(this.Ints.unaryMinus(u)));           // If vx² = -u, set x <-- x * 2^((p-1)/4)
          const noRoot = this.Ints.equal(vx2, this.mod(this.Ints.multiply(this.Ints.unaryMinus(u) , this.CONSTANTS.SQRT_M1)));   // There is no valid root, vx² = -u√(-1)
          if (useRoot1) x = root1;
          if (useRoot2 || noRoot) x = root2;          // We return root2 anyway, for const-time
          if (this.edIsNegative(x)) x = this.mod(this.Ints.unaryMinus(x));
          return { isValid: useRoot1 || useRoot2, value: x };
        }

    // Calculates 1/√(number)
    invertSqrt(number: BIT): { isValid: boolean; value: BIT } {
        return this.uvRatio(this.toBigInt(1), number)
    }
}
