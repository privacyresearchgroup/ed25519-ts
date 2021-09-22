import { Hash, sha512 } from './hash'
import { CurveType, Constants } from './curve'
import { KeyUtils } from './key-utils'
import { SerializationFunctions, IntFactory, B32, hexToBytes, bytesToHex, Hex, PrivKey } from './serialization'
import { MathFunctions } from './math'
import { BigIntType, Integers } from './integers'

export interface PointData<BIT extends BigIntType> {
    x: BIT
    y: BIT
    _WINDOW_SIZE?: number
}

export interface PointOps<BIT> {
    toHex(): string
    toRawBytes(): Uint8Array
    toX25519(): BIT
    equals(other: PointBase<BIT>): boolean
    add(other: PointBase<BIT>): PointBase<BIT>
    subtract(other: PointBase<BIT>): PointBase<BIT>
    negate(): PointBase<BIT>
    multiply(scalar: number | BIT): PointBase<BIT>
    _setWindowSize(w: number): void
}

export type PointBase<BIT> = PointData<BIT> & PointOps<BIT>

export interface PointStatic<BIT> {
    fromHex(hex: Hex): PointBase<BIT>
    fromPrivateKey(pk: PrivKey<BIT>): Promise<PointBase<BIT>>
    ZERO: PointBase<BIT>
    BASE: PointBase<BIT>
    precompute(windowSize?: number, point?: PointBase<BIT>): PointBase<BIT>
}

export function pointEquals<BIT extends BigIntType, PT extends PointData<BIT>>(
    p: PT,
    q: PT,
    Ints: Integers<BIT>
): boolean {
    return Ints.equal(p.x, q.x) && Ints.equal(p.y, q.y)
}

export interface ExtendedPointData<BIT extends BigIntType> {
    x: BIT
    y: BIT
    z: BIT
    t: BIT
}
export interface ExtendedPointOps<BIT> {
    toAffine(): PointData<BIT>
    equals(other: ExtendedPointBase<BIT>): boolean
    ristrettoEquals(other: ExtendedPointBase<BIT>): boolean
    add(other: ExtendedPointBase<BIT>): ExtendedPointBase<BIT>
    subtract(other: ExtendedPointBase<BIT>): ExtendedPointBase<BIT>
    negate(): ExtendedPointBase<BIT>
    multiply(scalar: number | BIT, affinePoint?: PointData<BIT>): ExtendedPointBase<BIT>
    multiplyUnsafe(scalar: BIT): ExtendedPointBase<BIT>
    toRistrettoBytes(): Uint8Array
}

export type ExtendedPointBase<BIT> = ExtendedPointData<BIT> & ExtendedPointOps<BIT>

export interface ExtendedPointStatic<BIT> {
    fromAffine(p: PointData<BIT>): ExtendedPointBase<BIT>
    fromRistrettoBytes(bytes: Uint8Array): ExtendedPointBase<BIT>
    fromRistrettoHash(hash: Uint8Array): ExtendedPointBase<BIT>
    pointPrecomputes: WeakMap<PointData<BIT>, ExtendedPointBase<BIT>[]>
    ZERO: ExtendedPointBase<BIT>
    BASE: ExtendedPointBase<BIT>
}

function basePoint<BIT extends BigIntType>(CURVE: CurveType<BIT>): PointData<BIT> {
    return { x: CURVE.Gx, y: CURVE.Gy }
}

function zeroPoint<BIT extends BigIntType>(Ints: Integers<BIT>): PointData<BIT> {
    return { x: Ints.BigInt(0), y: Ints.BigInt(0) }
}

export function makeExtendedPointClass<BIT extends BigIntType>(
    CURVE: CurveType<BIT>,
    CONSTANTS: Constants<BIT>,
    Ints: Integers<BIT>,
    serializer: SerializationFunctions<BIT>,
    math: MathFunctions<BIT>,
    toBigInt: IntFactory<BIT>
): ExtendedPointStatic<BIT> {
    const POINT_BASE = basePoint(CURVE)
    const POINT_ZERO = zeroPoint(Ints)
    return class ExtendedPoint {
        constructor(public x: BIT, public y: BIT, public z: BIT, public t: BIT) {}

        static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, toBigInt(1), math.mod(Ints.multiply(CURVE.Gx, CURVE.Gy)))
        static ZERO = new ExtendedPoint(toBigInt(0), toBigInt(1), toBigInt(1), toBigInt(0))

        // Stores precomputed values for points.
        static pointPrecomputes = new WeakMap<PointData<BIT>, ExtendedPoint[]>()
        static fromAffine(p: PointData<BIT>): ExtendedPoint {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            if (!(p.x && p.y && !(p as any).z && !(p as any).t)) {
                throw new TypeError('ExtendedPoint#fromAffine: expected Point')
            }
            if (pointEquals(p, POINT_ZERO, Ints)) return ExtendedPoint.ZERO
            return new ExtendedPoint(p.x, p.y, toBigInt(1), math.mod(Ints.multiply(p.x, p.y)))
        }
        // Takes a bunch of Jacobian Points but executes only one
        // invert on all of them. invert is very slow operation,
        // so this improves performance massively.
        static toAffineBatch(points: ExtendedPoint[]): PointData<BIT>[] {
            const toInv = math.invertBatch(points.map((p) => p.z))
            const affs = points.map((p, i) => p.toAffine(toInv[i]))
            return affs
        }

        static normalizeZ(points: ExtendedPoint[]): ExtendedPoint[] {
            return this.toAffineBatch(points).map(this.fromAffine)
        }

        // Ristretto-related methods.

        static bytes255ToNumberLE(bytes: Uint8Array): BIT {
            return math.mod(
                Ints.bitwiseAnd(
                    serializer.bytesToNumberLE(bytes),
                    Ints.subtract(Ints.exponentiate(toBigInt(2), toBigInt(255)), toBigInt(1))
                )
            )
        }

        // The hash-to-group operation applies Elligator twice and adds the results.
        // https://ristretto.group/formulas/elligator.html
        static fromRistrettoHash(hash: Uint8Array): ExtendedPoint {
            const r1 = ExtendedPoint.bytes255ToNumberLE(hash.slice(0, B32))
            // const h = hash.slice(0, B32);
            const R1 = ExtendedPoint.calcElligatorRistrettoMap(r1)
            const r2 = ExtendedPoint.bytes255ToNumberLE(hash.slice(B32, B32 * 2))
            const R2 = ExtendedPoint.calcElligatorRistrettoMap(r2)
            return R1.add(R2)
        }

        // Computes Elligator map for Ristretto
        // https://ristretto.group/formulas/elligator.html
        static calcElligatorRistrettoMap(r0: BIT) {
            const { d } = CURVE
            const r = math.mod(Ints.multiply(CONSTANTS.SQRT_M1, Ints.multiply(r0, r0))) // 1  SQRT_M1*r0*r0
            const Ns = math.mod(Ints.multiply(Ints.add(r, toBigInt(1)), CONSTANTS.ONE_MINUS_D_SQ)) // 2  (r + 1)*ONE_MINUS_D_SQ
            let c = toBigInt(-1) // 3
            const D = math.mod(Ints.multiply(Ints.subtract(c, Ints.multiply(d, r)), math.mod(Ints.add(r, d)))) // 4 (c - d * r) * mod(r + d)
            const uvr = math.uvRatio(Ns, D) // 5
            const Ns_D_is_sq = uvr.isValid
            let s = uvr.value

            let s_ = math.mod(Ints.multiply(s, r0)) // 6
            if (!math.edIsNegative(s_)) s_ = math.mod(Ints.unaryMinus(s_))
            if (!Ns_D_is_sq) s = s_ // 7
            if (!Ns_D_is_sq) c = r // 8
            const Nt = math.mod(
                Ints.subtract(
                    Ints.multiply(Ints.multiply(c, Ints.subtract(r, toBigInt(1))), CONSTANTS.D_MINUS_ONE_SQ),
                    D
                )
            ) // 9   c * (r - jsbi(1)) * D_MINUS_ONE_SQ - D
            const s2 = Ints.multiply(s, s)
            const W0 = math.mod(Ints.multiply(Ints.add(s, s), D)) // 10    (s + s) * D
            const W1 = math.mod(Ints.multiply(Nt, CONSTANTS.SQRT_AD_MINUS_ONE)) // 11  Nt * SQRT_AD_MINUS_ONE
            const W2 = math.mod(Ints.subtract(toBigInt(1), s2)) // 12  1 - s2
            const W3 = math.mod(Ints.add(toBigInt(1), s2)) // 13  1 + s2
            return new ExtendedPoint(
                math.mod(Ints.multiply(W0, W3)),
                math.mod(Ints.multiply(W2, W1)),
                math.mod(Ints.multiply(W1, W3)),
                math.mod(Ints.multiply(W0, W2))
            )
        }

        // Ristretto: Decoding to Extended Coordinates
        // https://ristretto.group/formulas/decoding.html
        static fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint {
            const { a, d } = CURVE
            const emsg = 'ExtendedPoint.fromRistrettoBytes: Cannot convert bytes to Ristretto Point'
            const s = ExtendedPoint.bytes255ToNumberLE(bytes)
            // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
            // 3. Check that s is non-negative, or else abort
            if (!equalBytes(serializer.numberToBytesPadded(s, B32), bytes) || math.edIsNegative(s))
                throw new Error(emsg)
            const s2 = math.mod(Ints.multiply(s, s))
            const u1 = math.mod(Ints.add(toBigInt(1), Ints.multiply(a, s2))) // 4 (a is -1)    1 + a * s2
            const u2 = math.mod(Ints.subtract(toBigInt(1), Ints.multiply(a, s2))) // 5  1 - a * s2
            const u1_2 = math.mod(Ints.multiply(u1, u1))
            const u2_2 = math.mod(Ints.multiply(u2, u2))
            const v = math.mod(Ints.subtract(Ints.multiply(a, Ints.multiply(d, u1_2)), u2_2)) // 6
            const { isValid, value: I } = math.invertSqrt(math.mod(Ints.multiply(v, u2_2))) // 7
            const Dx = math.mod(Ints.multiply(I, u2)) // 8
            const Dy = math.mod(Ints.multiply(Ints.multiply(I, Dx), v)) // 9
            let x = math.mod(Ints.multiply(Ints.add(s, s), Dx)) // 10
            if (math.edIsNegative(x)) x = math.mod(Ints.unaryMinus(x)) // 10
            const y = math.mod(Ints.multiply(u1, Dy)) // 11
            const t = math.mod(Ints.multiply(x, y)) // 12
            if (!isValid || math.edIsNegative(t) || Ints.equal(y, toBigInt(0))) throw new Error(emsg)
            return new ExtendedPoint(x, y, toBigInt(1), t)
        }

        // Ristretto: Encoding from Extended Coordinates
        // https://ristretto.group/formulas/encoding.html
        toRistrettoBytes(): Uint8Array {
            let { x, y } = this
            const { z, t } = this
            const u1 = math.mod(Ints.multiply(Ints.add(z, y), Ints.subtract(z, y))) // 1  (z+y)*(z-y)
            const u2 = math.mod(Ints.multiply(x, y)) // 2
            // Square root always exists
            const { value: invsqrt } = math.invertSqrt(math.mod(Ints.multiply(Ints.multiply(u1, u2), u2))) // 3  u1*u2^2
            const D1 = math.mod(Ints.multiply(invsqrt, u1)) // 4
            const D2 = math.mod(Ints.multiply(invsqrt, u2)) // 5
            const zInv = math.mod(Ints.multiply(Ints.multiply(D1, D2), t)) // 6
            let D: BIT // 7
            if (math.edIsNegative(Ints.multiply(t, zInv))) {
                ;[x, y] = [math.mod(Ints.multiply(y, CONSTANTS.SQRT_M1)), math.mod(Ints.multiply(x, CONSTANTS.SQRT_M1))]
                D = math.mod(Ints.multiply(D1, CONSTANTS.INVSQRT_A_MINUS_D))
            } else {
                D = D2 // 8
            }
            if (math.edIsNegative(Ints.multiply(x, zInv))) y = math.mod(Ints.unaryMinus(y)) // 9
            let s = math.mod(Ints.multiply(Ints.subtract(z, y), D)) // 10 (check footer's note, no sqrt(-a))
            if (math.edIsNegative(s)) s = math.mod(Ints.unaryMinus(s))
            return serializer.numberToBytesPadded(s, B32) // 11
        }

        ristrettoEquals(other: ExtendedPoint): boolean {
            // this assumes CURVE.a === -1
            return (
                this.equals(other) ||
                Ints.equal(math.mod(Ints.multiply(this.y, other.y)), math.mod(Ints.multiply(this.x, other.x)))
            )
        }

        // Ristretto methods end.

        // Compare one point to another.
        equals(other: ExtendedPoint): boolean {
            const b = other
            const [T1, T2, Z1, Z2] = [this.t, b.t, this.z, b.z]
            return Ints.equal(math.mod(Ints.multiply(T1, Z2)), math.mod(Ints.multiply(T2, Z1)))
        }

        // Inverses point to one corresponding to (x, -y) in Affine coordinates.
        negate(): ExtendedPoint {
            return new ExtendedPoint(
                math.mod(Ints.unaryMinus(this.x)),
                this.y,
                this.z,
                math.mod(Ints.unaryMinus(this.t))
            )
        }

        // Fast algo for doubling Extended Point when curve's a=-1.
        // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
        // Cost: 3M + 4S + 1*a + 7add + 1*2.
        double(): ExtendedPoint {
            const X1 = this.x
            const Y1 = this.y
            const Z1 = this.z
            const { a } = CURVE
            const A = math.mod(Ints.multiply(X1, X1))
            const B = math.mod(Ints.multiply(Y1, Y1))
            const C = math.mod(Ints.multiply(Ints.multiply(toBigInt(2), Z1), Z1))
            const D = math.mod(Ints.multiply(a, A))
            const X1pY1 = Ints.add(X1, Y1)
            const E = math.mod(Ints.subtract(Ints.subtract(Ints.multiply(X1pY1, X1pY1), A), B))
            const G = math.mod(Ints.add(D, B))
            const F = math.mod(Ints.subtract(G, C))
            const H = math.mod(Ints.subtract(D, B))
            const X3 = math.mod(Ints.multiply(E, F))
            const Y3 = math.mod(Ints.multiply(G, H))
            const T3 = math.mod(Ints.multiply(E, H))
            const Z3 = math.mod(Ints.multiply(F, G))
            return new ExtendedPoint(X3, Y3, Z3, T3)
        }

        // Fast algo for adding 2 Extended Points when curve's a=-1.
        // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
        // Cost: 8M + 8add + 2*2.
        add(other: ExtendedPointBase<BIT>): ExtendedPoint {
            const X1 = this.x
            const Y1 = this.y
            const Z1 = this.z
            const T1 = this.t
            const X2 = other.x
            const Y2 = other.y
            const Z2 = other.z
            const T2 = other.t
            const A = math.mod(Ints.multiply(Ints.subtract(Y1, X1), Ints.add(Y2, X2)))
            const B = math.mod(Ints.multiply(Ints.add(Y1, X1), Ints.subtract(Y2, X2)))
            const F = math.mod(Ints.subtract(B, A))
            if (Ints.equal(F, toBigInt(0))) {
                // Same point.
                return this.double()
            }
            const C = math.mod(Ints.multiply(Ints.multiply(Z1, toBigInt(2)), T2))
            const D = math.mod(Ints.multiply(Ints.multiply(T1, toBigInt(2)), Z2))
            const E = math.mod(Ints.add(D, C))
            const G = math.mod(Ints.add(B, A))
            const H = math.mod(Ints.subtract(D, C))
            const X3 = math.mod(Ints.multiply(E, F))
            const Y3 = math.mod(Ints.multiply(G, H))
            const T3 = math.mod(Ints.multiply(E, H))
            const Z3 = math.mod(Ints.multiply(F, G))
            return new ExtendedPoint(X3, Y3, Z3, T3)
        }

        subtract(other: ExtendedPointBase<BIT>): ExtendedPoint {
            return this.add(other.negate())
        }

        // Non-constant-time multiplication. Uses double-and-add algorithm.
        // It's faster, but should only be used when you don't care about
        // an exposed private key e.g. sig verification.
        multiplyUnsafe(scalar: BIT): ExtendedPoint {
            if (!serializer.isValidScalar(scalar)) throw new TypeError('Point#multiply: expected number or bigint')
            let n = math.mod(scalar, CURVE.n)
            if (Ints.equal(n, toBigInt(1))) return this
            let p = ExtendedPoint.ZERO
            let d: ExtendedPoint = new ExtendedPoint(this.x, this.y, this.z, this.t)
            while (Ints.greaterThan(n, toBigInt(0))) {
                if (Ints.NE(Ints.bitwiseAnd(n, toBigInt(1)), 0)) p = p.add(d)
                d = d.double()
                n = Ints.signedRightShift(n, toBigInt(1)) // n >>= 1;
            }
            return p
        }

        precomputeWindow(W: number): ExtendedPoint[] {
            const windows = 256 / W + 1
            const points: ExtendedPoint[] = []
            let p = new ExtendedPoint(this.x, this.y, this.z, this.t)
            let base = p
            for (let window = 0; window < windows; window++) {
                base = p
                points.push(base)
                for (let i = 1; i < 2 ** (W - 1); i++) {
                    base = base.add(p)
                    points.push(base)
                }
                p = base.double()
            }
            return points
        }

        wNAF(n: BIT, affinePoint?: PointData<BIT>): [ExtendedPoint, ExtendedPoint] {
            if (!affinePoint && this.equals(ExtendedPoint.BASE)) affinePoint = POINT_BASE
            const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1
            if (256 % W) {
                throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2')
            }

            let precomputes = affinePoint && ExtendedPoint.pointPrecomputes.get(affinePoint)
            if (!precomputes) {
                precomputes = this.precomputeWindow(W)
                if (affinePoint && W !== 1) {
                    precomputes = ExtendedPoint.normalizeZ(precomputes)
                    ExtendedPoint.pointPrecomputes.set(affinePoint, precomputes)
                }
            }

            let p = ExtendedPoint.ZERO
            let f = ExtendedPoint.ZERO

            const windows = 256 / W + 1
            const windowSize = 2 ** (W - 1)

            const mask = Ints.BigInt(2 ** W - 1) // Create mask with W ones: 0b1111 for W=4 etc.
            const maxNumber = 2 ** W
            const shiftBy = Ints.BigInt(W)

            for (let window = 0; window < windows; window++) {
                const offset = window * windowSize
                // Extract W bits.
                // let wbits = Number(n & mask);
                let wbits = Ints.toNumber(Ints.bitwiseAnd(n, mask))

                // Shift number by W bits.
                n = Ints.signedRightShift(n, shiftBy) // n >>= shiftBy;

                // If the bits are bigger than max size, we'll split those.
                // +224 => 256 - 32
                if (wbits > windowSize) {
                    wbits -= maxNumber
                    n = Ints.add(n, toBigInt(1))
                }

                // Check if we're onto Zero point.
                // Add random point inside current window to f.
                if (wbits === 0) {
                    f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset])
                } else {
                    const cached = precomputes[offset + Math.abs(wbits) - 1]
                    p = p.add(wbits < 0 ? cached.negate() : cached)
                }
            }

            return [p, f]
        }

        // Constant time multiplication.
        // Uses wNAF method. Windowed method may be 10% faster,
        // but takes 2x longer to generate and consumes 2x memory.
        multiply(scalar: number | BIT, affinePoint?: PointData<BIT>): ExtendedPoint {
            if (!serializer.isValidScalar(scalar)) throw new TypeError('Point#multiply: expected number or bigint')
            const s: BIT = typeof scalar === 'number' ? toBigInt(scalar) : scalar
            const n = math.mod(s, CURVE.n)
            const normed = ExtendedPoint.normalizeZ(this.wNAF(n, affinePoint))[0]
            return normed
        }

        // Converts Extended point to default (x, y) coordinates.
        // Can accept precomputed Z^-1 - for example, from invertBatch.
        toAffine(invZ: BIT = math.invert(this.z)): PointData<BIT> {
            const x = math.mod(Ints.multiply(this.x, invZ))
            const y = math.mod(Ints.multiply(this.y, invZ))
            return { x, y }
        }
    }
}

export function makePointClass<BIT extends BigIntType>(
    CURVE: CurveType<BIT>,
    Ints: Integers<BIT>,
    serializer: SerializationFunctions<BIT>,
    math: MathFunctions<BIT>,
    keyUtils: KeyUtils<BIT>,
    toBigInt: IntFactory<BIT>,
    ExtendedPointClass: ExtendedPointStatic<BIT>,
    sha512Impl?: Hash
): PointStatic<BIT> {
    return class Point {
        // Base point aka generator
        // public_key = Point.BASE * private_key
        static BASE: Point = new Point(CURVE.Gx, CURVE.Gy)
        // Identity point aka point at infinity
        // point = point + zero_point
        static ZERO: Point = new Point(toBigInt(0), toBigInt(1))
        // We calculate precomputes for elliptic curve point multiplication
        // using windowed method. This specifies window size and
        // stores precomputed values. Usually only base point would be precomputed.
        _WINDOW_SIZE?: number

        constructor(public x: BIT, public y: BIT) {}

        // "Private method", don't use it directly.
        _setWindowSize(windowSize: number) {
            this._WINDOW_SIZE = windowSize
            ExtendedPointClass.pointPrecomputes.delete(this)
        }
        static precompute(windowSize = 8, point = Point.BASE): typeof Point.BASE {
            const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y)
            cached._setWindowSize(windowSize)
            cached.multiply(toBigInt(1))
            return cached
        }

        // Converts hash string or Uint8Array to Point.
        // Uses algo from RFC8032 5.1.3.
        static fromHex(hash: Hex) {
            const { d, P } = CURVE
            const bytes = hash instanceof Uint8Array ? hash : hexToBytes(hash)
            if (bytes.length !== 32) throw new Error('Point.fromHex: expected 32 bytes')
            // 1.  First, interpret the string as an integer in little-endian
            // representation. Bit 255 of this number is the least significant
            // bit of the x-coordinate and denote this value x_0.  The
            // y-coordinate is recovered simply by clearing this bit.  If the
            // resulting value is >= p, decoding fails.
            const last = bytes[31]
            const normedLast = last & ~0x80
            const isLastByteOdd = (last & 0x80) !== 0
            const normed = Uint8Array.from(Array.from(bytes.slice(0, 31)).concat(normedLast))
            const y = serializer.bytesToNumberLE(normed)
            if (Ints.greaterThanOrEqual(y, P)) throw new Error('Point.fromHex expects hex <= Fp')

            // 2.  To recover the x-coordinate, the curve equation implies
            // x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
            // non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
            const y2 = math.mod(Ints.multiply(y, y))
            const u = math.mod(Ints.subtract(y2, toBigInt(1)))
            const v = math.mod(Ints.add(Ints.multiply(d, y2), toBigInt(1)))

            const uvr = math.uvRatio(u, v)
            const isValid = uvr.isValid
            let x = uvr.value
            if (!isValid) throw new Error('Point.fromHex: invalid y coordinate')

            // 4.  Finally, use the x_0 bit to select the right square root.  If
            // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
            // 2, set x <-- p - x.  Return the decoded point (x,y).
            const isXOdd = Ints.equal(Ints.bitwiseAnd(x, toBigInt(1)), toBigInt(1))
            if (isLastByteOdd !== isXOdd) {
                x = math.mod(Ints.unaryMinus(x))
            }
            return new Point(x, y)
        }

        static async fromPrivateKey(privateKey: PrivKey<BIT>) {
            const privBytes = await sha512(keyUtils.normalizePrivateKey(privateKey), sha512Impl)
            return Point.BASE.multiply(keyUtils.encodePrivate(privBytes))
        }

        /**
         * Converts point to compressed representation of its Y.
         * ECDSA uses `04${x}${y}` to represent long form and
         * `02${x}` / `03${x}` to represent short form,
         * where leading bit signifies positive or negative Y.
         * EDDSA (ed25519) uses short form.
         */
        toRawBytes(): Uint8Array {
            const hex = serializer.numberToHex(this.y)
            const u8 = new Uint8Array(B32)
            for (let i = hex.length - 2, j = 0; j < B32 && i >= 0; i -= 2, j++) {
                u8[j] = Number.parseInt(hex[i] + hex[i + 1], 16)
            }
            // const mask = this.x & jsbi(1) ? 0x80 : 0;
            const mask = Ints.NE(Ints.bitwiseAnd(this.x, toBigInt(1)), 0) ? 0x80 : 0
            u8[B32 - 1] |= mask
            return u8
        }

        // Same as toRawBytes, but returns string.
        toHex(): string {
            return bytesToHex(this.toRawBytes())
        }

        // Converts to Montgomery; aka x coordinate of curve25519.
        // We don't have fromX25519, because we don't know sign!
        toX25519(): BIT {
            // curve25519 is birationally equivalent to ed25519
            // x, y: ed25519 coordinates
            // u, v: x25519 coordinates
            // u = (1 + y) / (1 - y)
            // See https://blog.filippo.io/using-ed25519-keys-for-encryption
            return math.mod(
                Ints.multiply(Ints.add(toBigInt(1), this.y), math.invert(Ints.subtract(toBigInt(1), this.y)))
            )
        }

        equals(other: Point): boolean {
            return Ints.equal(this.x, other.x) && Ints.equal(this.y, other.y)
        }

        negate() {
            return new Point(math.mod(Ints.unaryMinus(this.x)), this.y)
        }

        add(other: Point): Point {
            const pointData = ExtendedPointClass.fromAffine(this).add(ExtendedPointClass.fromAffine(other)).toAffine()

            return new Point(pointData.x, pointData.y)
        }

        subtract(other: Point): Point {
            return this.add(other.negate())
        }

        // Constant time multiplication.
        multiply(scalar: number | BIT): Point {
            const tmp = ExtendedPointClass.fromAffine(this)
            const prod = tmp.multiply(scalar, this)
            const aff = prod.toAffine()
            return new Point(aff.x, aff.y)
        }
    }
}

function equalBytes(b1: Uint8Array, b2: Uint8Array) {
    if (b1.length !== b2.length) {
        return false
    }
    for (let i = 0; i < b1.length; i++) {
        if (b1[i] !== b2[i]) {
            return false
        }
    }
    return true
}
