import { Hash } from './hash'
import { CurveType, makeConstants, makeCurve } from './curve'
import { KeyUtils } from './key-utils'
import { SerializationFunctions } from './serialization'
import { MathFunctions } from './math'
import { ExtendedPointStatic, makeExtendedPointClass, makePointClass, PointStatic } from './points'
import { BigIntType, Integers } from './integers'
import { makeUtils, UtilsType } from './utils'
import { makeSigningFunctions, SigningFunctions } from './signing'

export * from './integers'
export * from './native-bigint'
export { CurveType, Constants } from './curve'
export { Message, Hash } from './hash'
export { Hex, PrivKey, IntFactory } from './serialization'
export { PointBase, PointStatic, ExtendedPointBase, ExtendedPointStatic } from './points'
export { SignatureBase, SignatureStatic } from './signing'

export interface Ed25519Type<BIT extends BigIntType> extends SigningFunctions<BIT> {
    Point: PointStatic<BIT>
    ExtendedPoint: ExtendedPointStatic<BIT>
    math: MathFunctions<BIT>
    keyUtils: KeyUtils<BIT>
    CURVE: CurveType<BIT>
    utils: UtilsType
}

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export function makeED<BIT extends BigIntType>(Ints: Integers<BIT>, sha512Impl?: Hash): Ed25519Type<BIT> {
    const toBigInt = Ints.BigInt
    const serializer = new SerializationFunctions(Ints)
    const CURVE = makeCurve(toBigInt)
    const CONSTANTS = makeConstants(toBigInt)
    const math = new MathFunctions(Ints, CURVE, CONSTANTS)
    const keyUtils = new KeyUtils(Ints, CURVE, serializer, math)

    // Default Point works in default aka affine coordinates: (x, y)
    // Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy)
    // https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
    const ExtendedPoint = makeExtendedPointClass(CURVE, CONSTANTS, Ints, serializer, math, toBigInt)

    const Point = makePointClass(CURVE, Ints, serializer, math, keyUtils, toBigInt, ExtendedPoint, sha512Impl)

    const utils = { ...makeUtils(CURVE, Ints, serializer), precompute: Point.precompute }
    const { Signature, sign, verify, getPublicKey } = makeSigningFunctions(
        CURVE,
        Ints,
        serializer,
        math,
        keyUtils,
        toBigInt,
        Point,
        ExtendedPoint,
        sha512Impl
    )

    // Enable precomputes. Slows down first publicKey computation by 20ms.
    Point.BASE._setWindowSize(8)
    return {
        Point,
        ExtendedPoint,
        utils,
        math,
        CURVE,
        sign,
        verify,
        getPublicKey,
        Signature,
        keyUtils,
    }
}
