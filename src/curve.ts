import { IntFactory, SerializationFunctions } from './serialization'
import { BigIntType, Integers } from './integers'

export interface CurveType<BIT extends BigIntType> {
    a: BIT
    d: BIT
    P: BIT
    n: BIT
    h: BIT
    Gx: BIT
    Gy: BIT
}

export interface Constants<BIT extends BigIntType> {
    SQRT_M1: BIT
    SQRT_AD_MINUS_ONE: BIT
    INVSQRT_A_MINUS_D: BIT
    ONE_MINUS_D_SQ: BIT
    D_MINUS_ONE_SQ: BIT
}

export function makeCurve<BIT extends BigIntType>(toBigInt: IntFactory<BIT>): CurveType<BIT> {
    const p25519 = toBigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949')
    return {
        // Params: a, b
        a: toBigInt(-1),
        // Equal to -121665/121666 over finite field.
        // Negative number is P - number, and division is invert(number, P)
        d: toBigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
        // Finite field 𝔽p over which we'll do calculations
        P: p25519,
        // Subgroup order aka C
        // 2n ** 252n + 27742317777372353535851937790883648493n,
        n: toBigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'),
        // Cofactor
        h: toBigInt(8),
        // Base point (x, y) aka generator point
        Gx: toBigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
        Gy: toBigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
    }
}

export function makeConstants<BIT extends BigIntType>(toBigInt: IntFactory<BIT>): Constants<BIT> {
    return {
        // √(-1) aka √(a) aka 2^((p-1)/4)
        SQRT_M1: toBigInt('19681161376707505956807079304988542015446066515923890162744021073123829784752'),
        // √(ad - 1)
        SQRT_AD_MINUS_ONE: toBigInt('25063068953384623474111414158702152701244531502492656460079210482610430750235'),
        // 1 / √(a-d)
        INVSQRT_A_MINUS_D: toBigInt('54469307008909316920995813868745141605393597292927456921205312896311721017578'),
        // 1-d²
        ONE_MINUS_D_SQ: toBigInt('1159843021668779879193775521855586647937357759715417654439879720876111806838'),
        // (d-1)²
        D_MINUS_ONE_SQ: toBigInt('40440834346308536858101042469323190826248399146238708352240133220865137265952'),
    }
}

export function isWithinCurveOrder<BIT extends BigIntType>(
    num: BIT,
    Ints: Integers<BIT>,
    CURVE: CurveType<BIT>
): boolean {
    return Ints.LT(0, num) && Ints.lessThan(num, CURVE.n)
}

export type RandGen = (bytesLength: number) => Uint8Array
export function randomScalar<BIT>(
    curve: CurveType<BIT>,
    Ints: Integers<BIT>,
    serialization: SerializationFunctions<BIT>,
    randomBytes: RandGen
): Uint8Array {
    let i = 1024
    while (i--) {
        const b32 = randomBytes(32)
        const num = serialization.bytesToNumberLE(b32)
        if (Ints.greaterThan(num, Ints.BigInt(1)) && Ints.lessThan(num, curve.n)) return b32
    }
    throw new Error('Valid private key was not found in 1024 iterations. PRNG is broken')
}
