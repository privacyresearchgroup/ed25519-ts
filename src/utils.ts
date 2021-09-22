import { CurveType, randomScalar } from './curve'
import { BigIntType, Integers } from './integers'
import { SerializationFunctions } from './serialization'

const randomBytes = (bytesLength = 32): Uint8Array => {
    if (typeof self == 'object' && 'crypto' in self) {
        return self.crypto.getRandomValues(new Uint8Array(bytesLength))
    } else if (typeof process === 'object' && 'node' in process.versions) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { randomBytes } = require('crypto')
        return new Uint8Array(randomBytes(bytesLength).buffer)
    } else {
        throw new Error("The environment doesn't have randomBytes function")
    }
}

export interface UtilsType {
    TORSION_SUBGROUP: string[]
    randomBytes: (bytesLength?: number) => Uint8Array
    randomPrivateKey: () => Uint8Array
}
export function makeUtils<BIT extends BigIntType>(
    CURVE: CurveType<BIT>,
    Ints: Integers<BIT>,
    serializer: SerializationFunctions<BIT>
): UtilsType {
    return {
        // The 8-torsion subgroup ℰ8.
        // Those are "buggy" points, if you multiply them by 8, you'll receive Point.ZERO.
        // Ported from curve25519-dalek.
        TORSION_SUBGROUP: [
            '0100000000000000000000000000000000000000000000000000000000000000',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            '0000000000000000000000000000000000000000000000000000000000000080',
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
            '0000000000000000000000000000000000000000000000000000000000000000',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
        ],
        randomBytes: randomBytes,
        // NIST SP 800-56A rev 3, section 5.6.1.2.2
        // https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
        randomPrivateKey: (): Uint8Array => {
            return randomScalar(CURVE, Ints, serializer, randomBytes)
        },
    }
}
