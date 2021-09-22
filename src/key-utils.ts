import { CurveType } from './curve'
import { B32, hexToBytes, PrivKey, SerializationFunctions } from './serialization'
import { MathFunctions } from './math'
import { BigIntType, Integers } from './integers'

export class KeyUtils<BIT extends BigIntType> {
    constructor(
        private Ints: Integers<BIT>,
        private CURVE: CurveType<BIT>,
        private serializer: SerializationFunctions<BIT>,
        private math: MathFunctions<BIT>
    ) {}

    toBigInt(n: number | string): BIT {
        return this.Ints.BigInt(n)
    }

    keyPrefix(privateBytes: Uint8Array): Uint8Array {
        return privateBytes.slice(B32)
    }

    encodePrivate(privateBytes: Uint8Array): BIT {
        const last = B32 - 1
        const head = privateBytes.slice(0, B32)
        head[0] &= 248
        head[last] &= 127
        head[last] |= 64
        return this.math.mod(this.serializer.bytesToNumberLE(head), this.CURVE.n)
    }

    normalizePrivateKey(key: PrivKey<BIT>): Uint8Array {
        let num: BIT
        if (
            key instanceof this.CURVE.P.constructor ||
            (typeof key === 'number' && Number.isSafeInteger(key)) ||
            (typeof key === 'bigint' && typeof this.CURVE.P === 'bigint')
        ) {
            num = (typeof key === 'number' ? this.Ints.BigInt(key) : key) as BIT
            if (
                this.Ints.lessThan(num, this.toBigInt(0)) ||
                this.Ints.greaterThan(num, this.Ints.exponentiate(this.toBigInt(2), this.toBigInt(256)))
            )
                throw new Error('Expected 32 bytes of private key')
            key = num.toString(16).padStart(B32 * 2, '0')
        }
        if (typeof key === 'string') {
            if (key.length !== 64) throw new Error('Expected 32 bytes of private key')
            return hexToBytes(key)
        } else if (key instanceof Uint8Array) {
            if (key.length !== 32) throw new Error('Expected 32 bytes of private key')
            return key
        } else {
            throw new TypeError('Expected valid private key')
        }
    }
}
