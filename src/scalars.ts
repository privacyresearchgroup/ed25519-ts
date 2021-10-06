import { BigIntType, CurveType, Integers } from '.'
import { MathFunctions } from './math'
import { SerializationFunctions } from './serialization'

export class Scalars<BIT extends BigIntType> {
    private _mod: BIT
    constructor(
        private Ints: Integers<BIT>,
        CURVE: CurveType<BIT>,
        private _serializer: SerializationFunctions<BIT>,
        private _math: MathFunctions<BIT>
    ) {
        this._mod = CURVE.n
    }

    serializeScalar(n: BIT): Uint8Array {
        // First ensure it is reduced modulo the group order
        const reduced = this._math.mod(n, this._mod)
        return this._serializer.numberToBytesPadded(reduced, 32)
    }

    deserializeScalar(buf: Uint8Array): BIT {
        return this._math.mod(this._serializer.bytesToNumberLE(buf), this._mod)
    }

    serializeNumber(n: BIT): Uint8Array {
        const len = Math.ceil((n.toString(16).length - 2) / 2)
        return this._serializer.numberToBytesPadded(n, len)
    }
    deserializeNumber(buf: Uint8Array): BIT {
        return this._serializer.bytesToNumberLE(buf)
    }
}
