import { CurveType } from './curve'
import { concatBytes, SerializationFunctions } from './serialization'
import { MathFunctions } from './math'
import { BigIntType } from './integers'

export type Message = string | number[] | ArrayBuffer | Uint8Array

export interface Hash {
    /**
     * Hash and return hex string.
     *
     * @param message The message you want to hash.
     */
    hex(message: Message): string

    /**
     * Hash and return ArrayBuffer.
     *
     * @param message The message you want to hash.
     */
    arrayBuffer(message: Message): ArrayBuffer

    /**
     * Hash and return integer array.
     *
     * @param message The message you want to hash.
     */
    digest(message: Message): number[]
}

export async function sha512(message: Uint8Array, sha512Impl?: Hash): Promise<Uint8Array> {
    if (sha512Impl) {
        return new Uint8Array(sha512Impl.digest(message))
    } else if (typeof self == 'object' && 'crypto' in self) {
        const buffer = await self.crypto.subtle.digest('SHA-512', message.buffer)
        return new Uint8Array(buffer)
    } else if (typeof process === 'object' && 'node' in process.versions) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { createHash } = require('crypto')
        const hash = createHash('sha512')
        hash.update(message)
        return Uint8Array.from(hash.digest())
    } else {
        throw new Error('SHA512 unavailable on platform')
    }
}

export function makeSha512ToNumberLE<BIT extends BigIntType>(
    serialization: SerializationFunctions<BIT>,
    math: MathFunctions<BIT>,
    CURVE: CurveType<BIT>,
    sha512Impl?: Hash
) {
    return async (...args: Uint8Array[]): Promise<BIT> => {
        const messageArray = concatBytes(...args)
        const hash = await sha512(messageArray, sha512Impl)
        const value = serialization.bytesToNumberLE(hash)
        return math.mod(value, CURVE.n)
    }
}
