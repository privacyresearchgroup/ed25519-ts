import { BigIntType, Integers } from './integers'

export type Hex = Uint8Array | string
export type PrivKey<BIT extends BigIntType> = Hex | BIT | number
export const B32 = 32

export type IntFactory<BIT extends BigIntType> = (n: string | number) => BIT

export class SerializationFunctions<BIT extends BigIntType> {
    private ZERO: BIT
    constructor(private Ints: Integers<BIT>) {
        this.ZERO = this.Ints.BigInt(0)
    }

    private isBigIntType(n: unknown): n is BIT {
        return n instanceof this.ZERO.constructor || (typeof n === 'bigint' && typeof this.ZERO == 'bigint')
    }

    toBigInt(n: number | string): BIT {
        return this.Ints.BigInt(n)
    }
    numberToHex(num: number | BIT): string {
        const hex = num.toString(16)
        return hex.length & 1 ? `0${hex}` : hex
    }

    numberToBytesPadded(num: BIT, length: number = B32): Uint8Array {
        const hex = this.numberToHex(num).padStart(length * 2, '0')
        return hexToBytes(hex).reverse()
    }

    isValidScalar(num: number | BIT): boolean {
        if (this.isBigIntType(num) && this.Ints.greaterThan(num, this.toBigInt(0))) return true
        if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num)) return true

        return false
    }

    // Little Endian
    bytesToNumberLE(uint8a: Uint8Array): BIT {
        let value = this.toBigInt(0)
        for (let i = 0; i < uint8a.length; i++) {
            value = this.Ints.add(
                value,
                this.Ints.leftShift(
                    this.Ints.BigInt(uint8a[i]),
                    this.Ints.multiply(this.toBigInt(8), this.Ints.BigInt(i))
                )
            )
        }
        return value
    }
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    if (arrays.length === 1) return arrays[0]
    const length = arrays.reduce((a, arr) => a + arr.length, 0)
    const result = new Uint8Array(length)
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i]
        result.set(arr, pad)
        pad += arr.length
    }
    return result
}

// Convert between types
// ---------------------
export function bytesToHex(uint8a: Uint8Array): string {
    // pre-caching chars could speed this up 6x.
    let hex = ''
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0')
    }
    return hex
}

export function hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex)
    }
    if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex')
    const array = new Uint8Array(hex.length / 2)
    for (let i = 0; i < array.length; i++) {
        const j = i * 2
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16)
    }
    return array
}
