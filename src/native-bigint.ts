/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
import { Integers } from '.'

export class NativeBigInt implements Integers<bigint> {
    BigInt(n: string | number): bigint {
        return BigInt(n)
    }
    add(a: bigint, b: bigint): bigint {
        return a + b
    }
    subtract(a: bigint, b: bigint): bigint {
        return a - b
    }
    multiply(a: bigint, b: bigint): bigint {
        return a * b
    }
    divide(a: bigint, b: bigint): bigint {
        return a / b
    }
    exponentiate(a: bigint, b: bigint): bigint {
        return a ** b
    }
    remainder(n: bigint, mod: bigint): bigint {
        return n % mod
    }
    unaryMinus(a: bigint): bigint {
        return -a
    }
    bitwiseAnd(a: bigint, b: bigint): bigint {
        return a & b
    }
    bitwiseOr(a: bigint, b: bigint): bigint {
        return a | b
    }
    bitwiseNot(a: bigint): bigint {
        return ~a
    }
    bitwiseXor(a: bigint, b: bigint): bigint {
        return a ^ b
    }
    signedRightShift(a: bigint, b: bigint): bigint {
        return a >> b
    }
    leftShift(a: bigint, b: bigint): bigint {
        return a << b
    }
    greaterThan(a: bigint, b: bigint): boolean {
        return a > b
    }
    greaterThanOrEqual(a: bigint, b: bigint): boolean {
        return a >= b
    }
    lessThan(a: bigint, b: bigint): boolean {
        return a < b
    }
    lessThanOrEqual(a: bigint, b: bigint): boolean {
        return a <= b
    }
    equal(a: bigint, b: bigint): boolean {
        return a === b
    }
    notEqual(a: bigint, b: bigint): boolean {
        return a !== b
    }
    GT(a: any, b: any): boolean {
        return this.BigInt(a) > this.BigInt(b)
    }
    GE(a: any, b: any): boolean {
        return this.BigInt(a) >= this.BigInt(b)
    }
    LT(a: any, b: any): boolean {
        return this.BigInt(a) < this.BigInt(b)
    }
    LE(a: any, b: any): boolean {
        return this.BigInt(a) <= this.BigInt(b)
    }
    EQ(a: any, b: any): boolean {
        return this.BigInt(a) === this.BigInt(b)
    }
    NE(a: any, b: any): boolean {
        return this.BigInt(a) !== this.BigInt(b)
    }
    toNumber(a: bigint): number {
        return Number(a)
    }
}
