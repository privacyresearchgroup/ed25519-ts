/* eslint-disable @typescript-eslint/no-explicit-any */
export interface BigIntType {
    toString(radix?: number): string
}

export interface Integers<BIT extends BigIntType> {
    BigInt(n: number | string): BIT
    add(a: BIT, b: BIT): BIT
    subtract(a: BIT, b: BIT): BIT
    multiply(a: BIT, b: BIT): BIT
    divide(a: BIT, b: BIT): BIT
    exponentiate(a: BIT, b: BIT): BIT
    remainder(n: BIT, mod: BIT): BIT
    unaryMinus(a: BIT): BIT

    bitwiseAnd(a: BIT, b: BIT): BIT
    bitwiseOr(a: BIT, b: BIT): BIT
    bitwiseNot(a: BIT): BIT
    bitwiseXor(a: BIT, b: BIT): BIT

    signedRightShift(a: BIT, b: BIT): BIT
    leftShift(a: BIT, b: BIT): BIT

    greaterThan(a: BIT, b: BIT): boolean
    greaterThanOrEqual(a: BIT, b: BIT): boolean
    lessThan(a: BIT, b: BIT): boolean
    lessThanOrEqual(a: BIT, b: BIT): boolean
    equal(a: BIT, b: BIT): boolean
    notEqual(a: BIT, b: BIT): boolean
    GT(a: any, b: any): boolean
    GE(a: any, b: any): boolean
    LT(a: any, b: any): boolean
    LE(a: any, b: any): boolean
    EQ(a: any, b: any): boolean
    NE(a: any, b: any): boolean

    toNumber(a: BIT): number
}
