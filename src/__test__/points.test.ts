import { makeED } from '..'
import JSBI from 'jsbi'
import { sha512 } from 'js-sha512'
import { ExtendedPointData } from '../points'

const ed = makeED(JSBI, sha512)

describe('Test Point and ExtendedPoint functions', () => {
    test('fExtendedPoint romAffine', () => {
        const extZero = ed.ExtendedPoint.fromAffine(ed.Point.ZERO)
        expect(extZero).toEqual<ExtendedPointData<JSBI>>(ed.ExtendedPoint.ZERO)

        const fromAffineOnExtendedPoint = () => {
            ed.ExtendedPoint.fromAffine(extZero)
        }
        expect(fromAffineOnExtendedPoint).toThrow('ExtendedPoint#fromAffine: expected Point')
    })

    test('multiply different input', () => {
        const badScalar = () => {
            ed.ExtendedPoint.BASE.multiplyUnsafe(JSBI.BigInt(-1))
        }

        expect(badScalar).toThrow('Point#multiply: expected number or bigint')

        const oneB = ed.ExtendedPoint.BASE.multiplyUnsafe(JSBI.BigInt(1))
        expect(oneB).toEqual(ed.ExtendedPoint.BASE)
    })

    test('precompute windows', () => {
        const twoB = ed.Point.BASE.multiply(2)
        const precomputeBase = ed.Point.precompute()
        const precomputeTwoW4 = ed.Point.precompute(4, twoB)
        expect(precomputeBase._WINDOW_SIZE).toStrictEqual(8)
        expect(precomputeBase).toBe(ed.Point.BASE)
        expect(precomputeTwoW4._WINDOW_SIZE).toStrictEqual(4)
        expect([precomputeTwoW4.x, precomputeTwoW4.y]).toEqual([twoB.x, twoB.y])

        const badWindow = () => {
            ed.Point.precompute(7, twoB.add(twoB))
        }
        expect(badWindow).toThrow('Point#wNAF: Invalid precomputation window, must be power of 2')
    })

    test('Point arithmetic', () => {
        const twoB = ed.Point.BASE.multiply(2)
        const threeB = ed.Point.BASE.multiply(3)
        const twoPlusOneB = twoB.add(ed.Point.BASE)

        expect(twoPlusOneB).toEqual(threeB)

        const threeMinusTwoB = threeB.subtract(twoB)
        expect({ ...threeMinusTwoB, _WINDOW_SIZE: 8 }).toEqual(ed.Point.BASE)
    })

    test('Point fromHex', () => {
        const wrongLengthInput = () => {
            ed.Point.fromHex('aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbc')
        }
        expect(wrongLengthInput).toThrow('Point.fromHex: expected 32 bytes')

        const tooBigInput = () => {
            const two256m1 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ed.Point.fromHex(two256m1)
        }

        expect(tooBigInput).toThrow('Point.fromHex expects hex <= Fp')

        const arbitraryBigInput = () => {
            const two256m1 = '7fadfadffffffffffffffffffffffffffffffffffffffffffffff12345678907'
            ed.Point.fromHex(two256m1)
        }

        expect(arbitraryBigInput).toThrow('Point.fromHex: invalid y coordinate')
    })
})
