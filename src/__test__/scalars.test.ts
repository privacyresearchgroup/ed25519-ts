import { sha512 } from 'js-sha512'
import JSBI from 'jsbi'
import { makeED } from '..'

const ed = makeED(JSBI, sha512)
describe('test scalar operations', () => {
    test('number serialization', () => {
        const bigNum = JSBI.multiply(ed.CURVE.P, ed.CURVE.n)
        const serialized = ed.scalars.serializeNumber(bigNum)
        const deserialized = ed.scalars.deserializeNumber(serialized)

        expect(serialized.length).toEqual(64)
        expect(deserialized.toString()).toEqual(bigNum.toString())
    })

    test('scalar serialization', () => {
        const bigNum = JSBI.multiply(ed.CURVE.P, ed.CURVE.n)
        const scalar = JSBI.multiply(ed.CURVE.P, ed.CURVE.n)
        const serialized = ed.scalars.serializeNumber(bigNum)
        const serializedScalar = ed.scalars.serializeScalar(scalar)
        const deserializedScalar1 = ed.scalars.deserializeScalar(serialized)
        const deserializedScalar2 = ed.scalars.deserializeScalar(serializedScalar)

        expect(serializedScalar.length).toEqual(32)
        expect(deserializedScalar1.toString()).toEqual('0')
        expect(deserializedScalar2.toString()).toEqual('0')
    })
})
