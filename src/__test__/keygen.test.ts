import { makeED } from '..'
import JSBI from 'jsbi'
import { sha512 } from 'js-sha512'

const ed = makeED(JSBI, sha512)

describe('Test key generation', () => {
    test('generate key', async () => {
        const k = ed.utils.randomPrivateKey()
        const pub = await ed.getPublicKey(k)

        const pub_pt = await ed.Point.fromPrivateKey(k)

        expect(pub_pt.toRawBytes()).toEqual(pub)

        const k_scalar = ed.keyUtils.encodePrivate(k)
        const k_inv = ed.math.invert(k_scalar, ed.CURVE.n)
        const kinvP = pub_pt.multiply(k_inv)
        expect(kinvP.multiply(8).equals(ed.Point.ZERO))
    })
})
