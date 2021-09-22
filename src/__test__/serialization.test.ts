import { concatBytes, hexToBytes } from '../serialization'
import JSBI from 'jsbi'

describe('Test serialization functions', () => {
    test('concatBytes', () => {
        const b1 = Uint8Array.from([1, 2, 3, 4])
        const b2 = Uint8Array.from([5, 6, 7])
        const bcat = concatBytes(b1, b2)

        const b1cat = concatBytes(b1)

        expect(bcat).toEqual(Uint8Array.from([1, 2, 3, 4, 5, 6, 7]))
        expect(b1cat).toEqual(b1)
    })

    test('hexToBytes', () => {
        const badPadding = () => {
            hexToBytes('fff')
        }
        expect(badPadding).toThrow('hexToBytes: received invalid unpadded hex')

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const sloppyJSInput = (n: any) => {
            hexToBytes(n as string)
        }
        expect(() => sloppyJSInput(1)).toThrow('hexToBytes: expected string, got number')
    })
})
