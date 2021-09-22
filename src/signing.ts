import { PointBase } from '.'
import { CurveType, isWithinCurveOrder } from './curve'
import { Hash, makeSha512ToNumberLE, sha512 } from './hash'
import { BigIntType, Integers } from './integers'
import { KeyUtils } from './key-utils'
import { MathFunctions } from './math'
import { ExtendedPointStatic, PointStatic } from './points'
import { SerializationFunctions, IntFactory, Hex, hexToBytes, B32, bytesToHex, PrivKey } from './serialization'

export interface SignatureData<BIT extends BigIntType> {
    r: PointBase<BIT>
    s: BIT
}
export interface SignatureOps {
    toRawBytes(): Uint8Array
    toHex(): string
}

export type SignatureBase<BIT extends BigIntType> = SignatureData<BIT> & SignatureOps

export interface SignatureStatic<BIT extends BigIntType> {
    new (r: PointBase<BIT>, s: BIT): SignatureBase<BIT>
    fromHex(hex: Hex): SignatureBase<BIT>
}

export type SigType<BIT extends BigIntType> = SignatureBase<BIT> | Hex
export type PubKey<BIT extends BigIntType> = Hex | PointBase<BIT>

export interface SigningFunctions<BIT extends BigIntType> {
    Signature: SignatureStatic<BIT>
    sign: {
        (hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>
        (hash: string, privateKey: Hex): Promise<string>
    }
    verify: (signature: SigType<BIT>, hash: Hex, publicKey: PubKey<BIT>) => Promise<boolean>
    getPublicKey: {
        (privateKey: number | Uint8Array | BIT): Promise<Uint8Array>
        (privateKey: string): Promise<string>
    }
}
export function makeSigningFunctions<BIT extends BigIntType>(
    CURVE: CurveType<BIT>,
    Ints: Integers<BIT>,
    serializer: SerializationFunctions<BIT>,
    math: MathFunctions<BIT>,
    keyUtils: KeyUtils<BIT>,
    toBigInt: IntFactory<BIT>,
    PointClass: PointStatic<BIT>,
    ExtendedPointClass: ExtendedPointStatic<BIT>,
    sha512Impl?: Hash
): SigningFunctions<BIT> {
    const Signature = class {
        constructor(public r: typeof PointClass.BASE, public s: BIT) {}

        static fromHex(hex: Hex) {
            hex = ensureBytes(hex)
            const r = PointClass.fromHex(hex.slice(0, 32))
            const s = serializer.bytesToNumberLE(hex.slice(32))
            if (!isWithinCurveOrder(s, Ints, CURVE)) throw new Error('Signature.fromHex expects s <= CURVE.n')
            return new Signature(r, s)
        }

        toRawBytes() {
            const numberBytes = hexToBytes(serializer.numberToHex(this.s)).reverse()
            const sBytes = new Uint8Array(B32)
            sBytes.set(numberBytes)
            const res = new Uint8Array(B32 * 2)
            res.set(this.r.toRawBytes())
            res.set(sBytes, 32)
            return res
            // return concatTypedArrays(this.r.toRawBytes(), sBytes);
        }

        toHex() {
            return bytesToHex(this.toRawBytes())
        }
    }

    type PubKey = Hex | typeof PointClass.BASE
    type SigType = Hex | ReturnType<typeof Signature.fromHex>

    const sha512ToNumberLE = makeSha512ToNumberLE(serializer, math, CURVE, sha512Impl)
    function getPublicKey(privateKey: Uint8Array | BIT | number): Promise<Uint8Array>
    function getPublicKey(privateKey: string): Promise<string>
    async function getPublicKey(privateKey: PrivKey<BIT>) {
        const key = await PointClass.fromPrivateKey(privateKey)
        return typeof privateKey === 'string' ? key.toHex() : key.toRawBytes()
    }

    function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>
    function sign(hash: string, privateKey: Hex): Promise<string>
    async function sign(hash: Hex, privateKey: Hex) {
        const privBytes = await sha512(keyUtils.normalizePrivateKey(privateKey))
        const p = keyUtils.encodePrivate(privBytes)
        const P = PointClass.BASE.multiply(p)
        const msg = ensureBytes(hash)
        const r = await sha512ToNumberLE(keyUtils.keyPrefix(privBytes), msg)
        const R = PointClass.BASE.multiply(r)
        const h = await sha512ToNumberLE(R.toRawBytes(), P.toRawBytes(), msg)
        const S = math.mod(Ints.add(r, Ints.multiply(h, p)), CURVE.n)
        const sig = new Signature(R, S)
        return typeof hash === 'string' ? sig.toHex() : sig.toRawBytes()
    }

    async function verify(signature: SigType, hash: Hex, publicKey: PubKey): Promise<boolean> {
        hash = ensureBytes(hash)

        const pk: typeof PointClass.BASE =
            publicKey instanceof PointClass.BASE.constructor
                ? (publicKey as typeof PointClass.BASE)
                : PointClass.fromHex(publicKey as string)
        if (!(signature instanceof Signature)) {
            signature = Signature.fromHex(signature)
        }
        const hs = await sha512ToNumberLE(signature.r.toRawBytes(), pk.toRawBytes(), hash)
        const Ph = ExtendedPointClass.fromAffine(pk).multiplyUnsafe(hs)
        const Gs = ExtendedPointClass.BASE.multiplyUnsafe(signature.s)
        const RPh = ExtendedPointClass.fromAffine(signature.r).add(Ph)
        return RPh.subtract(Gs).multiplyUnsafe(toBigInt(8)).equals(ExtendedPointClass.ZERO)
    }

    return { Signature, sign, verify, getPublicKey }
}

function ensureBytes(hash: Hex): Uint8Array {
    return hash instanceof Uint8Array ? hash : hexToBytes(hash)
}
