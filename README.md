# Ed25519 and Ristretto255 with Injectable BigInt and Hash Dependencies

This is an efficient implementation of [ed25519](https://en.wikipedia.org/wiki/EdDSA) that can be used with any integer arithmetic library that implements a standard interface based on [JSBI](https://github.com/GoogleChromeLabs/jsbi). This allows `ed25519-ts` to be used on platforms where native `bigint`s are not available (e.g. React Native) or with other libraries that may have different performance or security characteristics. The package also allows injection of a SHA-512 dependency, allowing users to
select native versions when possible and best alternatives when not.

Cryptographic features include:

- Direct support for EdDSA signing and verification
- Can be used for asymmetric encryption
- Provides [ristretto255](https://ristretto.group) support and [elligator](https://dl.acm.org/doi/pdf/10.1145/2508859.2516734) encoding/decoding.

The core logic is a direct modification of [noble-ed25519](https://github.com/paulmillr/noble-ed25519). When using `ed25519` on a
platform that provides native `bigint` support, `noble-ed25519` is preferred.

## Usage

Use yarn or NPM in node.js, browser, or React Native:

> yarn add @privacyresearch/pr-ed25519

To use with `JSBI` and `js-sha512`

```js
import JSBI from 'jsbi'
import sha512 from 'js-sha512'
import { makeED } from '@privacyresearch/pr-ed25519'

const ed = makeED(JSBI, sha512.sha512)

const privateKey = ed.utils.randomPrivateKey() // 32-byte Uint8Array or string.
const msgHash = 'aaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbb'

const publicKey = await ed.getPublicKey(privateKey)
const signature = await ed.sign(msgHash, privateKey)
const signatureIsValid = await ed.verify(signature, msgHash, publicKey)
```

In the code examples below we will assume a variable `ed` has been created as above.

### Signing and Verification

The basics of signing can be seen in the example above, however there are some subtleties of type.
Below we extend the example with (superfluous) type annotations so that we see more clearly what was
happening in the example.

```typescript
const privateKey: Uint8Array = ed.utils.randomPrivateKey() // 32-byte Uint8Array or string.
const msgHash: string = 'aaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbb'

// The publicKey is a Uint8Array because privateKey is Uint8Array | BIT | number.
// If privateKey were a (hex) string, then pubKey would be too
const publicKey: Uint8Array = await ed.getPublicKey(privateKey)

// Since msgHash is a (hex) string, signature is also a (hex) string
const signature: string = await ed.sign(msgHash, privateKey)
const signatureIsValid = await ed.verify(signature, msgHash, publicKey)
```

Now we can change this to pass binary data - `Uint8Array`s - instead of strings

```typescript
const privateKey: Uint8Array = ed.utils.randomPrivateKey() // 32-byte Uint8Array or string.
const msgHash: Uint8Array = hexToBytes('aaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbbaaaabbbb')

// The publicKey is a Uint8Array because privateKey is Uint8Array | BIT | number.
// If privateKey were a (hex) string, then pubKey would be too
const publicKey: Uint8Array = await ed.getPublicKey(privateKey)

// Since msgHash is a Uint8Array, signature is also a Uint8Array
const signature: Uint8Array = await ed.sign(msgHash, privateKey)
const signatureIsValid = await ed.verify(signature, msgHash, publicKey)
```

### Curve Arithmetic

Curve points can be manipulated either as affine points (using only (x,y) coordinates) or extended points (using (x,y,z,t)
coordinates). Affine points are represented by the class `ed.Point` which implements the interface `PointBase<BIT>` and has
static methods implementing `PointStatic<BIT>` [code](https://github.com/privacyresearchgroup/pr-ed25519/blob/main/src/points.ts#L26). Extended points are represented by the class `ed.ExtendedPoint` which implements the interface `ExtendedPointBase<BIT>` and has
static methods implementing `ExtendedPointStatic<BIT>` [code](https://github.com/privacyresearchgroup/pr-ed25519/blob/main/src/points.ts#L61).

Manipulation of these points is straightforward. We can add, negate, subtract, and multiply by scalars:

```typescript
// Make some scalars
const scalar6 = Ints.BigInt(6)
const scalar7 = Ints.BigInt(7)
const scalar21 = Ints.BigInt(21)
const scalar42 = Ints.BigInt(42)

// Create some curve points by multiplying the scalars by our base point
const P6 = ed.ExtendedPoint.BASE.multiply(scalar6)
const P7 = ed.ExtendedPoint.BASE.multiply(scalar7)
const P21 = ed.ExtendedPoint.BASE.multiply(scalar21)
const P42 = ed.ExtendedPoint.BASE.multiply(scalar42)

// Now arithmetic works as expected
P6.add(P6.negate()).equals(ed.ExtendedPoint.ZERO) //true
P6.multiply(scalar7).equals(P42) // true
P7.add(P7).add(P7).equals(P21) // true
P42.subtract(P42).equals(P21) //true
```

The same operations could be carried out on `ed.Point`s too, but keep in mind that internally each operation
will convert an affine point to an extended point, so it is slightly more efficient to work directly with
extended points.

Extended points also offer another multiplication option that is _not_ constant time: `multiplyUnsafe`. This can be
used in situations where timing attacks are not a concern, for example in signature verification where all inputs are
public. Here we see it used in the last line of the signature verification function:

```typescript
// If sig is valid, we're in the torsion subgroup. Multiply by 8 will give zero.
return RPh.subtract(Gs).multiplyUnsafe(toBigInt(8)).equals(ExtendedPointClass.ZERO)
```

### Ristretto

Many cryptographic protocols require use of a prime order group. Ed25519 is not prime order, but it does have a prime order subgroup
of index 8. There are ad hoc ways to force points into this subgroup, such as multiplying points by 8, but these mangle points
and require new security proofs. Other curves with prime order groups have slower arithmetic operations. We want both the speed of
Ed25519 and the security of a prime order group.

[Ristretto](https://ristretto.group) gives us us this by working in the quotient group of our cofactor-8 curve modulo its torsion
subgroup: E/E[8]. For Ed25519 is a prime order group whose elements are cosets of the torsion subgroup E[8]. Done naively this approach
would produce large encodings - each coset contains 8 Edwards points - and expensive equality tests. Ristretto avoids these problems
and provides compact encodings, efficient equality checks, and a censorship-resistant elligator based mapping from general bit strings
to Ristretto points. With implementations of Ristretto available in multiple programming languages, this also gives a programmer
easy interoperability with other systems, making it easy to use, say, Rust on a server and TypeScript on a client.

To use these with this library you can perform all arithmetic with ExtendedPoint objects (the map from the Edwards curve to the Ristretto group is a homomorphism). When using the curve in a protocol that requires a prime order group, use the functions:

- `extendedPoint.toRistrettoBytes(): Uint8Array` to produce the canonical encoding of a Ristretto point. _(Our Edwards point is mapped to a Ristretto point and then encoded.)_
- `ed.ExtendedPoint.fromRistrettoBytes(bytes: Uint8Array): ExtendedPointBase<BIT>` to compute an Edwards point representative of an encoded Ristretto point.
- `ed.ExtendedPoint.fromRistrettoHash(bytes: Uint8Array): ExtendedPointBase<BIT>` to map an arbitrary 64-byte array to Edwards point representative of an encoded Ristretto point using the censorship-resistant Elligator mapping.
- `extendedPoint.ristrettoEquals(other: ExtendedPointBase<BIT>): boolean` to check whether two Edwards points represent the same Ristretto point.

For example:

```typescript
// Hash a string to encode it as an extended point with elligator
const h = sha512('hyvä hyvä')
const point = ed.ExtendedPoint.fromRistrettoHash(h)
const encoded = point.toRistrettoBytes() // Uint8Array

// we could now send `encoded` over the wire to a server as part of a protocol, etc...
const decoded = ed.ExtendedPoint.fromRistrettoBytes(encoded)

point.equals(decoded) // MAYBE false!
point.ristrettoEquals(decoded) // ALWAYS true

expect(encoded).toEqual(decoded.toRistrettoBytes()) // Always true
```

### Other Protocols: An OPRF

As mentioned above, we can use this implementation of Ristretto255 directly in cryptographic protocols that require a prime
order group. As an example, here we implement an Oblivious Pseudorandom Function [OPRF] protocol as described in
[Burns, et al.](https://eprint.iacr.org/2017/111.pdf) replacing their hash-to-point function with the Ristretto/Elligator hash.

#### Client prepares a message

```typescript
function prepareOPRFClientMessage(oprfInput: Uint8Array, bSecret: Uint8Array): Uint8Array {
  const A = ed.ExtendedPoint.fromRistrettoHash(oprfInput)
  const B = A.multiply(ed.keyUtils.encodePrivate(bSecret))
  return B.toRistrettoBytes()
}

const bSecret = ed.utils.randomPrivateKey()
const rawMessage = 'my secret OPRF input'
const hashed = sha512(rawMessage)
const maskedInput = prepareOPRFClientMessage(hashed, bSecret)

storeSecretInSession(bSecret) // We will need this to unmask server response
sendMessageToServer(maskedInput)
```

#### Server applies function to masked input

```typescript
function prepareServerOPRFMessage(clientOPRFMessage: Uint8Array, serverOPRFKey: Uint8Array): Uint8Array {
  const B = ed.ExtendedPoint.fromRistrettoBytes(clientOPRFMessage)
  const k = ed.keyUtils.encodePrivate(serverOPRFKey)
  const C = B.multiply(k)
  return C.toRistrettoBytes()
}

const serverOPRFMessage = prepareServerOPRFMessage(clientOPRFMessage, serverOPRFKey)
sendMEssageToClient(serverOPRFMEssage)
```

#### Client unmasks the response

```typescript
// Retrieve bSecret for session
function receiveServerMessage(cBytes: Uint8Array, bSecret: Uint8Array): Uint8Array {
  const C = ed.ExtendedPoint.fromRistrettoBytes(cBytes)
  const b = ed.keyUtils.encodePrivate(bSecret)
  const bInv = ed.math.invert(b, ed.CURVE.n)
  const D = C.multiply(bInv)
  return D.toRistrettoBytes()
}

const oprfOutput = receiveServerMessage(serverOPRFMessage, bSecret)
// Now remove algebraic content before using the bits
const outputForUsage = sha256(oprfOutput)
```

## Performance Comparison with `noble-ed25519`

Running the benchmarks on a MacBook Pro with 2.7 GHz Intel i7 we see that using `pr-ed25519` with JSBI for
integer arithmetic is 5-10 times slower than using the `noble-ed25519` implementation with native `bigint`.
However using `pr-ed25519` with
[our native BigInt wrapper](https://github.com/privacyresearchgroup/pr-ed25519/blob/main/src/native-bigint.ts)
yields results much closer to `noble-ed25519`. In some areas, particularly in verification, `pr-ed25519` still
significantly underperforms `noble-ed25519`, so we see that the cost of abstracting the integer implementation
is real and `noble-ed25519` should be preferred for environments where the native javascript `bbigint` is
available and acceptable.

`noble-ed25519` benchmarks:

```
Benchmarking
Initialized: 63ms
RAM: rss=34.2mb heap=13.7mb used=7.3mb ext=1.0mb

getPublicKey 1 bit x 2,962 ops/sec @ 337μs/op
getPublicKey(utils.randomPrivateKey()) x 3,113 ops/sec @ 321μs/op
sign x 1,464 ops/sec @ 682μs/op
verify x 316 ops/sec @ 3ms/op
verifyBatch x 394 ops/sec @ 2ms/op
Point.fromHex decompression x 5,452 ops/sec @ 183μs/op
ristretto255#fromHash x 2,790 ops/sec @ 358μs/op
ristretto255 round x 1,332 ops/sec @ 750μs/op
RAM: rss=56.9mb heap=25.2mb used=12.2mb ext=1.4mb arr=0.3mb
```

`pr-ed25519` with JSBI benchmarks:

```
Benchmarking
Initialized: 346ms
RAM: rss=52.1mb heap=25.2mb used=15.5mb ext=1.0mb

getPublicKey 1 bit x 793 ops/sec @ 1ms/op
getPublicKey(utils.randomPrivateKey()) x 825 ops/sec @ 1ms/op
sign x 350 ops/sec @ 2ms/op
verify x 32 ops/sec @ 30ms/op
verifyBatch x 39 ops/sec @ 25ms/op
Point.fromHex decompression x 836 ops/sec @ 1ms/op
ristretto255#fromHash x 374 ops/sec @ 2ms/op
ristretto255 round x 210 ops/sec @ 4ms/op
RAM: rss=81.1mb heap=44.6mb used=12.8mb ext=1.4mb arr=0.3mb
```

`pr-ed25519` with native `BigInt`:

```
Benchmarking
Initialized: 78ms
RAM: rss=36.4mb heap=13.7mb used=6.3mb ext=1.0mb

getPublicKey 1 bit x 2,944 ops/sec @ 339μs/op
getPublicKey(utils.randomPrivateKey()) x 3,137 ops/sec @ 318μs/op
sign x 1,446 ops/sec @ 691μs/op
verify x 210 ops/sec @ 4ms/op
verifyBatch x 216 ops/sec @ 4ms/op
Point.fromHex decompression x 4,933 ops/sec @ 202μs/op
ristretto255#fromHash x 2,478 ops/sec @ 403μs/op
ristretto255 round x 1,179 ops/sec @ 847μs/op
RAM: rss=59.0mb heap=26.0mb used=12.6mb ext=1.4mb arr=0.3mb
```

<!-- ## API

In what follows, most functions will be parameterized by the type of integers we are using. We will refer to our
integer type parameter as `BIT` - Big Integer Type - and will require it to implement the interface [`BigIntType`]().
These integer objects are manipulated by a class `Ints` which implements [`Integers<BIT>`](). The terms `BIT` and `Ints` will be used below without further comment.

- [`getPublicKey(privateKey)`](#getpublickeyprivatekey)
- [`sign(hash, privateKey)`](#signhash-privatekey)
- [`verify(signature, hash, publicKey)`](#verifysignature-hash-publickey)
- [Helpers & Point](#helpers--point)

The API is largely unchanged from `noble-ed25519`, and the description below is reproduced from there with small changes.

##### `getPublicKey(privateKey)`

```typescript
function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>
function getPublicKey(privateKey: string): Promise<string>
function getPublicKey<BIT extends BigIntType>(privateKey: BIT): Promise<Uint8Array>
```

- `privateKey: Uint8Array | string | BIT` will be used to generate public key.
  Public key is generated by executing scalar multiplication of a base Point(x, y) by a fixed
  integer. The result is another `Point(x, y)` which we will by default encode to hex Uint8Array.
- Returns:

  - `Promise<Uint8Array>` if `Uint8Array` was passed
  - `Promise<string>` if hex `string` was passed
  - Uses **promises**, because ed25519 uses SHA internally; and we're using built-in browser `window.crypto`, which returns `Promise`.

- Use `Point.fromPrivateKey(privateKey)` if you want `Point` instance instead
- Use `Point.fromHex(publicKey)` if you want to convert hex / bytes into Point.
  It will use decompression algorithm 5.1.3 of RFC 8032.

##### `sign(hash, privateKey)`

```typescript
function sign(hash: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>
function sign(hash: string, privateKey: string): Promise<string>
```

- `hash: Uint8Array | string` - message hash which would be signed
- `privateKey: Uint8Array | string` - private key which will sign the hash
- Returns EdDSA signature. You can consume it with `Signature.fromHex()` method:
  - `Signature.fromHex(ed25519.sign(hash, privateKey))`

##### `verify(signature, hash, publicKey)`

```typescript
function verify(
  signature: Uint8Array | string | Signature,
  hash: Uint8Array | string,
  publicKey: Uint8Array | string | Point
): Promise<boolean>
```

- `signature: Uint8Array | string | Signature` - returned by the `sign` function
- `hash: Uint8Array | string` - message hash that needs to be verified
- `publicKey: Uint8Array | string | Point` - e.g. that was generated from `privateKey` by `getPublicKey`
- Returns `Promise<boolean>`: `Promise<true>` if `signature == hash`; otherwise `Promise<false>`

##### Ristretto255

To use Ristretto, simply use `fromRistrettoHash()` and `toRistrettoBytes()` methods.

```typescript
// The hash-to-group operation applies Elligator twice and adds the results.
ExtendedPoint.fromRistrettoHash(hash: Uint8Array): ExtendedPoint;

// Decode a byte-string s_bytes representing a compressed Ristretto point into extended coordinates.
ExtendedPoint.fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint;

// Encode a Ristretto point represented by the point (X:Y:Z:T) in extended coordinates to Uint8Array.
ExtendedPoint.toRistrettoBytes(): Uint8Array
```

It extends Mike Hamburg's Decaf approach to cofactor elimination to support cofactor-8 curves such as Curve25519.

In particular, this allows an existing Curve25519 library to implement a prime-order group with only a thin abstraction layer, and makes it possible for systems using Ed25519 signatures to be safely extended with zero-knowledge protocols, with no additional cryptographic assumptions and minimal code changes.

##### Helpers & Point

`utils.randomPrivateKey()`

Returns cryptographically random `Uint8Array` that could be used as Private Key.

`utils.precompute(W = 8, point = Point.BASE)`

Returns cached point which you can use to `#multiply` by it.

This is done by default, no need to run it unless you want to
disable precomputation or change window size.

We're doing scalar multiplication (used in getPublicKey etc) with
precomputed BASE_POINT values.

This slows down first getPublicKey() by milliseconds (see Speed section),
but allows to speed-up subsequent getPublicKey() calls up to 20x.

You may want to precompute values for your own point.

`utils.TORSION_SUBGROUP`

The 8-torsion subgroup ℰ8. Those are "buggy" points, if you multiply them by 8, you'll receive Point.ZERO.

Useful to check implementations for signature malleability. See [the link](https://moderncrypto.org/mail-archive/curves/2017/000866.html)

`Point#toX25519`

You can use the method to use ed25519 keys for curve25519 encryption.

https://blog.filippo.io/using-ed25519-keys-for-encryption

```typescript
ed25519.CURVE.P // 2 ** 255 - 19
ed25519.CURVE.n // 2 ** 252 - 27742317777372353535851937790883648493
ed25519.Point.BASE // new ed25519.Point(Gx, Gy) where
// Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n
// Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;


// Elliptic curve point in Affine (x, y) coordinates.
ed25519.Point {
  constructor(x: bigint, y: bigint);
  static fromY(y: bigint);
  static fromHex(hash: string);
  static fromPrivateKey(privateKey: string | Uint8Array);
  toX25519(): bigint; // Converts to Curve25519
  toRawBytes(): Uint8Array;
  toHex(): string; // Compact representation of a Point
  equals(other: Point): boolean;
  negate(): Point;
  add(other: Point): Point;
  subtract(other: Point): Point;
  multiply(scalar: bigint): Point;
}
// Elliptic curve point in Extended (x, y, z, t) coordinates.
ed25519.ExtendedPoint {
  constructor(x: bigint, y: bigint, z: bigint, t: bigint);
  static fromAffine(point: Point): ExtendedPoint;
  static fromRistrettoHash(hash: Uint8Array): ExtendedPoint;
  static fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint;
  toRistrettoBytes(): Uint8Array;
  toAffine(): Point;
}
ed25519.Signature {
  constructor(r: bigint, s: bigint);
  toHex(): string;
}

// Precomputation helper
utils.precompute(W, point);
``` -->

## License

(c) 2021 Privacy Research, LLC [(https://privacyresearch.io)](https://privacyresearch.io), see LICENSE file.
Portions (c) 2019 Paul Miller (https://paulmillr.com)
