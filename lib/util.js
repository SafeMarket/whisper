const BigNumber = require('bignumber.js')
const secp256k1 = require('secp256k1')
const crypto = require('crypto')
const SHA3 = require('keccakjs')
const ECIES = require('./ecies')

const MILLISECOND = new BigNumber(1)
const SECOND = new BigNumber(1000)
const STATUS_CODE = 0x00
const MESSAGES_CODE = 0x01
const PROTOCOL_VERSION = 0x02
const PROTOCOL_NAME = 'shh'
const SIGNATURE_FLAG = 128
const SIGNATURE_LENGTH = 65
const EXPIRATION_CYCLE = MILLISECOND.times(800)
const TRANSMISSION_CYCLE = MILLISECOND.times(300)
const TTL = SECOND.times(50)
const POW = SECOND.times(50)

function now(){
  return new BigNumber((new Date).getTime())
}

function toBuffer(){

  const args = argumentsToArray(arguments)
  let length = 0
  
  args.forEach((arg) => {

    if(Number.isInteger(arg))
      length += 1
    else if (arg instanceof BigNumber)
      length += 1
    else if (arg instanceof Buffer)
      length += arg.length
    else if (arg === null)
      'do nothing'
    else
      throw new Error('util.toBuffer: Invalid type')
    
  })

  const buffer = new Buffer(length)
  let bufferIndex = 0

  args.forEach((arg) => {

    if(Number.isInteger(arg)) {
      buffer[bufferIndex] = arg
      bufferIndex ++
    }else if (arg instanceof BigNumber){
      buffer[bufferIndex] += BigNumber.toNumber()
      bufferIndex ++
    }else if (arg instanceof Buffer){
      for(let i = 0; i < arg.length; i++){
        buffer[bufferIndex + i] = arg[i]
      }
      bufferIndex += arg.length
    }
    
  })

  return buffer
}

function bufferToArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
}

function argumentsToArray(args){
  return [].slice.call(args)
}

function sign(hash, keypair){

  if(hash.length !== 32)
    throw new Error('Expected hash to be exactly 32 bytes')

  if(keypair.privateKey.length !== 32)
    throw new Error('Expected private key to be exactly 32 bytes')

  const signature = secp256k1.sign(hash, keypair.privateKey)

  signature.r = signature.signature.slice(0, 32)
  signature.s = signature.signature.slice(32, 64)
  signature.v = signature.recovery + 27

  if(!verify(hash, signature, keypair.publicKey))
    throw new Error('Signature failed to verify');

  return signature
}

function verify(message, signature, publicKey){
  return secp256k1.verify(message, signature.signature, publicKey)
}

function sha3(bytes, length){
  bytes = toBuffer(bytes)
  if (!length) length = 256

  var h = new SHA3(length)
  if (bytes) {
    h.update(bytes)
  }
  return new Buffer(h.digest('hex'), 'hex')
}

function firstBit(buffer){
  for (var i = 0; i < buffer.length; i++) {
    if (buffer[i] > 0) {
      return i
    }
  }
  return buffer.length
}

function recover(hash, signature){
  return secp256k1.recover(hash, signature.signature, signature.recovery)
}

function privateKeyToPublicKey(privateKey){
  return secp256k1.publicKeyCreate(privateKey)
}

function zeroBuffer(length){
  return (new Buffer(length)).fill(0)
}

function encrypt(message, publicKey){
  const ephemeralKeypair = require('./Keypair').generate()
  const ecies = new ECIES(ephemeralKeypair.privateKey, ephemeralKeypair.publicKey, publicKey)
  return ecies.encryptMessage(crypto.randomBytes(32), message)
}

function decrypt(ciphertext, keypair){
  const ecies = new ECIES(keypair.privateKey, keypair.publicKey)
  return ecies.decryptMessage(ciphertext)
}

module.exports = {
  MILLISECOND,
  SECOND,
  STATUS_CODE,
  MESSAGES_CODE,
  PROTOCOL_VERSION,
  PROTOCOL_NAME,
  SIGNATURE_FLAG,
  SIGNATURE_LENGTH,
  EXPIRATION_CYCLE,
  TRANSMISSION_CYCLE,
  TTL,
  POW,
  now,
  toBuffer,
  argumentsToArray,
  sha3,
  sign,
  firstBit,
  recover,
  privateKeyToPublicKey,
  zeroBuffer,
  verify,
  encrypt,
  decrypt
}