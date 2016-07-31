const util = require('./util')
const keccak = require('keccakjs')
const rlp = require('rlp')
const Message = require('./Message')

function Envelope(ttl, topics, data){
  ttl = ttl || util.TTL
  topcis = topics || []

  this.expiry = util.now().plus(ttl)
  this.ttl = ttl
  this.topics = topics
  this.data = data
  this.nonce = 0
}

Envelope.prototype.seal = function seal(pow){

  return

  const self = this
  const d = new Buffer(64)
  d.copy(this.rlpWithoutNonce())

  const finish = util.now().add(pow)
  let bestBit = 0

  const nonceBuffer = new Buffer(4)

  for (nonce = 0; nonce < 1024; nonce++) {
    nonceBuffer.writeUInt8(nonce % 256, Math.floor(nonce / 256))
    d.copy(nonceBuffer, 60)

    const hash = util.sha3(d)
    const firstBit = util.firstBit(hash)

    if (firstBit > bestBit) {
      self.nonce = nonceBuffer
      bestBit = firstBit
    }
    nonce++
  }

}

Envelope.prototype.rlpWithoutNonce = function rlpWithoutNonce(){
  return rlp.encode(this.expiry.toNumber(), this.ttl.toNumber(), this.topics, this.data)
}

Envelope.prototype.open = function open(privateKey){

  const payloadOffset = this.data[0] === 0 ? 1 : util.SIGNATURE_LEGNTH + 1
  const payload = new Buffer(this.data.length - payloadOffset)
  this.data.copy(payload, 0, payloadOffset)

  const Message = require('./Message')
  const message = new Message(payload, {
    flags: this.data[0],
  })

  if (message.flags === util.SIGNATURE_FLAG) {
    message.signature = data.splice(0, util.SIGNATURE_LEGNTH)
  }

  message.decrypt(privateKey)

  return message

}

Envelope.prototype.hash = function hash(){
  
  if (this.hash)
    return this.hash

  const encoded = rlp.EncodeToBytes(this)
  this.hash = util.sha3(encoded)

}

Envelope.prototype.decodeRlp = function decodeRlp(rlpStream) {
  const raw = rlpStream.raw()
  rlp.decodeBytes(raw)
  this.hash = keccak(raw)
}

module.exports = Envelope