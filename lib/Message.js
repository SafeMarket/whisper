const util = require('./util')
const keccak = require('keccakjs')
const Q = require('q')

function Message(payload, options){
  this.flags = 0
  this.payload = payload
}

Message.prototype.wrap = function wrap(pow, options){

  const Envelope = require('./Envelope')
  const deferred = Q.defer()

  pow = pow || util.POW
  options = options || {}

  if (options.from)
    this.sign(options.from)

  if (options.to) {
    this.encrypt(options.to)
    const envelope = new Envelope(options.ttl, options.topics, this.bytes())
    envelope.seal(pow)
    deferred.resolve(envelope)
  } else {
    const envelope = new Envelope(this.ttl, this.topics, this.bytes())
    envelope.seal(pow)
    deferred.resolve(envelope)
  }
  return deferred.promise
}

Message.prototype.sign = function sign(keypair){
  this.flags = util.SIGNATURE_FLAG
  this.signature = util.sign(this.hash(), keypair)
}

Message.prototype.recover = function recover(){
  return util.recover(this.hash(), this.signature)
}

Message.prototype.encrypt = function encrypt(publicKey){
  this.payload = util.encrypt(this.payload, publicKey)
}

Message.prototype.decrypt = function decrypt(keypair){
  this.payload = util.decrypt(this.payload, keypair)
}

Message.prototype.hash = function hash(){
  return util.sha3(util.toBuffer(this.flags, this.payload))
}

Message.prototype.bytes = function bytes(){
  return util.toBuffer(this.flags, this.signature ? this.signature.signature : null, this.payload)
}

module.exports = Message