const crypto = require('crypto')
const util = require('./util')
const secp256k1 = require('secp256k1')


function Keypair(privateKey){
  this.privateKey = privateKey
  this.publicKey = util.privateKeyToPublicKey(privateKey)

  while(!secp256k1.publicKeyVerify(this.publicKey)){
    this.publicKey = util.privateKeyToPublicKey(privateKey)
  }

}

Keypair.generate = function generate(){
  while(true){
    const privateKey = crypto.randomBytes(32)
    if(secp256k1.privateKeyVerify(privateKey))
      return new Keypair(privateKey)
  }
}

module.exports = Keypair