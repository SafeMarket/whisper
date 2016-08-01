const Keypair = require('../lib/Keypair')
const Message = require('../lib/Message')
const util = require('../lib/util')
const chai = require('chai')
const expect = chai.expect
chai.use(require('chai-bignumber')())
chai.use(require('chai-as-promised'))
chai.should()

const helloWorldBuffer = new Buffer("hello world")

describe('Message', () => {

  describe('unsigned, unencrypted message', () => {

    let message, envelope

    it('should instatiate', () => {
      message = new Message(new Buffer("hello world"))
    })

    it('should wrap', () => {
      return message.wrap().then((_envelope) => {
        envelope = _envelope
      }).should.eventually.be.fulfilled
    })

    it('should have flags of 0', () => {
      expect(message.flags).to.equal(0)
    })

    it('should have correct no signatue', () => {
      expect(message.signature).to.be.undefned
    })

    it('should have correct payload', () => {
      expect(message.payload).to.deep.equal(helloWorldBuffer)
    })

    it('should have correct TTL', () => {
      expect(envelope.ttl).to.be.bignumber.equal(util.TTL)
    })

  })

  describe('signed, unencrypted message', () => {

    let keypair, message, envelope

    it('should generate key', () => {
      keypair = Keypair.generate()
    })

    it('should create a new message', () => {
      message = new Message(helloWorldBuffer)
    })

    it('should wrap message', () => {
      return message.wrap(util.POW, { from: keypair }).then((_envelope) => {
        envelope = _envelope
      }).should.eventually.be.fulfilled
    })

    it('should have correct signature flag', () => {
      expect(message.flags).to.equal(util.SIGNATURE_FLAG)
    })

     it('should have signatue', () => {
      expect(message.signature).to.not.be.undefned
    })


    it('should have correct payload', () => {
      expect(message.payload).to.deep.equal(helloWorldBuffer)
    })

    it('should have correct TTL', () => {
      expect(envelope.ttl).to.be.bignumber.equal(util.TTL)
    })


    it('should recover public key', () => {
      expect(keypair.publicKey).to.deep.equal(message.recover())
    })
    
  })

  describe('unsigned, encrypted message', () => {

    let keypair, message, envelope, openedMessage

    it('should generate key', () => {
      keypair = Keypair.generate()
    })

    it('should create a new message', () => {
      message = new Message(helloWorldBuffer)
    })

    it('should wrap message', () => {
      return message.wrap(util.POW, { to: keypair.publicKey }).then((_envelope) => {
        envelope = _envelope
      }).should.eventually.be.fulfilled
    })

    it('should have correct signature flag', () => {
      expect(message.flags).to.equal(0)
    })

    it('should have undefined signature', () => {
      expect(message.signature).to.be.undefined
    })

    it('should open message', () => {
      openedMessage = envelope.open(keypair)
    })

    it('should have correct payload', () => {
      expect(openedMessage.payload).to.deep.equal(helloWorldBuffer)
    })

  })

  describe('signed, encrypted message', () => {

    let keypairFrom, keypairTo, message, envelope, openedMessage

    it('should generate keys', () => {
      keypairFrom = Keypair.generate()
      keypairTo = Keypair.generate()
    })

    it('should create a new message', () => {
      message = new Message(helloWorldBuffer)
    })

    it('should wrap message', () => {
      return message.wrap(util.POW, { to: keypairTo.publicKey, from: keypairFrom }).then((_envelope) => {
        envelope = _envelope
      }).should.eventually.be.fulfilled
    })

    it('should have correct signature flag', () => {
      expect(message.flags).to.equal(util.SIGNATURE_FLAG)
    })

    it('should have signature', () => {
      expect(message.signature).to.not.be.undefined
    })

    it('should open message', () => {
      openedMessage = envelope.open(keypairTo)
    })

    it('should have correct payload', () => {
      expect(openedMessage.payload).to.deep.equal(helloWorldBuffer)
    })

  })

})
  