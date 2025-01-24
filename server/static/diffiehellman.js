class DiffieHellman {
    constructor() {
        this.keyPair = sjcl.ecc.elGamal.generateKeys(256);
    }

    generateKeys() {
        this.publicKey = sjcl.codec.hex.fromBits(this.keyPair.pub.get());
    }

    getPublicKey() {
        return this.publicKey;
    }

    computeSecret(serverPublicKeyHex) {
        const serverPublicKeyBits = sjcl.codec.hex.toBits(serverPublicKeyHex);
        const sharedSecret = this.keyPair.sec.deriveKey(serverPublicKeyBits);
        return sjcl.codec.hex.fromBits(sharedSecret);
    }
}
