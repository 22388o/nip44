import { should } from 'micro-should';
import { v2 } from './index.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
// @ts-ignore
import { default as vec } from './nip44.vectors.json' assert { type: 'json' };
import { schnorr } from '@noble/curves/secp256k1';
// @ts-ignore
import { strictEqual, throws } from 'node:assert';
const v2vec = vec.v2;

should('NIP44: valid.encrypt_decrypt', async () => {
  for (const v of v2vec.valid.encrypt_decrypt) {
    const pub2 = bytesToHex(schnorr.getPublicKey(v.sec2));
    const key = v2.utils.getConversationKey(v.sec1, pub2);
    strictEqual(bytesToHex(key), v.conversation_key);
    const ciphertext = v2.encrypt(v.plaintext, key, hexToBytes(v.nonce));
    strictEqual(ciphertext, v.ciphertext);
    const decrypted = v2.decrypt(ciphertext, key);
    strictEqual(decrypted, v.plaintext);
  }
});
should('NIP44: valid.get_conversation_key', async () => {
  for (const v of v2vec.valid.get_conversation_key) {
    const key = v2.utils.getConversationKey(v.sec1, v.pub2);
    strictEqual(bytesToHex(key), v.conversation_key);
  }
});
should('NIP44: valid.calc_padded_len', () => {
  for (const [len, shouldBePaddedTo] of v2vec.valid.calc_padded_len) {
    const actual = v2.utils.calcPaddedLen(len);
    strictEqual(actual, shouldBePaddedTo);
  }
});
should('NIP44: invalid.decrypt', async () => {
  for (const v of v2vec.invalid.decrypt) {
    throws(
      () => {
        v2.decrypt(v.ciphertext, hexToBytes(v.conversation_key));
      },
      { message: new RegExp(v.note) },
    );
  }
});
should('NIP44: invalid.get_conversation_key', async () => {
  for (const v of v2vec.invalid.get_conversation_key) {
    throws(() => v2.utils.getConversationKey(v.sec1, v.pub2), {
      message: /(Point is not on curve|Cannot find square root)/,
    });
  }
});
should.run();
