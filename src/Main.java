/**
 * Test class of RSA
 */
public class Main {
    public static void main(String[] args) {
        // we have three people
        RSA alice = new RSA();
        RSA bob   = new RSA();
        RSA eve   = new RSA();

        // alice wants to send this message to bob
        String messageFromAliceToBob = "The quick brown fox jump over the lazy dog. af;sfliij;aeoirlfj;eraoilskgdgnlaurkj;gshnlaeriugkajnsdlkgjahfhneilufukwejfilukj";//"Ya like jazz?";

        // alice then uses bob's public key to encrypt the message
        String encryptedMessage = RSA.encryptMessage(messageFromAliceToBob, bob.publicKey);

        // this is what alice sent to bob
        System.out.printf("Original message Alice sent to Bob: %s\n", messageFromAliceToBob);

        // this is what alice sent to bob
        System.out.printf("Encrypted message Alice sent to Bob: %s\n", encryptedMessage);

        // when bob decodes, he gets this message
        System.out.printf("Message Bob gets: %s\n", bob.decryptMessage(encryptedMessage));

        // when eve tries to eavesdrop/intercept the message, she gets this message
        System.out.printf("Message Eve gets: %s\n", eve.decryptMessage(encryptedMessage));

        // if eve really wanted to successfully decrypt the message,
        // she would need to find bob's private key (n, d),
        // and remember, de ≡ 1 (mod phi(n)) => d ≡ e^(-1) (mod phi(n))
        // and phi(n) = phi(p*q) = phi(p) * phi(q) = (p-1) * (q-1),
        // but finding the prime factorization of a large number takes way too long!!!

        // Also, note that the primes are deemed "probably prime",
        // so they might not be prime, in which case RSA would fail.
        // You should do a quick check: decrypt(encrypt(message)) == message,
        // do this before confirming p and q.
    }
}
