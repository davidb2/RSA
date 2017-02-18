import java.util.Base64;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A representation of an encrypted message.
 * https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29#Encryption
 */
public class RSA {
    private final static String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    private final static String NUMBERS = "0123456789";
    private final static String SYMBOLS = " ~`@#$%^&*()_-+=|\n\r\t\0{}[]\\\'\";:?/>.<,\b";
    private final static String TEST_STRING = ALPHABET + ALPHABET.toUpperCase() + NUMBERS + SYMBOLS;
    private final static int MIN_BIT_LENGTH = 100, MAX_BIT_LENGTH = 1000;
    private final static int CERTAINTY = 99;
    private final static int BASE = 64;
    private final BigInteger p, q, phi, d;
    private final PrivateKey privateKey;

    public final BigInteger n, e;
    public final PublicKey publicKey;

    /**
     * Default constructor for the RSA class.
     */
    public RSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p, q, n, phi, e, d;
        boolean isFine;
        do {
            int bitLength0 = random.nextInt(MAX_BIT_LENGTH - MIN_BIT_LENGTH + 1) + MIN_BIT_LENGTH;
            int bitLength1 = random.nextInt(MAX_BIT_LENGTH - MIN_BIT_LENGTH + 1) + MIN_BIT_LENGTH;

            // random primes
            p = BigInteger.probablePrime(bitLength0, random);
            q = BigInteger.probablePrime(bitLength1, random);

            // n = p * q
            n = p.multiply(q);

            // https://en.wikipedia.org/wiki/Euler%27s_totient_function
            // phi(n) = phi(p*q) = phi(p) * phi(q) = (p-1) * (q-1)
            phi = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));

            // 1 <= e <= phi(n) && gcd(phi(n), e) = 1. Further, we can just make e prime.
            e = BigInteger.probablePrime(iLog(phi) - 1, random);

            // d ≡ e^(-1) (mod phi(n)) => de ≡ 1 (mod phi(n))
            // you should definitely look at the wikipedia article of how to find the modular inverse
            d = e.modInverse(phi);

            // make sure it works
            try {
                RSA test = new RSA(p, q, e);
                isFine = test.decryptMessage(RSA.encryptMessage(TEST_STRING, test.publicKey)).equals(TEST_STRING);
            } catch (Exception exception) {
                isFine = false;
            }
        } while (p.equals(q) || !isFine);



        // assign member variables
        this.p = p;
        this.q = q;
        this.n = n;
        this.phi = phi;
        this.d = d;
        this.e = e;
        this.publicKey = new PublicKey(n, e);
        this.privateKey = new PrivateKey(n, d);
    }

    /**
     * Custom primes. BE CAREFUL AND MAKE SURE P AND Q ARE PRIME WITH GREAT CERTAINTY AND P != Q!!!
     * @param p a prime number
     * @param q different prime number
     */
    public RSA(BigInteger p, BigInteger q, BigInteger e) throws RSAException {
        if (p.equals(q)) {
            throw new RSAException("p must not equal q.");
        }
        if (!p.isProbablePrime(CERTAINTY) || !q.isProbablePrime(CERTAINTY)) {
            throw new RSAException("p or q need to have a higher probability of being prime.");
        }

        // n = p * q
        BigInteger n = p.multiply(q);

        // https://en.wikipedia.org/wiki/Euler%27s_totient_function
        // phi(n) = phi(p*q) = phi(p) * phi(q) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));


        if (!phi.gcd(e).equals(BigInteger.ONE)) {
            throw new RSAException("e must be coprime with phi(n).");
        }

        // d ≡ e^(-1) (mod phi(n)) => de ≡ 1 (mod phi(n))
        // you should definitely look at the wikipedia article of how to find the modular inverse
        BigInteger d = e.modInverse(phi);

        // assign member variables
        this.p = p;
        this.q = q;
        this.n = n;
        this.phi = phi;
        this.d = d;
        this.e = e;
        this.publicKey = new PublicKey(n, e);
        this.privateKey = new PrivateKey(n, d);
    }

    /**
     * Returns the encrypted message given the public key
     * @param message the message to encrypt
     * @param publicKey the public key
     * @return the encrypted message
     */
    public static String encryptMessage(String message, PublicKey publicKey) {
        // get each character's ascii representation
        byte[] encodedCharacters = message.getBytes();

        // turn the message into a number
        BigInteger encodedNumber = new BigInteger(encodedCharacters);

        // Compute m^e (mod n) where m is a number representation of the message.
        BigInteger encryptedNumber = encodedNumber.modPow(publicKey.e, publicKey.n);

        // Base 64 encode the encrypted message, so it will be represented with less characters
        String encryptedString = new String(Base64.getEncoder().encode(encryptedNumber.toByteArray()));

        return encryptedString;
    }

    /**
     *
     * @param message
     * @return
     */
    public String decryptMessage(String message) {
        // get the decimal representation of the encrypted message
        BigInteger encryptedNumber = new BigInteger(Base64.getDecoder().decode(message.getBytes()));

        // decrypt the message: c^d ≡ m (mod n), where m is the original message
        BigInteger decryptedNumber = encryptedNumber.modPow(privateKey.d, privateKey.n);

        // get each character's ascii value
        byte[] decodedCharacters = decryptedNumber.toByteArray();

        // byte array to String
        String decodedMessage = new String(decodedCharacters);

        return decodedMessage;
    }

    /**
     * Computes the integer logarithm of a BigInteger (base 2)
     * @param num number
     * @return floor of the number (integer)
     */
    private int iLog(BigInteger num) {
        return (int) (num.toString().length() / Math.log(2));

    }
}
