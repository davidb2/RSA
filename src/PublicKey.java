import java.math.BigInteger;

/**
 * Stores a public key
 */
public class PublicKey {
    public final BigInteger n, e;

    /**
     * Constructor for Public key
     * @param n n
     * @param e e
     */
    public PublicKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof PublicKey) {
            PublicKey other = (PublicKey) obj;
            return this.n.equals(other.n) && this.e.equals(other.e);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return (this.n.hashCode() + "" + this.e.hashCode()).hashCode();
    }
}
