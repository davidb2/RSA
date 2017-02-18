import java.math.BigInteger;

/**
 * Stores a private Key
 */
public class PrivateKey {
    public final BigInteger n, d;

    /**
     * Constructor for Private Key
     * @param n n
     * @param d d
     */
    public PrivateKey(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof PrivateKey) {
            PrivateKey other = (PrivateKey) obj;
            return this.n.equals(other.n) && this.d.equals(other.d);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return (this.n.hashCode() + "" + this.d.hashCode()).hashCode();
    }
}