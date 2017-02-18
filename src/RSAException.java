/**
 * Exceptions for RSA class.
 */
public class RSAException extends Exception {
    /**
     * Default constructor
     */
    public RSAException() {}

    /**
     * Constructor with provided error message
     * @param message error message
     */
    public RSAException(String message) {
        super(message);
    }
}
