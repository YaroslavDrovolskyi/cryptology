package ua.drovolskyi.cryptology.test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/*
    Алгоритм DSA - це алгоритм для створення та перевірки цифрового підпису
    Для алгоритму потрібні такі параметри:
        - хеш-функція H(x). В якості неї взято функцію SHA-1
        - q - це велике просте число, розмірність якого в бітах дорівнює розмірності виходу хеш-функції H(x)
        - p - це просте число, для якого (p-1)/q - ціле число.
        - g = h^((p-1)/q) mod p, де h - довільне число, g != 1

    Також для створення підпису потрібні:
        - секретний ключ x - це випадкове число з інтервалу (0, q)
        - відкритий ключ y = g^x mod p

    Параметри домену (p, q, g) є публічними
    Відкритий ключ y є публічним
    Секретний ключ x відомий тільки тому, хто підписував повідомлення

    Створення підпису відбувається за допомогою методу sign(),
    а перевірка підпису - за допомогою методу checkSignature()

    Алгоритми створення та перевірки підпису наведені в коментарях до відповідних методів


    To sign message, you should:
     - provide parameters of domain (p, q, g), public key y, private key x
        (or you can generate them all by calling .generateDomainParametersAndKeys())
     - provide message

     To check signature, you should:
      - provide parameters of domain (p, q, g), public key y
      - provide message
 */
public class DsaAlgorithm {
    private int L = 1024; // length of p in bits
    private int N = 160;  // length of q in bits

    private BigInteger x; // private key, random number in interval (0, q)
    private BigInteger y; // public key, y = g^x mod p

    // Parameters of domain (not secret)
    private BigInteger p; // prime number, length is L bits, (p-1)/q must be integer
    private BigInteger q; // prime number, length is N bits
    private BigInteger g; // group generator // 1 < g < p


    private long seed; // seed used for generation of domain parameters
    private int counter; // used for generation parameters

    private BigInteger k; // generated for signing message

    private final MessageDigest hash; // hash function. Must SHA-1 with output 160 bits

    public DsaAlgorithm() throws NoSuchAlgorithmException {
        this.hash = MessageDigest.getInstance("SHA-1");
    }


    /*
        Algorithm (lecture 9, p. 13):
        - parameters of domain (p, q, g) must be already set (or generated)
        - private and public keys must be already set (or generated)
        - hash function H() is SHA-1
        - generate random number k from interval (0, q)
        - calculate r = (g^k mod p) mod q
        - calculate s = (k^(-1) * (H(message) + x*r)) mod q
        - if r=0 or s=0, generate new k
        - else (r, s) - it is signature
     */
    public byte[][] sign(byte[] message) {
        if (p == null || q == null || g == null) {
            throw new RuntimeException("Parameters of domain are not set");
        }
        if (x == null || y == null) {
            throw new RuntimeException("Keys are not set");
        }

        do {
            generateK();
        } while (! k.gcd(q).equals(BigInteger.ONE));
        BigInteger kInverse = k.modInverse(q);
        BigInteger r = g.modPow(k, p).mod(q);
        BigInteger messageHash = new BigInteger(1, hash.digest(message));
        BigInteger s = kInverse.multiply(messageHash.add(x.multiply(r))).mod(q);

        return new byte[][] { r.toByteArray(), s.toByteArray() };


    }

    private void generateK() {
        BigInteger c;
        long t = seed;
        do {
            c = new BigInteger(N, new Random(t));
            t = new Random(t).nextInt();
        } while (c.compareTo(q.subtract(BigInteger.TWO)) > 0);
        k = c.add(BigInteger.ONE);
    }

    /*
        Algorithm (lecture 9, p. 14):
        - parameters of domain (p, q, g) must be already set
        - public key must be already set
        - hash function H() is SHA-1
        - calculate w = s^(-1) mod q
        - calculate u = (H(message) * w) mod q
        - calculate z = (r*w) mod q
        - calculate v = ((g^u * y^z) mod p) mod q
        - if v == r then signature is correct, otherwise - signature is incorrect
     */
    public boolean checkSignature(byte[] message, byte[][] signature) {
        if (p == null || q == null || g == null) {
            throw new RuntimeException("Parameters of domain are not set");
        }
        if (y == null) {
            throw new RuntimeException("Public key is not set");
        }

        BigInteger r = new BigInteger(1, signature[0]);
        BigInteger s = new BigInteger(1, signature[1]);
        if (r.compareTo(q) >= 0 || s.compareTo(q) >= 0) {
            return false;
        }

        if(!s.gcd(q).equals(BigInteger.ONE)){
            return false;
        }
        BigInteger w = s.modInverse(q);
        BigInteger messageHash = new BigInteger(1, hash.digest(message));
        BigInteger u = messageHash.multiply(w).mod(q);
        BigInteger z = r.multiply(w).mod(q);
        BigInteger v = g.modPow(u, p).multiply(y.modPow(z, p)).mod(p).mod(q);

        return v.equals(r);
    }

    /**
     * Generates q, p, g, x, y according to rules of DSA algorithm
     */
    public void generateDomainParametersAndKeys() {
        int n = (int) (Math.ceil((double) L / N) - 1);
        int b = L - 1 - (n * N);

        // Generate seed
        seed = new Random().nextInt();

        // Calculate q
        // q = 2^(N-1) + U + 1 - (U mod 2)
        BigInteger qMin = BigInteger.TWO.pow(N - 1);
        BigInteger U = new BigInteger(1, hash.digest(longToByteArray(seed))).mod(qMin);
        q = qMin.add(U).add(BigInteger.ONE).subtract(U.mod(BigInteger.TWO));

        int offset = 1;
        for (counter = 0; counter < 4*L; ++counter) {
            BigInteger[] V = new BigInteger[n + 1];
            for (int j = 0; j <= n; ++j) {
                // V_j = hash((seed + offset + j) mod 2^32
                V[j] = new BigInteger(1, hash.digest(new BigInteger(longToByteArray(seed + offset + j))
                        .mod(BigInteger.TWO.pow(32))
                        .toByteArray()
                ));
            }

            // W = V_0 + (V_1 * 2^N) + ... + (V_(n-1) * 2^((n-1) * N)) + ((V_n mod 2^b) * 2^(n * N))
            BigInteger W = new BigInteger(1, V[0].toByteArray());
            for (int i = 1; i < n; ++i) {
                W = W.add(V[i].multiply(BigInteger.TWO.pow(i * N)));
            }
            W = W.add(V[n].mod(BigInteger.TWO.pow(b)).multiply(BigInteger.TWO.pow(n * N)));

            BigInteger X = W.add(BigInteger.TWO.pow(L - 1));
            BigInteger c = X.mod(BigInteger.TWO.multiply(q));

            // Calculate p
            p = X.subtract(c.subtract(BigInteger.ONE));

            if (isPrime(p, 4)) {
                break;
            }

            offset += n + 1;
        }

        // Calculate h and g
        BigInteger e = new BigInteger(1, p.subtract(BigInteger.ONE).toByteArray()).divide(q);
        do {
            // h needs to be in range [1, (p - 1)]. We can ensure this by setting the length in bits to be 2 less than
            // the length of p and adding one to the result of random generation.
            BigInteger h = new BigInteger(L - 2, new Random(seed)).add(BigInteger.ONE);
            g = h.modPow(e, p);
        } while ( g.compareTo(BigInteger.ONE) == 0);


        BigInteger c;
        long tmp = seed;
        do {
            c = new BigInteger(N, new Random(tmp));
            tmp = new Random(tmp).nextInt();
        } while (c.compareTo(q.subtract(BigInteger.TWO)) > 0);
        x = c.add(BigInteger.ONE);
        y = g.modPow(x, p);
    }

    public void setDomainParameters(byte[] pBytes, byte[] qBytes, byte[] gBytes) {
        BigInteger p = new BigInteger(1, pBytes);
        BigInteger q = new BigInteger(1, qBytes);
        BigInteger g = new BigInteger(1, gBytes);

        if (!isPrime(p, 4)) {
            throw new RuntimeException("p must be prime");
        }
        if (!p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
            throw new RuntimeException("(p-1)/q must be integer number");
        }
        if (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p) >= 0) {
            throw new RuntimeException("g must be in interval (1, p)");
        }

        this.p = p;
        this.q = q;
        this.g = g;
        this.seed = 0;
        this.counter = 0;
    }

    public void setKeys(byte[] y, byte[] x) {
        if (p == null || q == null || g == null) {
            throw new RuntimeException("Firstly set domain parameters");
        }
        BigInteger yBig = new BigInteger(1, y);
        BigInteger xBig = new BigInteger(1, x);
        if (!yBig.equals(g.modPow(xBig, p))) { // check if y == (g^x) mod p
            throw new RuntimeException("Incorrect keys: y=(g^x) mod p is not true");
        }
        this.y = yBig;
        this.x = xBig;
    }

    public void setPublicKey(byte[] y){
        this.y = new BigInteger(1, y);
    }

    public byte[] getP() {
        if(p != null){
            return removeLeadingZeroByte(p.toByteArray());
        }
        return null;
    }

    public byte[] getQ() {
        if(q != null){
            return removeLeadingZeroByte(q.toByteArray());
        }
        return null;
    }

    public byte[] getG() {
        if(g != null){
            return removeLeadingZeroByte(g.toByteArray());
        }
        return null;
    }

    public byte[] getX() {
        if(x != null){
            return removeLeadingZeroByte(x.toByteArray());
        }
        return null;
    }

    public byte[] getY() {
        if(y != null){
            return removeLeadingZeroByte(y.toByteArray());
        }
        return null;
    }

    private static byte[] removeLeadingZeroByte(byte[] bytes) {
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        return bytes;
    }

    // Check if given number is prime.
    // It is Miller-Rabin primality test
    public static boolean isPrime(BigInteger number, int certainty) {
        if (number.compareTo(BigInteger.ONE) <= 0 || number.compareTo(BigInteger.TWO.add(BigInteger.TWO)) == 0) {
            return false;
        }
        if (number.compareTo(BigInteger.TWO.add(BigInteger.ONE)) <= 0) {
            return true;
        }

        BigInteger d = number.subtract(BigInteger.ONE);

        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.shiftRight(1); // divide d by 2
        }

        for (int i = 0; i < certainty; ++i) {
            if (!isPrimeImpl(number, d)) {
                return false;
            }
        }

        return true;
    }

    // auxiliary method for isPrime()
    private static boolean isPrimeImpl(BigInteger number, BigInteger odd) {
        // Choose a random number in interval [2, number-2]
        BigInteger a;
        do {
            a  = new BigInteger(number.bitLength(), new Random());
        } while (a.compareTo(BigInteger.TWO) < 0 || a.compareTo(number.subtract(BigInteger.TWO)) > 0);

        BigInteger x = a.modPow(odd, number);

        if (x.equals(BigInteger.ONE) || x.equals(number.subtract(BigInteger.ONE))) {
            return true;
        }

        while (!odd.equals(number.subtract(BigInteger.ONE))) {
            x = x.modPow(x, number);
            odd = odd.shiftLeft(1); // odd *= 2

            if (x.equals(BigInteger.ONE)) {
                return false;
            }
            if (x.equals(number.subtract(BigInteger.ONE))) {
                return true;
            }
        }

        return false;
    }

    private static byte[] longToByteArray(long value) {
        return new byte[] {
                (byte)(value >>> 56),
                (byte)(value >>> 48),
                (byte)(value >>> 40),
                (byte)(value >>> 32),
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

}
