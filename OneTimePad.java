import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/** XOR pad demonstration; displayed keys are disposable teaching values. */
public class OneTimePad {
    private static final SecureRandom RANDOM = new SecureRandom();
    public static byte[] generateKey(int length) {
        if (length < 0) throw new IllegalArgumentException("Negative key length");
        byte[] key = new byte[length];
        RANDOM.nextBytes(key);
        return key;
    }
    public static byte[] xor(byte[] message, byte[] key) {
        if (message == null || key == null || message.length != key.length)
            throw new IllegalArgumentException("Message and key lengths must match");
        byte[] output = new byte[message.length];
        for (int i = 0; i < message.length; i++)
            output[i] = (byte) (message[i] ^ key[i]);
        return output;
    }
    private static void require(boolean condition, String test) {
        if (!condition) throw new AssertionError(test);
    }
    public static void main(String[] args) {
        byte[] plaintext = "MY NAME IS UNKNOWN".getBytes(StandardCharsets.UTF_8);
        byte[] key = generateKey(plaintext.length);
        byte[] ciphertext = xor(plaintext, key);
        byte[] recovered = xor(ciphertext, key);
        System.out.println("Plaintext : " + new String(plaintext, StandardCharsets.UTF_8));
        System.out.println("Byte count: " + plaintext.length);
        System.out.println("Demo key  : " + HexFormat.of().formatHex(key));
        System.out.println("Ciphertext: " + HexFormat.of().formatHex(ciphertext));
        System.out.println("Recovered : " + new String(recovered, StandardCharsets.UTF_8));
        require(Arrays.equals(plaintext, recovered), "Required plaintext round trip");
        System.out.println("PASS required plaintext round trip");
        require(xor(new byte[]{0x4d}, new byte[]{0x2a})[0] == 0x67, "Known vector");
        System.out.println("PASS known XOR vector 4d XOR 2a = 67");
        boolean rejected = false;
        try { xor(new byte[2], new byte[1]); }
        catch (IllegalArgumentException expected) { rejected = true; }
        require(rejected, "Unequal lengths");
        System.out.println("PASS unequal key length rejected");
        require(xor(new byte[0], new byte[0]).length == 0, "Empty input");
        System.out.println("PASS empty input");
        for (int n = 0; n < 1000; n++) {
            byte[] message = generateKey(n % 257);
            byte[] pad = generateKey(message.length);
            require(Arrays.equals(message, xor(xor(message, pad), pad)), "Round trip " + n);
        }
        System.out.println("PASS 1000 varied binary round trips");
        byte[] all = new byte[256];
        for (int i = 0; i < all.length; i++) all[i] = (byte) i;
        byte[] pad = generateKey(all.length);
        require(Arrays.equals(all, xor(xor(all, pad), pad)), "All byte values");
        System.out.println("PASS all 256 byte values");
        System.out.println("TOTAL: 6 checks passed");
    }
}
