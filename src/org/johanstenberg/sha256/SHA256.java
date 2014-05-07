package org.johanstenberg.sha256;

import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.InputStream;

/**
 * SHA-256 hash function, reads hex-encoded input from STDIN or a file and prints
 * the resulting hash to STDOUT.
 * <p/>
 * Implementation details taken from: <a href="http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf">here</a>
 *
 * @author Johan Stenberg
 */
final public class SHA256 {

    /**
     * Read-from-file flag, used for testing purposes. If false,
     * reads from STDIN.
     */
    private static boolean READ_FROM_FILE = true;

    /**
     * File name flag, used when testing.
     */
    private static String FILE_NAME = "test.txt";

    /**
     * Main method of the program. Reads the input from
     * file or STDIN and hashes it, and later prints it to STDOUT.
     *
     * @param args Not used.
     * @throws Throwable Only used if missing file.
     */
    public static void main(String[] args) throws Throwable {
        Kattio io;
        if (READ_FROM_FILE) {
            InputStream fileInputStream = new FileInputStream(FILE_NAME);
            io = new Kattio(fileInputStream, System.out);
        } else {
            io = new Kattio(System.in, System.out);
        }

        SHA256Digest sha256Digest = SHA256Digest.getInstance();

        while (io.hasMoreLineTokens()) {
            String s = io.getLine();
            byte[] data = DatatypeConverter.parseHexBinary(s);

            byte[] hash = sha256Digest.digest(data);
            System.out.println(DatatypeConverter.printHexBinary(hash));
        }


        io.close();
    }
}
