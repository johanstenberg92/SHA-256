package org.johanstenberg.sha256;

import java.io.*;
import java.util.StringTokenizer;

/**
 * Modified Kattio boilerplate code.
 *
 * @author Kattis & Johan Stenberg
 */
final public class Kattio extends PrintWriter {

    public Kattio(InputStream i) {
        super(new BufferedOutputStream(System.out));
        r = new BufferedReader(new InputStreamReader(i));
    }

    public Kattio(InputStream i, OutputStream o) {
        super(new BufferedOutputStream(o));
        r = new BufferedReader(new InputStreamReader(i));
    }

    public boolean hasMoreTokens() {
        return peekToken() != null;
    }

    public boolean hasMoreLineTokens() throws Throwable {
        if (line == null) {
            line = r.readLine();
        }

        return line != null;
    }

    public String getLine() throws Throwable {
        if (line != null) {
            String tmp = line;
            line = r.readLine();
            return tmp;
        }

        return null;
    }

    public int getInt() {
        return Integer.parseInt(nextToken());
    }

    public double getDouble() {
        return Double.parseDouble(nextToken());
    }

    public long getLong() {
        return Long.parseLong(nextToken());
    }

    public String getWord() {
        return nextToken();
    }


    private BufferedReader r;
    private String line;
    private StringTokenizer st;
    private String token;

    private String peekToken() {
        if (token == null)
            try {
                while (st == null || !st.hasMoreTokens()) {
                    line = r.readLine();
                    if (line == null) return null;
                    st = new StringTokenizer(line);
                }
                token = st.nextToken();
            } catch (IOException e) {
            }
        return token;
    }

    private String nextToken() {
        String ans = peekToken();
        token = null;
        return ans;
    }

}
