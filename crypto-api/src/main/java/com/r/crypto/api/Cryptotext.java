package com.r.crypto.api;

import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.exception.RCryptoException;
import com.r.crypto.util.Util;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.r.crypto.api.CryptoAlgorithm.CRYPTO_ALGORITHM_REGEXP;
import static com.r.crypto.util.RCryptoEncoders.DECODER;
import static com.r.crypto.util.RCryptoEncoders.ENCODER;
import static com.r.crypto.util.Util.quote;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Represents a cryptographic result, including algorithm, parameters, and ciphertext.
 */
public class Cryptotext implements Serializable {
    private static final long serialVersionUID = -1L;

    public static final String CRYPTOTEXT_HEADER_REGEX = "\\A"
            + "(\\{(?<cryptoTag>crypto)(:(?<version>\\w+))?})?"
            + "(\\{" + CRYPTO_ALGORITHM_REGEXP
            + "(?::(?<options>[^:]+))?"
            + "})";

    private static final Pattern CRYPTO_TEXT_PATTERN = Pattern.compile(
            CRYPTOTEXT_HEADER_REGEX + "?"
                    + "(?<data>[-\\w\\d_]*)"
                    + "\\z"
    );

    private CryptoAlgorithm algorithm;
    private final Map<String, String> options = new TreeMap<>();
    private byte[] data;

    public Cryptotext() {
    }

    public Cryptotext(String algorithmSpec) {
        this.algorithm = CryptoAlgorithm.parse(algorithmSpec);
    }

    public Cryptotext(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Cryptotext(String algorithm, byte[] data) {
        this.algorithm = CryptoAlgorithm.parse(algorithm);
        this.data = data;
    }

    public Cryptotext(CryptoAlgorithm algorithm, byte[] data) {
        this.algorithm = algorithm;
        this.data = data;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public Map<String, String> getOptions() {
        return options;
    }

    public String getOption(String name) {
        return options.get(name);
    }

    public KmsKey getKey() {
        return KmsKey.parse(options.get("key"));
    }

    public void setKey(KmsKey key) {
        setOption("key", key == null ? null : key.toString());
    }

    public String getTenant() {
        return options.get("tenant");
    }

    public void setTenant(String tenant) {
        setOption("tenant", tenant);
    }

    public void setOption(String name, String value) {
        if (value == null) {
            options.remove(name);
        } else {
            options.put(name, value);
        }
    }

    public void setOptions(Map<String, String> options) {
        this.options.clear();
        this.options.putAll(options);
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public String encode() {
        if (data == null) {
            return null;
        }

        return mutableHeader().append(ENCODER.encodeToString(data)).toString();
    }

    public String header() {
        return mutableHeader().toString();
    }

    public StringBuilder mutableHeader() {
        StringBuilder b = new StringBuilder("{").append(algorithm.encode());

        if (!options.isEmpty()) {
            b.append(":");
            options.forEach((key, value) -> b.append(key).append("=").append(value).append(","));
            b.setCharAt(b.length() - 1, '}');
        } else {
            b.append("}");
        }

        return b;
    }

    public byte[] encodeRaw() {
        if (data == null) {
            return null;
        }

        return Util.concat(header().getBytes(UTF_8), data);
    }

    public byte[][] split(int... sizes) {
        return Util.split(data, sizes);
    }

    public static Cryptotext parse(byte[] data) {
        if (data == null) {
            return null;
        }

        if (data[0] != '{') {
            throw new RCryptoException("cryptotext invalid encoded data");
        }

        int headerEnd = -1;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == '}') {
                headerEnd = i;
                break;
            }
        }
        if (headerEnd == -1 || headerEnd == data.length - 1) {
            throw new RCryptoException("cryptotext invalid encoded data");
        }

        String header = new String(data, 0, headerEnd + 1, UTF_8);
        String encodedData = ENCODER.encodeToString(Arrays.copyOfRange(data, headerEnd + 1, data.length));
        return parse(header + encodedData);
    }

    public static Cryptotext parse(CharSequence header, byte[] data) {
        if (header == null && data == null) {
            return null;
        }

        if (header == null) {
            throw new RCryptoException("cannot parse null header");
        }

        Cryptotext cryptotext = parseInternal(header);
        if (cryptotext == null) {
            throw new RCryptoException("invalid cryptotext header: " + quote(header));
        }

        if (cryptotext.data != null) {
            // Header is a full Cryptotext string, e.g. "{aes}abcd", which is
            // invalid since data is already second argument to this method.
            throw new RCryptoException("header already has base64 data: " + quote(header));
        }

        cryptotext.setData(data);
        return cryptotext;
    }

    public static Cryptotext parse(CharSequence s) {
        Cryptotext cryptotext = parseInternal(s);
        return cryptotext == null || cryptotext.data == null ? null : cryptotext;
    }

    public static Cryptotext copy(Cryptotext cryptotext) {
        if (cryptotext == null) {
            return null;
        }

        Cryptotext copy = new Cryptotext(new CryptoAlgorithm(cryptotext.getAlgorithm()));
        copy.options.putAll(cryptotext.options);
        copy.data = cryptotext.data;
        return copy;
    }

    private static Cryptotext parseInternal(CharSequence s) {
        if (s == null) {
            return null;
        }

        Matcher matcher = CRYPTO_TEXT_PATTERN.matcher(s);
        if (!matcher.matches()) {
            throw new RCryptoException("invalid cryptotext");
        }

        String algorithmName = matcher.group("algorithmName");
        String parameters = matcher.group("parameters");
        String options = matcher.group("options");
        byte[] data = "".equals(matcher.group("data")) ? null : DECODER.decode(matcher.group("data"));

        if (algorithmName == null) {
            return parse(data);
        }

        Cryptotext cryptotext = new Cryptotext(new CryptoAlgorithm(
                algorithmName,
                parameters == null ? null : Arrays.asList(parameters.split(","))
        ));

        if (options != null) {
            for (String pair : options.split(",")) {
                String[] parts = pair.split("=");
                cryptotext.setOption(parts[0], parts[1]);
            }
        }

        if (data != null) {
            cryptotext.setData(data);
        }

        return cryptotext;
    }

    // CHECKSTYLE:OFF
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Cryptotext that = (Cryptotext) o;
        return algorithm.equals(that.algorithm) && options.equals(that.options) && Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, options, Arrays.hashCode(data));
    }

    public String toSimpleString() {
        return Util.toSimpleString(this) + header() + "#" + Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return Util.toSimpleString(this) + encode();
    }
}
