package com.r.crypto.api;

import com.r.crypto.exception.RCryptoException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoAlgorithm {
    public static final String ALGORITHM_CLASSES_REGEX = "(?<algorithmClass>"
            + Arrays.toString(AlgorithmClass.values()).toLowerCase().replaceAll("[\\[\\]]", "").replaceAll(", ", "|")
            + ")";
    public static final String CRYPTO_ALGORITHM_SPEC_REGEXP = "(?<algorithmName>[^\\[:]+)?(\\[(?<parameters>[^:]+)])?";
    public static final String CRYPTO_ALGORITHM_REGEXP = "(" + ALGORITHM_CLASSES_REGEX + ":)?" + CRYPTO_ALGORITHM_SPEC_REGEXP;
    public static final Pattern CRYPTO_ALGORITHM_PATTERN = Pattern.compile("\\A" + CRYPTO_ALGORITHM_REGEXP + "\\z");

    protected final String algorithmName;
    protected final List<String> parameters = new ArrayList<>();

    public CryptoAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithmName = algorithm.algorithmName;
        this.parameters.addAll(algorithm.parameters);
    }

    public CryptoAlgorithm(String algorithm) {
        this(parse(algorithm));
    }

    public CryptoAlgorithm(String algorithmName, Object... parameters) {
        this(algorithmName, Arrays.stream(parameters).map(String::valueOf).collect(Collectors.toList()));
    }

    public CryptoAlgorithm(String algorithmName, List<String> parameters) {
        this.algorithmName = Objects.requireNonNull(algorithmName).toLowerCase();
        if (parameters != null) {
            this.parameters.addAll(parameters);
        }
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public List<String> getParameters() {
        return parameters;
    }

    public void addParameter(String parameter) {
        parameters.add(parameter);
    }

    public void addParameter(int parameter) {
        parameters.add(String.valueOf(parameter));
    }

    public String getParameter(int i) {
        return parameters.get(i);
    }

    public boolean matches(String... algorithmSpecs) {
        return Arrays.stream(algorithmSpecs)
                .map(CryptoAlgorithm::parse)
                .filter(Objects::nonNull)
                .anyMatch(this::matches);
    }

    public boolean matches(CryptoAlgorithm... others) {
        for (CryptoAlgorithm other : others) {
            if (other == null
                    || other.getClass() != getClass()
                    || !algorithmName.equals(other.algorithmName)
                    || parameters.size() > other.parameters.size()) {
                return false;
            }

            for (int i = 0; i < parameters.size(); i++) {
                if (!parameters.get(i).equals(other.parameters.get(i))) {
                    return false;
                }
            }
        }

        return true;
    }

    public static CryptoAlgorithm parse(String s) {
        if (s == null) {
            return null;
        }

        Matcher matcher = CRYPTO_ALGORITHM_PATTERN.matcher(s);
        if (!matcher.matches()) {
            throw new RCryptoException("unable to parse algorithmSpec=\"" + s + "\"");
        }

        String algorithmName = matcher.group("algorithmName");
        List<String> parameters = matcher.group("parameters") == null ? null : Arrays.asList(matcher.group("parameters").split(","));

        return new CryptoAlgorithm(algorithmName, parameters);
    }

    public StringBuilder encode() {
        StringBuilder b = new StringBuilder(algorithmName);
        if (!parameters.isEmpty()) {
            b.append("[");
            parameters.forEach(param -> b.append(param).append(","));
            b.setCharAt(b.length() - 1, ']');
        }

        return b;
    }

    public byte[] encodeBytes() {
        return encode().toString().getBytes(UTF_8);
    }

    // CHECKSTYLE:OFF
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CryptoAlgorithm algorithm = (CryptoAlgorithm) o;
        return algorithmName.equals(algorithm.algorithmName) && parameters.equals(algorithm.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithmName, parameters);
    }

    @Override
    public String toString() {
        return encode().toString();
    }
}
