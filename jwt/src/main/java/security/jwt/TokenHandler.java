package security.jwt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.util.Assert;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TokenHandler {

	private static final String HMAC_ALGO = "HmacSHA256";
	private static final String SEPARATOR = ".";
	private static final String SEPARATOR_SPLITTER = "\\.";

	private final Mac hmac;

	private final ObjectMapper objectMapper = new ObjectMapper();

	public TokenHandler(String secret) {
		Assert.notNull(secret, "You must specify spring.security.jwt.secret property");
		try {
			byte[] secretKey = DatatypeConverter.parseBase64Binary(secret);
			hmac = Mac.getInstance(HMAC_ALGO);
			hmac.init(new SecretKeySpec(secretKey, HMAC_ALGO));
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException("failed to initialize HMAC: "
					+ e.getMessage(), e);
		}
	}

	public final JwtContent parseJwtContentFromToken(String token, Class<? extends JwtContent> clazz) {
		final String[] parts = token.split(SEPARATOR_SPLITTER);
		if (parts.length == 2 && parts[0].length() > 0 && parts[1].length() > 0) {
			try {
				final byte[] contentBytes = fromBase64(parts[0]);
				final byte[] hash = fromBase64(parts[1]);
				final byte[] hashedContentBytes = createHmac(contentBytes);
				boolean validHash = Arrays.equals(hashedContentBytes,
						hash);
				if (validHash) {
					final JwtContent content = fromJSON(contentBytes, clazz);
					if (new Date().getTime() < content.getExpires()) {
						return content;
					} else
						throw new JwtExpiresException();
				}
			} catch (IllegalArgumentException e) {
				throw new JwtWrongFormatException("Jwt was tempered", e);
			}
		}
		throw new JwtWrongFormatException();
	}

	public final String createTokenForJwtContent(JwtContent content) {
		byte[] contentBytes = toJSON(content);
		byte[] hash = createHmac(contentBytes);
		final StringBuilder sb = new StringBuilder(170);
		sb.append(toBase64(contentBytes));
		sb.append(SEPARATOR);
		sb.append(toBase64(hash));
		return sb.toString();
	}

	private JwtContent fromJSON(final byte[] contentBytes,Class<? extends JwtContent> clazz) {
		try {
			return objectMapper.readValue(
					new ByteArrayInputStream(contentBytes), clazz);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private byte[] toJSON(JwtContent content) {
		try {
			return objectMapper.writeValueAsBytes(content);
		} catch (JsonProcessingException e) {
			throw new IllegalStateException(e);
		}
	}

	private String toBase64(byte[] content) {
		return DatatypeConverter.printBase64Binary(content);
	}

	private byte[] fromBase64(String content) {
		return DatatypeConverter.parseBase64Binary(content);
	}

	private synchronized byte[] createHmac(byte[] content) {
		return hmac.doFinal(content);
	}
}
