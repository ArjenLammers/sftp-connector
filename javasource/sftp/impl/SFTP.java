package sftp.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.common.Factory.Named.Util;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.sftp.StatefulSFTPClient;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import sftp.proxies.Format;
import sftp.proxies.Key;
import sftp.proxies.KeyType;

public class SFTP {
	public static final String CONTEXT_CLIENT = "SFTPCLIENT";
	// public static final String CONTEXT_JSCH = "SFTP_JSCH";
	
	private final static ILogNode LOGGER = Core.getLogger("SFTP");
	
	public static ILogNode getLogger() {
		return LOGGER;
	}
	
	public static StatefulSFTPClient getClient(IContext context) throws CoreException {
		Object o = context.getData().get(CONTEXT_CLIENT);
		if (o == null || !(o instanceof StatefulSFTPClient)) 
			throw new CoreException("No SFTP client found, please connect first.");
		
		return (StatefulSFTPClient) o;
 	}

	public static void setClient(IContext context, StatefulSFTPClient client) {
		context.getData().put(CONTEXT_CLIENT, client);
	}
	
	public static void removeContextObjects(IContext context) {
		// context.getData().remove(CONTEXT_JSCH);
		context.getData().remove(CONTEXT_CLIENT);
	}
	
	public static void validateKey(IContext context, Key key) throws CoreException {
		if (!key.getHasContents()) {
			key.setValid(false);
			key.setValidationMessage("No key contents set.");
		}
		
		try {
			String passPhrase = key.getPassPhrase();
			if (passPhrase != null) {
				passPhrase = encryption.proxies.microflows.Microflows.decrypt(context, passPhrase);
			}
			
			KeyFormat format = null;
			
			try {
				if (key.getFormat() == null) {
					InputStreamReader isr = new InputStreamReader(Core.getFileDocumentContent(context, key.getMendixObject()));
					format = KeyProviderUtil.detectKeyFileFormat(isr, false);
					if (format != null) {
						key.setFormat(Format.valueOf(format.name()));
					}
				} else {
					format = KeyFormat.valueOf(key.getFormat().name());
				}
			} catch (IOException e) {
				throw new CoreException("No format given and an error occurred while detecting format: " + e.getMessage(), e);
			}
			
			FileKeyProvider fkp = (FileKeyProvider) Util.create((new DefaultConfig()).getFileKeyProviderFactories(),
					format.toString());
			if (fkp == null) {
				throw new CoreException("No provider available for " + format + " key file");
			}
			
			InputStreamReader isr = new InputStreamReader(Core.getFileDocumentContent(context, key.getMendixObject()));
			if (passPhrase != null) {
				fkp.init(isr, PasswordUtils.createOneOff(passPhrase.toCharArray()));
			} else {
				fkp.init(isr);
			}

			PublicKey pubKey = fkp.getPublic();
			net.schmizz.sshj.common.KeyType keyType = net.schmizz.sshj.common.KeyType.fromKey(pubKey);
			
			KeyType mxKeyType = KeyType.valueOf(keyType.name());
			key.setKeyType(mxKeyType);
			key.setFingerprint(SecurityUtils.getFingerprint(pubKey));
			
			String publicKey = keyType.toString() + " ";
			
			PlainBuffer buffer = new PlainBuffer();
			keyType.putPubKeyIntoBuffer(pubKey, buffer);
			byte[] data = new byte[buffer.wpos()];
			buffer.readRawBytes(data);
			publicKey += Base64.encodeBase64String(data);
		
			key.setPublicKey(publicKey);
			key.setValid(true);
			key.setValidationMessage(null);
			
		} catch (Exception e) {
			key.setFingerprint(null);
			key.setPublicKey(null);
			key.setValid(false);
			key.setValidationMessage(e.getMessage());
			
			LOGGER.error("Error while validating key: " + e.getMessage(), e);
		}
	}
	
	public static void generateKeyContents(IContext context, Key key) throws CoreException {
		KeyPair kp;
		KeyPairGenerator kpg;
		try {
			String decryptedPass = encryption.proxies.microflows.Microflows.decrypt(
					context, key.getPassPhrase());
			
			kpg = SecurityUtils.getKeyPairGenerator("ECDSA");
			ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
			kpg.initialize(spec);
			
			
			kp = kpg.generateKeyPair();
			PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
					.setProvider(SecurityUtils.getSecurityProvider())
					.build(decryptedPass.toCharArray());
			
			StringWriter sw = new StringWriter();
			JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
			
			/* pemWriter.writeObject(pkcs8Builder.build(new JcePKCSPBEOutputEncryptorBuilder(
					PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC).build(decryptedPass.toCharArray()))); */
			pemWriter.writeObject(kp.getPrivate(), encryptor);
			pemWriter.flush();
			// pemWriter.writeObject(kp.getPublic());
			
			/*
			JcaPKCS8Generator gen2 = new JcaPKCS8Generator(kp.getPrivate(), encryptor);  
		    PemObject obj2 = gen2.generate();  
			
			
			pemWriter.writeObject(kp.getPrivate(), encryptor);
			// pemWriter.writeObject(kp.getPublic(), encryptor);
			 */
			pemWriter.close();
			
			Core.storeFileDocumentContent(context, key.getMendixObject(), new ByteArrayInputStream(sw.toString().getBytes()));
			key.setFormat(Format.PKCS8);
			key.setName("private_key.pem");
			
			validateKey(context, key);
		} catch (Exception e) {
			throw new CoreException(e);
		}
		
	}
}
