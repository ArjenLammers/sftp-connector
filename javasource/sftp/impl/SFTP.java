package sftp.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.common.Factory.Named.Util;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.sftp.StatefulSFTPClient;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import net.schmizz.sshj.userauth.method.AuthMethod;
import net.schmizz.sshj.userauth.method.AuthPassword;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.Resource;
import sftp.proxies.Configuration;
import sftp.proxies.Format;
import sftp.proxies.Key;
import sftp.proxies.KeyType;
import sftp.proxies.NewKeyType;
import sftp.proxies.microflows.Microflows;

public class SFTP {
	public static final String CONTEXT_CLIENT = "SFTPCLIENT";
	
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
	
	public static void generateKeyContents(IContext context, Key key, NewKeyType type) throws CoreException {
		KeyPair kp;
		KeyPairGenerator kpg = null;
		try {
			String decryptedPass = encryption.proxies.microflows.Microflows.decrypt(
					context, key.getPassPhrase());
			Ed25519PrivateKeyParameters privateKey = null;
			
			switch (type) {
			case DSA:
				kpg = KeyPairGenerator.getInstance("DSA");
				kpg.initialize(2048);
				break;
			case RSA:
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(4096);
				break;
			case ECDSA:
				kpg = SecurityUtils.getKeyPairGenerator("ECDSA");
				ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
				kpg.initialize(spec);
				break;
			case Ed25519:
				Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
				gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
				AsymmetricCipherKeyPair asymmetricCipherKeyPair = gen.generateKeyPair();
		        privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
				break;
			default:
				throw new CoreException("No new key type given!");
			}
			
			PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
					.setProvider(SecurityUtils.getSecurityProvider())
					.build(decryptedPass.toCharArray());
			
			StringWriter sw = new StringWriter();
		    JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
			
			switch (type) {
			case Ed25519:
				byte[] content = OpenSSHPrivateKeyUtil.encodePrivateKey(
						privateKey);
				PemObject o = new PemObject("OPENSSH PRIVATE KEY", content);
				pemWriter.writeObject(o, encryptor);
				key.setFormat(Format.OpenSSHv1);
				break;
			default:
				key.setFormat(Format.PKCS8);
				kp = kpg.generateKeyPair();
			}

			pemWriter.flush();
			pemWriter.close();

			Core.storeFileDocumentContent(context, key.getMendixObject(), new ByteArrayInputStream(sw.toString().getBytes()));
			key.setName("private_key.pem");
			
			validateKey(context, key);
		} catch (Exception e) {
			throw new CoreException(e);
		}
	}
	
	public static SSHClient connect(IContext context, Configuration configuration) throws Exception {
		SSHClient ssh = new SSHClient();
		
		try {
			
			ssh.addHostKeyVerifier(new InMemoryHostkeyVerifier(configuration.getHostKey(), 
					configuration.getHostKeyFingerprint()));
			ssh.setConnectTimeout(configuration.getConnectTimeout());		
		
			List<AuthMethod> authMethods = new LinkedList<>();
			
			if (configuration.getPassword() != null && !"".equals(configuration.getPassword())) {
				String decryptedPassword =
						encryption.proxies.microflows.Microflows.decrypt(context, configuration.getPassword());
				if (decryptedPassword != null && !"".equals(decryptedPassword)) {
					authMethods.add(new AuthPassword(
							new PresuppliedPasswordFinder(decryptedPassword)));
				}
			}
			
			if (configuration.getUseKey()) {
				Key key = null;
				if (configuration.getUseGeneralKey()) {
					key = Microflows.dS_GetGeneralKey(context);
					if (key == null)
						throw new CoreException("No general key found.");
				} else {
					key = configuration.getConfiguration_Key();
					if (key == null)
						throw new CoreException("No connection specific key found.");
				}
			
				KeyFormat format = KeyFormat.valueOf(key.getFormat().name());
				FileKeyProvider fkp = (FileKeyProvider) Util.create((new DefaultConfig()).getFileKeyProviderFactories(),
						format.toString()); 
				if (fkp == null) {
					throw new CoreException("No provider available for " + format + " key file");
				}
				
				String passPhrase = key.getPassPhrase();
				if (passPhrase != null) {
					passPhrase = encryption.proxies.microflows.Microflows.decrypt(context, passPhrase);
				}
				
				InputStreamReader isr = new InputStreamReader(Core.getFileDocumentContent(context, 
						key.getMendixObject()));
				if (passPhrase != null) {
					fkp.init(isr, PasswordUtils.createOneOff(passPhrase.toCharArray()));
				} else {
					fkp.init(isr);
				}
				
				authMethods.add(new AuthPublickey(fkp));
			}
			
			ssh.connect(configuration.getHostname(), configuration.getPort());
			ssh.auth(configuration.getUsername(), authMethods);
			return ssh;
		} catch (Exception e) {
			SFTP.getLogger().error("An error ocurred while using SFTP: " + e.toString(), e);
			throw e;
		}
	}
		
	static class PresuppliedPasswordFinder implements PasswordFinder {

		private String password;
		
		public PresuppliedPasswordFinder(String password) {
			this.password = password;
		}
		
		@Override
		public char[] reqPassword(Resource<?> resource) {
			return this.password.toCharArray();
		}

		@Override
		public boolean shouldRetry(Resource<?> resource) {
			return false;
		}
	}
	
	private static class InMemoryHostkeyVerifier implements HostKeyVerifier {

		private String hostkey = null, hostkeyFingerprint = null;
		
		public InMemoryHostkeyVerifier(String hostkey, String hostkeyFingerprint) {
			this.hostkey = hostkey;
			this.hostkeyFingerprint = hostkeyFingerprint;
		}
		
		@Override
		public boolean verify(String host, int port, PublicKey pubKey) {
			String fingerPrint = SecurityUtils.getFingerprint(pubKey);
			if (!fingerPrint.equals(this.hostkeyFingerprint)) {
				LOGGER.error("Fingerprint of host " + host + "(" + fingerPrint + ") does not match " + 
						this.hostkeyFingerprint);
				return false;
			}
			String key = Base64.encodeBase64String(pubKey.getEncoded());
			if (!key.equals(this.hostkey)) {
				LOGGER.error("Public key of host " + host + " does not match.");
				return false;
			}
			return true;
		}
		
	}
			
}
