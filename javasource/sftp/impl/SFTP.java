package sftp.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.apache.commons.io.IOUtils;
import org.apache.xerces.impl.dv.util.Base64;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;

import sftp.proxies.Key;

public class SFTP {
	public static final String CONTEXT_CHANNEL = "SFTP_CHANNEL";
	public static final String CONTEXT_JSCH = "SFTP_JSCH";
	
	public static ILogNode getLogger() {
		return Core.getLogger("SFTP");
	}
	
	public static ChannelSftp getChannel(IContext context) throws CoreException {
		Object o = context.getData().get(CONTEXT_CHANNEL);
		if (o == null || !(o instanceof ChannelSftp)) 
			throw new CoreException("No SFTP channel found, please connect to a session first.");
		
		return (ChannelSftp) o;
 	}
	
	public static void setChannel(IContext context, ChannelSftp channel) {
		context.getData().put(CONTEXT_CHANNEL, channel);
	}
	
	public static JSch getJSch(IContext context) throws CoreException {
		Object o = context.getData().get(CONTEXT_JSCH);
		if (o == null || !(o instanceof JSch)) 
			throw new CoreException("No SFTP channel found, please connect to a session first.");
		
		return (JSch) o;
 	}
	
	public static void setJSch(IContext context, JSch jsch) {
		context.getData().put(CONTEXT_JSCH, jsch);
	}
	
	public static void removeContextObjects(IContext context) {
		context.getData().remove(CONTEXT_JSCH);
		context.getData().remove(CONTEXT_CHANNEL);
	}
	
	public static void validateKey(IContext context, Key key) throws CoreException {
		if (!key.getHasContents()) {
			key.setValid(false);
			key.setValidationMessage("No key contents set.");
		}
		
		String passPhrase = key.getPassPhrase();
		if (passPhrase != null) {
			passPhrase = encryption.proxies.microflows.Microflows.decrypt(context, passPhrase);
		}
		
		try {
			JSch jsch = new JSch();

			KeyPair keypair = KeyPair.load(jsch, IOUtils.toByteArray(
				Core.getFileDocumentContent(context, key.getMendixObject())), null);
			if (!keypair.decrypt(passPhrase)) {
				throw new Exception("Unable to decrypt key, the passphrase probably doesn't match.");
			}
			
			key.setFingerprint(keypair.getFingerPrint());
			String publicKey = "";
			switch (keypair.getKeyType()) {
			case KeyPair.DSA:
				publicKey += "ssh-dsa ";
				break;
			case KeyPair.RSA:
				publicKey += "ssh-rsa ";
				break;
			}
			
			publicKey += Base64.encode(keypair.getPublicKeyBlob());
			publicKey += " " + keypair.getPublicKeyComment();
			
			key.setPublicKey(publicKey);
			key.setValid(true);
			key.setValidationMessage(null);
			
		} catch (Exception e) {
			key.setFingerprint(null);
			key.setPublicKey(null);
			key.setValid(false);
			key.setValidationMessage(e.getMessage());
		}
	}
	
	public static void generateKeyContents(IContext context, Key key) throws CoreException {
		JSch jsch = new JSch();
		KeyPair keyPair;
		try {
			keyPair = KeyPair.genKeyPair(jsch, KeyPair.DSA, 2048);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			String decryptedPass = encryption.proxies.microflows.Microflows.decrypt(
					context, key.getPassPhrase());
			
			keyPair.writePrivateKey(buffer, decryptedPass.getBytes());
			keyPair.writePublicKey(buffer, "");
			buffer.close();
			ByteArrayInputStream bis = new ByteArrayInputStream(buffer.toByteArray());
			key.setName("key.key");
			Core.storeFileDocumentContent(context, key.getMendixObject(), bis);
		} catch (Exception e) {
			SFTP.getLogger().error("Error while generating certificate: " + e.getMessage(), e);
			throw new CoreException(e);
		}
		
	}
}
