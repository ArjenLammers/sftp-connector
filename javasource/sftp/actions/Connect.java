// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package sftp.actions;

import java.util.Base64;
import java.util.Properties;
import org.apache.commons.io.IOUtils;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.MendixLogger;
import sftp.impl.SFTP;
import sftp.proxies.Key;
import sftp.proxies.microflows.Microflows;

/**
 * Sets up a session to an SFTP server and executes a microflow.
 * Within the microflow actions on the SFTP can be performed.
 * If the microflow is finished, the connection to the SFTP will be disconnected.
 */
public class Connect extends CustomJavaAction<IMendixObject>
{
	private IMendixObject __configuration;
	private sftp.proxies.Configuration configuration;
	private java.lang.Boolean enableDebugging;
	private java.lang.String microflow;
	private IMendixObject microflowArgument;
	private java.lang.String microflowResult;

	public Connect(IContext context, IMendixObject configuration, java.lang.Boolean enableDebugging, java.lang.String microflow, IMendixObject microflowArgument, java.lang.String microflowResult)
	{
		super(context);
		this.__configuration = configuration;
		this.enableDebugging = enableDebugging;
		this.microflow = microflow;
		this.microflowArgument = microflowArgument;
		this.microflowResult = microflowResult;
	}

	@Override
	public IMendixObject executeAction() throws Exception
	{
		this.configuration = __configuration == null ? null : sftp.proxies.Configuration.initialize(getContext(), __configuration);

		// BEGIN USER CODE
		ILogNode logger = SFTP.getLogger();
		IMendixObject result = null;
		
		JSch jsch = new JSch();
		Session session = null;
		ChannelSftp channel = null;
		
		try {
			if (this.enableDebugging) {
				JSch.setLogger(new MendixLogger());
			}
			
			Properties config = new Properties();
			// this avoids trying different methods like kerberos and causing timeouts
			config.put("PreferredAuthentications", "publickey,password");
			
			if (!configuration.getStrictHostkeyChecking()) {
				config.put("StrictHostKeyChecking", "no");
			} else {
				config.put("StrictHostKeyChecking", "yes");
				
				HostKey hostKey = new HostKey(configuration.getHostname(), Base64.getDecoder().decode(configuration.getHostKey()));
				jsch.getHostKeyRepository().add(hostKey, null);
			}
						
			if (configuration.getUseKey()) {
				Key key = null;
				if (configuration.getUseGeneralKey()) {
					key = Microflows.dS_GetGeneralKey(getContext());
					if (key == null)
						throw new CoreException("No general key found.");
				} else {
					key = configuration.getConfiguration_Key();
					if (key == null)
						throw new CoreException("No connection specific key found.");
					
				}

				String decryptedPassphrase =
						encryption.proxies.microflows.Microflows.decrypt(getContext(), key.getPassPhrase());
				jsch.addIdentity(configuration.getUsername(), IOUtils.toByteArray(Core.getFileDocumentContent(getContext(), key.getMendixObject())), 
						null, decryptedPassphrase.getBytes());
			}
			
			session = jsch.getSession(configuration.getUsername(), configuration.getHostname(), 
					configuration.getPort());
			
			if (configuration.getPassword() != null && !"".equals(configuration.getPassword())) {
				String decryptedPassword =
						encryption.proxies.microflows.Microflows.decrypt(getContext(), configuration.getPassword());
				if (decryptedPassword != null && !"".equals(decryptedPassword)) {
					session.setPassword(decryptedPassword);
				}
			}

			session.setConfig(config);
			session.connect(configuration.getConnectTimeout());
			
			Channel c = session.openChannel("sftp");
			c.connect();
			channel = (ChannelSftp) c;
			
			SFTP.setChannel(getContext(), channel);
			SFTP.setJSch(getContext(), jsch);
			
			result = Core.execute(getContext(), this.microflow, this.microflowArgument);
			
		} catch (Exception e) {
			logger.error("An error ocurred while using SFTP: " + e.toString(), e);
			throw e;
		} finally {
			if (session != null) {
				try {
					session.disconnect();
				} catch (Exception e) {
					logger.error("Unable to disconnect session: " + e.toString(), e);
				}
			}
			SFTP.removeContextObjects(getContext());
		}
		
		return result;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public java.lang.String toString()
	{
		return "Connect";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
