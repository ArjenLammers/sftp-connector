// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package myfirstmodule.actions;

import java.net.InetSocketAddress;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder.Forward;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import sftp.impl.SFTP;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class RemotePortForwarding extends CustomJavaAction<java.lang.Boolean>
{
	private IMendixObject __configuration;
	private sftp.proxies.Configuration configuration;
	private java.lang.Long forward;
	private java.lang.String forwardingAddress;
	private java.lang.Long forwardingPort;

	public RemotePortForwarding(IContext context, IMendixObject configuration, java.lang.Long forward, java.lang.String forwardingAddress, java.lang.Long forwardingPort)
	{
		super(context);
		this.__configuration = configuration;
		this.forward = forward;
		this.forwardingAddress = forwardingAddress;
		this.forwardingPort = forwardingPort;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.configuration = this.__configuration == null ? null : sftp.proxies.Configuration.initialize(getContext(), __configuration);

		// BEGIN USER CODE
		SSHClient ssh = SFTP.connect(getContext(), configuration);
		try {
			ssh.getRemotePortForwarder().bind(
					new Forward(forward.intValue()),
					new SocketForwardingConnectListener(
							new InetSocketAddress(forwardingAddress, forwardingPort.intValue())));
			ssh.getConnection().getKeepAlive().setKeepAliveInterval(10);
			ssh.getTransport().join();
		} finally {
			ssh.disconnect();
			ssh.close();
		}
		return true;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "RemotePortForwarding";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
