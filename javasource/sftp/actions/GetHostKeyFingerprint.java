// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package sftp.actions;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.SFTP;

/**
 * Retrieves the HostKey fingerprint from the session.
 */
public class GetHostKeyFingerprint extends CustomJavaAction<java.lang.String>
{
	public GetHostKeyFingerprint(IContext context)
	{
		super(context);
	}

	@Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		ChannelSftp channel = SFTP.getChannel(getContext());
		HostKey hostKey = channel.getSession().getHostKey();
		return hostKey.getFingerPrint(new JSch());
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public java.lang.String toString()
	{
		return "GetHostKeyFingerprint";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
