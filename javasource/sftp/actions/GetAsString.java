// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package sftp.actions;

import java.io.InputStream;
import org.apache.commons.io.IOUtils;
import com.jcraft.jsch.ChannelSftp;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.SFTP;

/**
 * Retrieve a file from the SFTP server and store its contents within a string.
 */
public class GetAsString extends CustomJavaAction<java.lang.String>
{
	private java.lang.String remoteFile;

	public GetAsString(IContext context, java.lang.String remoteFile)
	{
		super(context);
		this.remoteFile = remoteFile;
	}

	@Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		ChannelSftp channel = SFTP.getChannel(getContext());
		InputStream is = channel.get(remoteFile);
		return IOUtils.toString(is, "UTF-8");
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public java.lang.String toString()
	{
		return "GetAsString";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
