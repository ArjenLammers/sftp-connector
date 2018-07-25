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
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.SFTP;

/**
 * Returns the current working directory.
 */
public class Pwd extends CustomJavaAction<java.lang.String>
{
	public Pwd(IContext context)
	{
		super(context);
	}

	@Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		ChannelSftp channel = SFTP.getChannel(getContext());
		return channel.pwd();
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public java.lang.String toString()
	{
		return "Pwd";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
