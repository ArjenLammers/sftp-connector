// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package sftp.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import net.schmizz.sshj.sftp.StatefulSFTPClient;
import sftp.impl.SFTP;

/**
 * Renames or moves a file or directory on the SFTP server.
 */
public class Rename extends CustomJavaAction<java.lang.Boolean>
{
	private java.lang.String from;
	private java.lang.String to;

	public Rename(IContext context, java.lang.String from, java.lang.String to)
	{
		super(context);
		this.from = from;
		this.to = to;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		// BEGIN USER CODE
		StatefulSFTPClient client = SFTP.getClient(getContext());
		client.rename(from, to);
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
		return "Rename";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
