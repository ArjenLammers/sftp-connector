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
import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.SFTP;
import com.mendix.systemwideinterfaces.core.IMendixObject;

/**
 * Creates and uploads a file on a SFTP server coming from a Mendix FileDocument.
 */
public class Put extends CustomJavaAction<java.lang.Boolean>
{
	private java.lang.String destination;
	private IMendixObject __file;
	private system.proxies.FileDocument file;

	public Put(IContext context, java.lang.String destination, IMendixObject file)
	{
		super(context);
		this.destination = destination;
		this.__file = file;
	}

	@Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.file = __file == null ? null : system.proxies.FileDocument.initialize(getContext(), __file);

		// BEGIN USER CODE
		ChannelSftp channel = SFTP.getChannel(getContext());
		channel.put(Core.getFileDocumentContent(getContext(), file.getMendixObject()), destination);
		return true;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public java.lang.String toString()
	{
		return "Put";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}