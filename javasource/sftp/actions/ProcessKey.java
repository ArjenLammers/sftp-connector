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
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.webui.CustomJavaAction;
import sftp.impl.SFTP;

public class ProcessKey extends CustomJavaAction<java.lang.Boolean>
{
	private IMendixObject __key;
	private sftp.proxies.Key key;

	public ProcessKey(IContext context, IMendixObject key)
	{
		super(context);
		this.__key = key;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.key = this.__key == null ? null : sftp.proxies.Key.initialize(getContext(), __key);

		// BEGIN USER CODE
		SFTP.validateKey(getContext(), key);
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
		return "ProcessKey";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
