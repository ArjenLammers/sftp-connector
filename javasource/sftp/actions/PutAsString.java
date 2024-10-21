// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package sftp.actions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import net.schmizz.sshj.sftp.StatefulSFTPClient;
import net.schmizz.sshj.xfer.InMemorySourceFile;
import sftp.impl.SFTP;

/**
 * Creates and uploads a file on a SFTP server coming from a String.
 * This action was introduced for optimization purposes.
 * In case the remote file is assumed to be a text file and should be directly processed, it doesn't make sense to store it as a FileDocument (leading to upload/download to e.g. S3 buckets).
 */
public class PutAsString extends CustomJavaAction<java.lang.Boolean>
{
	private java.lang.String destination;
	private java.lang.String contents;

	public PutAsString(IContext context, java.lang.String destination, java.lang.String contents)
	{
		super(context);
		this.destination = destination;
		this.contents = contents;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		// BEGIN USER CODE
		StatefulSFTPClient client = SFTP.getClient(getContext());
		String fileName, path;
		if (destination.contains("/")) {
			fileName = destination.substring(destination.lastIndexOf('/') + 1);
			path = destination.substring(0, destination.lastIndexOf('/'));
		} else {
			fileName = destination;
			path = client.pwd();
		}
		
		
		InMemorySourceFile source = new InMemorySourceFile() {

			@Override
			public String getName() {
				return fileName;
			}

			@Override
			public long getLength() {
				return contents.length();
			}

			@Override
			public InputStream getInputStream() throws IOException {
				return new ByteArrayInputStream(contents.getBytes());
			}
		};
		client.put(source, path);
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
		return "PutAsString";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}