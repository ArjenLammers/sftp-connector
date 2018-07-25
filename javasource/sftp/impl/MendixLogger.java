package sftp.impl;

import com.mendix.logging.ILogNode;

public class MendixLogger implements com.jcraft.jsch.Logger {

	private ILogNode logger = SFTP.getLogger();
	
	@Override
	public boolean isEnabled(int arg0) {
		return true;
	}

	@Override
	public void log(int level, String message) {
		switch (level) {
		case DEBUG:
			logger.trace(message);
			break;
		case INFO:
			logger.debug(message);
			break;
		case WARN:
			logger.warn(message);
			break;
		case ERROR:
			logger.error(message);
			break;
		case FATAL:
			logger.critical(message);
			break;
		}
	}
	
}