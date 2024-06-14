// This file was generated by Mendix Studio Pro.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package sftp.proxies;

public class Configuration
{
	private final com.mendix.systemwideinterfaces.core.IMendixObject configurationMendixObject;

	private final com.mendix.systemwideinterfaces.core.IContext context;

	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "SFTP.Configuration";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		Name("Name"),
		Hostname("Hostname"),
		Port("Port"),
		Username("Username"),
		Password("Password"),
		StrictHostkeyChecking("StrictHostkeyChecking"),
		HostKey("HostKey"),
		HostKeyFingerprint("HostKeyFingerprint"),
		UseKey("UseKey"),
		UseGeneralKey("UseGeneralKey"),
		ConnectTimeout("ConnectTimeout"),
		PrioritizeSshRsaKeyAlgorithm("PrioritizeSshRsaKeyAlgorithm"),
		Configuration_Key("SFTP.Configuration_Key");

		private final java.lang.String metaName;

		MemberNames(java.lang.String s)
		{
			metaName = s;
		}

		@java.lang.Override
		public java.lang.String toString()
		{
			return metaName;
		}
	}

	public Configuration(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, entityName));
	}

	protected Configuration(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject configurationMendixObject)
	{
		if (configurationMendixObject == null) {
			throw new java.lang.IllegalArgumentException("The given object cannot be null.");
		}
		if (!com.mendix.core.Core.isSubClassOf(entityName, configurationMendixObject.getType())) {
			throw new java.lang.IllegalArgumentException(String.format("The given object is not a %s", entityName));
		}	

		this.configurationMendixObject = configurationMendixObject;
		this.context = context;
	}

	/**
	 * @deprecated Use 'Configuration.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static sftp.proxies.Configuration initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return sftp.proxies.Configuration.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 * @param context The context to be used
	 * @param mendixObject The Mendix object for the new instance
	 * @return a new instance of this proxy class
	 */
	public static sftp.proxies.Configuration initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new sftp.proxies.Configuration(context, mendixObject);
	}

	public static sftp.proxies.Configuration load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return sftp.proxies.Configuration.initialize(context, mendixObject);
	}

	public static java.util.List<sftp.proxies.Configuration> load(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String xpathConstraint) throws com.mendix.core.CoreException
	{
		return com.mendix.core.Core.createXPathQuery(String.format("//%1$s%2$s", entityName, xpathConstraint))
			.execute(context)
			.stream()
			.map(obj -> sftp.proxies.Configuration.initialize(context, obj))
			.collect(java.util.stream.Collectors.toList());
	}

	/**
	 * Commit the changes made on this proxy object.
	 * @throws com.mendix.core.CoreException
	 */
	public final void commit() throws com.mendix.core.CoreException
	{
		com.mendix.core.Core.commit(context, getMendixObject());
	}

	/**
	 * Commit the changes made on this proxy object using the specified context.
	 * @throws com.mendix.core.CoreException
	 */
	public final void commit(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		com.mendix.core.Core.commit(context, getMendixObject());
	}

	/**
	 * Delete the object.
	 */
	public final void delete()
	{
		com.mendix.core.Core.delete(context, getMendixObject());
	}

	/**
	 * Delete the object using the specified context.
	 */
	public final void delete(com.mendix.systemwideinterfaces.core.IContext context)
	{
		com.mendix.core.Core.delete(context, getMendixObject());
	}
	/**
	 * @return value of Name
	 */
	public final java.lang.String getName()
	{
		return getName(getContext());
	}

	/**
	 * @param context
	 * @return value of Name
	 */
	public final java.lang.String getName(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.Name.toString());
	}

	/**
	 * Set value of Name
	 * @param name
	 */
	public final void setName(java.lang.String name)
	{
		setName(getContext(), name);
	}

	/**
	 * Set value of Name
	 * @param context
	 * @param name
	 */
	public final void setName(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String name)
	{
		getMendixObject().setValue(context, MemberNames.Name.toString(), name);
	}

	/**
	 * @return value of Hostname
	 */
	public final java.lang.String getHostname()
	{
		return getHostname(getContext());
	}

	/**
	 * @param context
	 * @return value of Hostname
	 */
	public final java.lang.String getHostname(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.Hostname.toString());
	}

	/**
	 * Set value of Hostname
	 * @param hostname
	 */
	public final void setHostname(java.lang.String hostname)
	{
		setHostname(getContext(), hostname);
	}

	/**
	 * Set value of Hostname
	 * @param context
	 * @param hostname
	 */
	public final void setHostname(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String hostname)
	{
		getMendixObject().setValue(context, MemberNames.Hostname.toString(), hostname);
	}

	/**
	 * @return value of Port
	 */
	public final java.lang.Integer getPort()
	{
		return getPort(getContext());
	}

	/**
	 * @param context
	 * @return value of Port
	 */
	public final java.lang.Integer getPort(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Integer) getMendixObject().getValue(context, MemberNames.Port.toString());
	}

	/**
	 * Set value of Port
	 * @param port
	 */
	public final void setPort(java.lang.Integer port)
	{
		setPort(getContext(), port);
	}

	/**
	 * Set value of Port
	 * @param context
	 * @param port
	 */
	public final void setPort(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Integer port)
	{
		getMendixObject().setValue(context, MemberNames.Port.toString(), port);
	}

	/**
	 * @return value of Username
	 */
	public final java.lang.String getUsername()
	{
		return getUsername(getContext());
	}

	/**
	 * @param context
	 * @return value of Username
	 */
	public final java.lang.String getUsername(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.Username.toString());
	}

	/**
	 * Set value of Username
	 * @param username
	 */
	public final void setUsername(java.lang.String username)
	{
		setUsername(getContext(), username);
	}

	/**
	 * Set value of Username
	 * @param context
	 * @param username
	 */
	public final void setUsername(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String username)
	{
		getMendixObject().setValue(context, MemberNames.Username.toString(), username);
	}

	/**
	 * @return value of Password
	 */
	public final java.lang.String getPassword()
	{
		return getPassword(getContext());
	}

	/**
	 * @param context
	 * @return value of Password
	 */
	public final java.lang.String getPassword(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.Password.toString());
	}

	/**
	 * Set value of Password
	 * @param password
	 */
	public final void setPassword(java.lang.String password)
	{
		setPassword(getContext(), password);
	}

	/**
	 * Set value of Password
	 * @param context
	 * @param password
	 */
	public final void setPassword(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String password)
	{
		getMendixObject().setValue(context, MemberNames.Password.toString(), password);
	}

	/**
	 * @return value of StrictHostkeyChecking
	 */
	public final java.lang.Boolean getStrictHostkeyChecking()
	{
		return getStrictHostkeyChecking(getContext());
	}

	/**
	 * @param context
	 * @return value of StrictHostkeyChecking
	 */
	public final java.lang.Boolean getStrictHostkeyChecking(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Boolean) getMendixObject().getValue(context, MemberNames.StrictHostkeyChecking.toString());
	}

	/**
	 * Set value of StrictHostkeyChecking
	 * @param stricthostkeychecking
	 */
	public final void setStrictHostkeyChecking(java.lang.Boolean stricthostkeychecking)
	{
		setStrictHostkeyChecking(getContext(), stricthostkeychecking);
	}

	/**
	 * Set value of StrictHostkeyChecking
	 * @param context
	 * @param stricthostkeychecking
	 */
	public final void setStrictHostkeyChecking(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Boolean stricthostkeychecking)
	{
		getMendixObject().setValue(context, MemberNames.StrictHostkeyChecking.toString(), stricthostkeychecking);
	}

	/**
	 * @return value of HostKey
	 */
	public final java.lang.String getHostKey()
	{
		return getHostKey(getContext());
	}

	/**
	 * @param context
	 * @return value of HostKey
	 */
	public final java.lang.String getHostKey(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.HostKey.toString());
	}

	/**
	 * Set value of HostKey
	 * @param hostkey
	 */
	public final void setHostKey(java.lang.String hostkey)
	{
		setHostKey(getContext(), hostkey);
	}

	/**
	 * Set value of HostKey
	 * @param context
	 * @param hostkey
	 */
	public final void setHostKey(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String hostkey)
	{
		getMendixObject().setValue(context, MemberNames.HostKey.toString(), hostkey);
	}

	/**
	 * @return value of HostKeyFingerprint
	 */
	public final java.lang.String getHostKeyFingerprint()
	{
		return getHostKeyFingerprint(getContext());
	}

	/**
	 * @param context
	 * @return value of HostKeyFingerprint
	 */
	public final java.lang.String getHostKeyFingerprint(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.HostKeyFingerprint.toString());
	}

	/**
	 * Set value of HostKeyFingerprint
	 * @param hostkeyfingerprint
	 */
	public final void setHostKeyFingerprint(java.lang.String hostkeyfingerprint)
	{
		setHostKeyFingerprint(getContext(), hostkeyfingerprint);
	}

	/**
	 * Set value of HostKeyFingerprint
	 * @param context
	 * @param hostkeyfingerprint
	 */
	public final void setHostKeyFingerprint(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String hostkeyfingerprint)
	{
		getMendixObject().setValue(context, MemberNames.HostKeyFingerprint.toString(), hostkeyfingerprint);
	}

	/**
	 * @return value of UseKey
	 */
	public final java.lang.Boolean getUseKey()
	{
		return getUseKey(getContext());
	}

	/**
	 * @param context
	 * @return value of UseKey
	 */
	public final java.lang.Boolean getUseKey(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Boolean) getMendixObject().getValue(context, MemberNames.UseKey.toString());
	}

	/**
	 * Set value of UseKey
	 * @param usekey
	 */
	public final void setUseKey(java.lang.Boolean usekey)
	{
		setUseKey(getContext(), usekey);
	}

	/**
	 * Set value of UseKey
	 * @param context
	 * @param usekey
	 */
	public final void setUseKey(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Boolean usekey)
	{
		getMendixObject().setValue(context, MemberNames.UseKey.toString(), usekey);
	}

	/**
	 * @return value of UseGeneralKey
	 */
	public final java.lang.Boolean getUseGeneralKey()
	{
		return getUseGeneralKey(getContext());
	}

	/**
	 * @param context
	 * @return value of UseGeneralKey
	 */
	public final java.lang.Boolean getUseGeneralKey(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Boolean) getMendixObject().getValue(context, MemberNames.UseGeneralKey.toString());
	}

	/**
	 * Set value of UseGeneralKey
	 * @param usegeneralkey
	 */
	public final void setUseGeneralKey(java.lang.Boolean usegeneralkey)
	{
		setUseGeneralKey(getContext(), usegeneralkey);
	}

	/**
	 * Set value of UseGeneralKey
	 * @param context
	 * @param usegeneralkey
	 */
	public final void setUseGeneralKey(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Boolean usegeneralkey)
	{
		getMendixObject().setValue(context, MemberNames.UseGeneralKey.toString(), usegeneralkey);
	}

	/**
	 * @return value of ConnectTimeout
	 */
	public final java.lang.Integer getConnectTimeout()
	{
		return getConnectTimeout(getContext());
	}

	/**
	 * @param context
	 * @return value of ConnectTimeout
	 */
	public final java.lang.Integer getConnectTimeout(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Integer) getMendixObject().getValue(context, MemberNames.ConnectTimeout.toString());
	}

	/**
	 * Set value of ConnectTimeout
	 * @param connecttimeout
	 */
	public final void setConnectTimeout(java.lang.Integer connecttimeout)
	{
		setConnectTimeout(getContext(), connecttimeout);
	}

	/**
	 * Set value of ConnectTimeout
	 * @param context
	 * @param connecttimeout
	 */
	public final void setConnectTimeout(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Integer connecttimeout)
	{
		getMendixObject().setValue(context, MemberNames.ConnectTimeout.toString(), connecttimeout);
	}

	/**
	 * @return value of PrioritizeSshRsaKeyAlgorithm
	 */
	public final java.lang.Boolean getPrioritizeSshRsaKeyAlgorithm()
	{
		return getPrioritizeSshRsaKeyAlgorithm(getContext());
	}

	/**
	 * @param context
	 * @return value of PrioritizeSshRsaKeyAlgorithm
	 */
	public final java.lang.Boolean getPrioritizeSshRsaKeyAlgorithm(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Boolean) getMendixObject().getValue(context, MemberNames.PrioritizeSshRsaKeyAlgorithm.toString());
	}

	/**
	 * Set value of PrioritizeSshRsaKeyAlgorithm
	 * @param prioritizesshrsakeyalgorithm
	 */
	public final void setPrioritizeSshRsaKeyAlgorithm(java.lang.Boolean prioritizesshrsakeyalgorithm)
	{
		setPrioritizeSshRsaKeyAlgorithm(getContext(), prioritizesshrsakeyalgorithm);
	}

	/**
	 * Set value of PrioritizeSshRsaKeyAlgorithm
	 * @param context
	 * @param prioritizesshrsakeyalgorithm
	 */
	public final void setPrioritizeSshRsaKeyAlgorithm(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Boolean prioritizesshrsakeyalgorithm)
	{
		getMendixObject().setValue(context, MemberNames.PrioritizeSshRsaKeyAlgorithm.toString(), prioritizesshrsakeyalgorithm);
	}

	/**
	 * @throws com.mendix.core.CoreException
	 * @return value of Configuration_Key
	 */
	public final sftp.proxies.Key getConfiguration_Key() throws com.mendix.core.CoreException
	{
		return getConfiguration_Key(getContext());
	}

	/**
	 * @param context
	 * @return value of Configuration_Key
	 * @throws com.mendix.core.CoreException
	 */
	public final sftp.proxies.Key getConfiguration_Key(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		sftp.proxies.Key result = null;
		com.mendix.systemwideinterfaces.core.IMendixIdentifier identifier = getMendixObject().getValue(context, MemberNames.Configuration_Key.toString());
		if (identifier != null) {
			result = sftp.proxies.Key.load(context, identifier);
		}
		return result;
	}

	/**
	 * Set value of Configuration_Key
	 * @param configuration_key
	 */
	public final void setConfiguration_Key(sftp.proxies.Key configuration_key)
	{
		setConfiguration_Key(getContext(), configuration_key);
	}

	/**
	 * Set value of Configuration_Key
	 * @param context
	 * @param configuration_key
	 */
	public final void setConfiguration_Key(com.mendix.systemwideinterfaces.core.IContext context, sftp.proxies.Key configuration_key)
	{
		if (configuration_key == null) {
			getMendixObject().setValue(context, MemberNames.Configuration_Key.toString(), null);
		} else {
			getMendixObject().setValue(context, MemberNames.Configuration_Key.toString(), configuration_key.getMendixObject().getId());
		}
	}

	/**
	 * @return the IMendixObject instance of this proxy for use in the Core interface.
	 */
	public final com.mendix.systemwideinterfaces.core.IMendixObject getMendixObject()
	{
		return configurationMendixObject;
	}

	/**
	 * @return the IContext instance of this proxy, or null if no IContext instance was specified at initialization.
	 */
	public final com.mendix.systemwideinterfaces.core.IContext getContext()
	{
		return context;
	}

	@java.lang.Override
	public boolean equals(Object obj)
	{
		if (obj == this) {
			return true;
		}
		if (obj != null && getClass().equals(obj.getClass()))
		{
			final sftp.proxies.Configuration that = (sftp.proxies.Configuration) obj;
			return getMendixObject().equals(that.getMendixObject());
		}
		return false;
	}

	@java.lang.Override
	public int hashCode()
	{
		return getMendixObject().hashCode();
	}

	/**
	 * @return String name of this class
	 */
	public static java.lang.String getType()
	{
		return entityName;
	}

	/**
	 * @return String GUID from this object, format: ID_0000000000
	 * @deprecated Use getMendixObject().getId().toLong() to get a unique identifier for this object.
	 */
	@java.lang.Deprecated
	public java.lang.String getGUID()
	{
		return "ID_" + getMendixObject().getId().toLong();
	}
}
