// This file was generated by Mendix Studio Pro.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package sftp.proxies;

public enum KeyType
{
	DSA(new java.lang.String[][] { new java.lang.String[] { "en_US", "DSA" } }),
	DSA_CERT(new java.lang.String[][] { new java.lang.String[] { "en_US", "DSA_CERT" } }),
	ECDSA256(new java.lang.String[][] { new java.lang.String[] { "en_US", "ECDSA256" } }),
	ECDSA384(new java.lang.String[][] { new java.lang.String[] { "en_US", "ECDSA384" } }),
	ECDSA521(new java.lang.String[][] { new java.lang.String[] { "en_US", "ECDSA521" } }),
	ED25519(new java.lang.String[][] { new java.lang.String[] { "en_US", "ED25519" } }),
	RSA(new java.lang.String[][] { new java.lang.String[] { "en_US", "RSA" } }),
	RSA_CERT(new java.lang.String[][] { new java.lang.String[] { "en_US", "RSA_CERT" } });

	private final java.util.Map<java.lang.String, java.lang.String> captions;

	private KeyType(java.lang.String[][] captionStrings)
	{
		this.captions = new java.util.HashMap<>();
		for (java.lang.String[] captionString : captionStrings) {
			captions.put(captionString[0], captionString[1]);
		}
	}

	public java.lang.String getCaption(java.lang.String languageCode)
	{
		return captions.getOrDefault(languageCode, "en_US");
	}

	public java.lang.String getCaption()
	{
		return captions.get("en_US");
	}
}
