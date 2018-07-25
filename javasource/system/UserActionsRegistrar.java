package system;

import aQute.bnd.annotation.component.Component;
import aQute.bnd.annotation.component.Reference;

import com.mendix.core.actionmanagement.IActionRegistrator;

@Component(immediate = true)
public class UserActionsRegistrar
{
  @Reference
  public void registerActions(IActionRegistrator registrator)
  {
    registrator.bundleComponentLoaded();
    registrator.registerUserAction(encryption.actions.DecryptString.class);
    registrator.registerUserAction(encryption.actions.EncryptString.class);
    registrator.registerUserAction(encryption.actions.GeneratePGPKeyRing.class);
    registrator.registerUserAction(encryption.actions.PGPDecryptDocument.class);
    registrator.registerUserAction(encryption.actions.PGPEncryptDocument.class);
    registrator.registerUserAction(encryption.actions.ValidatePrivateKeyRing.class);
    registrator.registerUserAction(sftp.actions.Cd.class);
    registrator.registerUserAction(sftp.actions.Connect.class);
    registrator.registerUserAction(sftp.actions.GenerateKey.class);
    registrator.registerUserAction(sftp.actions.Get.class);
    registrator.registerUserAction(sftp.actions.GetHostKey.class);
    registrator.registerUserAction(sftp.actions.GetHostKeyFingerprint.class);
    registrator.registerUserAction(sftp.actions.List.class);
    registrator.registerUserAction(sftp.actions.MkDir.class);
    registrator.registerUserAction(sftp.actions.ProcessKey.class);
    registrator.registerUserAction(sftp.actions.Put.class);
    registrator.registerUserAction(sftp.actions.Pwd.class);
    registrator.registerUserAction(sftp.actions.Rename.class);
    registrator.registerUserAction(sftp.actions.Rm.class);
    registrator.registerUserAction(sftp.actions.RmDir.class);
    registrator.registerUserAction(system.actions.VerifyPassword.class);
  }
}
