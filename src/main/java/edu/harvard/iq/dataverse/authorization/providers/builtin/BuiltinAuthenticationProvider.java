package edu.harvard.iq.dataverse.authorization.providers.builtin;

import edu.harvard.iq.dataverse.authorization.AuthenticationProviderDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.CredentialsAuthenticationProvider;
import java.util.Arrays;
import java.util.List;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;
import edu.harvard.iq.dataverse.util.BundleUtil;
import edu.harvard.iq.dataverse.validation.PasswordValidatorServiceBean;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * An authentication provider built into the application. Uses JPA and the
 * local database to store the users.
 *
 * @author michael
 */
public class BuiltinAuthenticationProvider implements CredentialsAuthenticationProvider {

    public static final String PROVIDER_ID = "builtin";
    /**
     * TODO: Think more about if it really makes sense to have the key for a
     * credential be a Bundle key. What if we want to reorganize our Bundle
     * files and rename some Bundle keys? Would login be broken until we update
     * the strings below?
     */
    public static final String KEY_USERNAME_OR_EMAIL = "login.builtin.credential.usernameOrEmail";
    public static final String KEY_PASSWORD = "login.builtin.credential.password";
    private static List<Credential> CREDENTIALS_LIST;

    final BuiltinUserServiceBean bean;
    final AuthenticationServiceBean authBean;
    private PasswordValidatorServiceBean passwordValidatorService;

    public BuiltinAuthenticationProvider( BuiltinUserServiceBean aBean, PasswordValidatorServiceBean passwordValidatorService, AuthenticationServiceBean auBean  ) {
        this.bean = aBean;
        this.authBean = auBean;
        this.passwordValidatorService = passwordValidatorService;
        CREDENTIALS_LIST = Arrays.asList(new Credential(KEY_USERNAME_OR_EMAIL), new Credential(KEY_PASSWORD, true));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AuthenticationProviderDisplayInfo getInfo() {
        return new AuthenticationProviderDisplayInfo(getId(), BundleUtil.getStringFromBundle("auth.providers.title.builtin"), "Internal user repository");
    }

    @Override
    public boolean isPasswordUpdateAllowed() {
        return true;
    }

    @Override
    public boolean isUserInfoUpdateAllowed() {
        return true;
    }

    @Override
    public boolean isUserDeletionAllowed() {
        return true;
    }

    @Override
    public void deleteUser(String userIdInProvider) {
        bean.removeUser(userIdInProvider);
    }

    @Override
    public void updatePassword(String userIdInProvider, String newPassword) {
        BuiltinUser biUser = bean.findByUserName( userIdInProvider  );
        biUser.updateEncryptedPassword(PasswordEncryption.get().encrypt(newPassword),
                                       PasswordEncryption.getLatestVersionNumber());
        bean.save(biUser);
    }

    /**
     * Validates that the passed password is indeed the password of the user.
     * @param userIdInProvider
     * @param password
     * @return {@code true} if the password matches the user's password; {@code false} otherwise.
     */
    @Override
    public Boolean verifyPassword( String userIdInProvider, String password ) {
        BuiltinUser biUser = bean.findByUserName( userIdInProvider  );
        if ( biUser == null ) return null;
        return PasswordEncryption.getVersion(biUser.getPasswordEncryptionVersion())
                                 .check(password, biUser.getEncryptedPassword());
    }


    @Override
    public AuthenticationResponse authenticate( AuthenticationRequest authReq ) {
        BuiltinUser u = bean.findByUserName(authReq.getCredential(KEY_USERNAME_OR_EMAIL) );
        AuthenticatedUser authUser = null;

        if(u == null) { //If can't find by username in builtin, get the auth user and then the builtin
            authUser = authBean.getAuthenticatedUserByEmail(authReq.getCredential(KEY_USERNAME_OR_EMAIL));
            if (authUser == null) { //if can't find by email return bad username, etc.
                return AuthenticationResponse.makeFail("Bad username, email address, or password");
            }
            u = bean.findByUserName(authUser.getUserIdentifier());
        }

        if ( u == null ) return AuthenticationResponse.makeFail("Bad username, email address, or password");

        //comentado para cambio de validacion de usuario
        //boolean userAuthenticated = PasswordEncryption.getVersion(u.getPasswordEncryptionVersion())
        //                                    .check(authReq.getCredential(KEY_PASSWORD), u.getEncryptedPassword() );

        boolean userAuthenticated = Boolean.FALSE;

        userAuthenticated = autenticatedLdap(authReq.getCredential(KEY_USERNAME_OR_EMAIL), authReq.getCredential(KEY_PASSWORD));

        if ( ! userAuthenticated ) {
            return AuthenticationResponse.makeFail("Bad username or password");
        }

        /* comentado para cambio de validacion de usuario
        if ( u.getPasswordEncryptionVersion() < PasswordEncryption.getLatestVersionNumber() ) {
            try {
                String passwordResetUrl = bean.requestPasswordUpgradeLink(u);

                return AuthenticationResponse.makeBreakout(u.getUserName(), passwordResetUrl);
            } catch (PasswordResetException ex) {
                return AuthenticationResponse.makeError("Error while attempting to upgrade password", ex);
            }
//        } else {
//            return AuthenticationResponse.makeSuccess(u.getUserName(), u.getDisplayInfo());
        }
        final List<String> errors = passwordValidatorService.validate(authReq.getCredential(KEY_PASSWORD));
        if (!errors.isEmpty()) {
            try {
                String passwordResetUrl = bean.requestPasswordComplianceLink(u);
                return AuthenticationResponse.makeBreakout(u.getUserName(), passwordResetUrl);
            } catch (PasswordResetException ex) {
                return AuthenticationResponse.makeError("Error while attempting to upgrade password", ex);
            }
        }
       */

        if(null == authUser) {
            authUser = authBean.getAuthenticatedUser(u.getUserName());
        }

        return AuthenticationResponse.makeSuccess(u.getUserName(), authUser.getDisplayInfo());
    }

    private Boolean autenticatedLdap(String user, String password){

        DefaultHttpClient httpClient = new DefaultHttpClient();
        Boolean b = Boolean.FALSE;

        try{
            //Define a postRequest request
            HttpPost postRequest = new HttpPost("https://run.mocky.io/v3/3be5879f-9f16-4594-9f27-8f85f3ce117c");

            //Set the API media type in http content-type header
            postRequest.addHeader("content-type", "application/json");

            //Set the request post body
            StringEntity userEntity = new StringEntity("{\"user\":\""+ user + "\",\"password\":\" "+ password + "\"}");
            postRequest.setEntity(userEntity);

            //Send the request; It will immediately return the response in HttpResponse object if any
            HttpResponse response = httpClient.execute(postRequest);

            //verify the valid error code first
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                b = Boolean.TRUE;
            }

        }catch(Exception e){
            return Boolean.FALSE;
        }
        finally
        {
            //Important: Close the connect
            httpClient.getConnectionManager().shutdown();
        }

        return b;
    }

    @Override
    public List<Credential> getRequiredCredentials() {
        return CREDENTIALS_LIST;
    }

    @Override
    public boolean isOAuthProvider() {
        return false;
    }

    @Override
    public boolean isDisplayIdentifier() {
        return false;
    }

}
