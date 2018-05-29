package io.cloudtrust.keycloak.test;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.scripting.DefaultScriptingProviderFactory;
import org.keycloak.scripting.ScriptingProvider;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The purpose of this class is to create the MOCKS that are necessary to run keycloak code. The main reason for this is
 * that keycloak takes a lot of the information that it uses from two sources:
 * 1) The database. The actual classes holding the data for this live in org.keycloak.models.jpa and rely on
 *    Hibernate/EntityManager to sync with the DB
 * 2) The cache, which is managed by infinispan. The actual classes that hold the data reside in
 *    org.keycloak.models.cache.infinispan.
 *
 * In the keycloak code only interface Models are referenced, for example a User is described by a UserModel interface
 * and a Realm or Client are referenced by the RealmModel and ClientModel interfaces. In practice, there would be
 * UserAdapter, RealmAdapter and ClientAdapter objects (the classes that extend those interfaces) when the code is
 * is running.
 *
 * While the objects that are represented in the database can be represented by either database or cache objects, there
 * are also some objects that are only held in the cache. This would be information that would pertain to the running
 * sessions and their state. Once again, the pattern is the same: there is an interface representing the state, and a
 * class which contains the actual information from the cache. An example for this would be the UserSessionModel
 * and the UserSessionAdapter for UserSessions. In this case however, there is only the cache object, not the jpa object.
 *
 * It is OK and necessary to create Mocks for all the objects that would come from the database or hold state, as
 * neither would be available when unit testing (and note that in some situations mocks for state shouldn't be created,
 * but replaced by actual objects). However, think long and hard before mocking any other behaviour or logic.
 */
public class MockHelper {

    //Mocks for DB elements
    @Mock
    private ClientModel client;
    @Mock
    private RealmModel realm;
    @Mock
    private UserModel user;
    @Mock
    private RoleModel role;

    //Mocks for sessions
    @Mock
    private KeycloakSession session;
    @Mock
    private UserSessionModel userSession;
    @Mock
    private AuthenticatedClientSessionModel clientSession;

    //Other mocks
    @Mock
    private UriInfo uriInfo;
    @Mock
    private KeyManager keyManager;

    /**
     * Initialises the mocks, must be called at least once in the test classes using this class. Can also be called
     * to reset the state of modified mocks.
     * @throws IOException
     */
    public void initMocks() throws IOException {
        MockitoAnnotations.initMocks(this);
        initRealm();
        initClient();
        initUser();
        initRole();

        initUserSession();
        initClientSession();
        initSession();

        initUriInfo();
        initKeyManager();
    }

    /**
     * Initialises a keycloak realm called "testRealm"
     */
    private void initRealm() {
        when(realm.getName()).thenReturn("testRealm");
        when(realm.isEnabled()).thenReturn(true);
        when(realm.getSslRequired()).thenReturn(SslRequired.ALL);
        when(realm.getAccessCodeLifespan()).thenReturn(1000);
        when(realm.getAccessTokenLifespan()).thenReturn(2000);
        when(realm.getRoleById(role.getId())).thenReturn(role);
    }

    public RealmModel getRealm() {
        return realm;
    }

    /**
     * Initialises a keycloak client of unspecified protocol
     */
    private void initClient() {
        when(client.getId()).thenReturn(UUID.randomUUID().toString()) ;
        when(client.getClientId()).thenReturn(getClientId());
        when(client.isEnabled()).thenReturn(true);
    }
    private String getClientId(){return "urn:test:example";}

    public ClientModel getClient() {
        return client;
    }

    /**
     * Initialises a test user
     */
    private void initUser() {
        when(user.getId()).thenReturn(getUserId());
        when(user.getUsername()).thenReturn("testUser");
        when(user.getEmail()).thenReturn("testUser@test.com");

        Set<GroupModel> userGroups = new HashSet<>();
        GroupModel group1 = mock(GroupModel.class);
        GroupModel group2 = mock(GroupModel.class);
        GroupModel group3 = mock(GroupModel.class);
        userGroups.addAll(Arrays.asList(group1, group2, group3));
        when(group1.getName()).thenReturn("group1");
        when(group2.getName()).thenReturn("group2");
        when(group3.getName()).thenReturn("group3");

        when(user.getGroups()).thenReturn(userGroups);
        when(user.isMemberOf(any())).thenReturn(false);
        when(user.isMemberOf(group1)).thenReturn(true);
        when(user.isMemberOf(group2)).thenReturn(true);
        when(user.isMemberOf(group3)).thenReturn(true);
    }
    private String getUserId(){
        return "e43169e4-82ac-4f7b-a8e3-9806d34c2825";
    }

    public UserModel getUser() {
        return user;
    }

    /**
     * Initialises a "user" role
     */
    private void initRole() {
        when(role.getId()).thenReturn(UUID.randomUUID().toString());
        when(role.getName()).thenReturn("user");
        when(role.getContainer()).thenReturn(realm);
    }

    /**
     * Initialises the keycloak session. This basically represent's keycloak's current state, including providers
     */
    private void initSession(){
        KeycloakContext context = Mockito.mock(KeycloakContext.class);
        when (session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        LoginFormsProvider loginFormsProvider = Mockito.mock(LoginFormsProvider.class);
        when(loginFormsProvider.setAuthenticationSession(any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString(), any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createErrorPage(any(Response.Status.class))).thenAnswer((Answer<Response>) invocation -> Response.status((Response.Status) invocation.getArguments()[0]).build());
        when (session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProvider);
        when(session.keys()).thenReturn(keyManager);
        when(getSession().getProvider(ScriptingProvider.class)).thenReturn(new DefaultScriptingProviderFactory().create(getSession()));
    }

    public KeycloakSession getSession() {
        return session;
    }

    /**
     * Initialises the user session, representing the current session of the user, which may span multiple clients
     */
    private void initUserSession() {
        when(userSession.getId()).thenReturn(UUID.randomUUID().toString());
        when(userSession.getBrokerSessionId()).thenReturn(UUID.randomUUID().toString());
        when(userSession.getUser()).thenReturn(user);
        Map<String, AuthenticatedClientSessionModel> map = Collections.singletonMap(client.getId(), clientSession);
        when(userSession.getAuthenticatedClientSessions()).thenReturn(map);
        doReturn(user.getId()).when(userSession).getBrokerUserId();
        when(userSession.isOffline()).thenReturn(true);
        when(userSession.getRealm()).thenReturn(realm);
    }

    public UserSessionModel getUserSession() {
        return userSession;
    }

    /**
     * Initialises the client session, representing the current state of the client, which may span multiple users.
     * Here we use the AuthenticatedClientSessionModel
     */
    private void initClientSession() {
        when(clientSession.getId()).thenReturn(UUID.randomUUID().toString());
        when(clientSession.getClient()).thenReturn(client);
        when(clientSession.getRedirectUri()).thenReturn(getClientId());
        when(clientSession.getNote("SSO_AUTH")).thenReturn("true");
        String roleId = role.getId();
        when(clientSession.getRoles()).thenReturn(Collections.singleton(roleId));
        when(clientSession.getUserSession()).thenReturn(userSession);
        when(clientSession.getRealm()).thenReturn(realm);
    }

    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }


    /**
     * Initialises the UriInfo for the current action
     */
    private void initUriInfo() {
        //We have to use thenAnswer so that the UriBuilder gets created on each call vs at mock time.
        when(uriInfo.getBaseUriBuilder()).
                thenAnswer(new Answer<UriBuilder>() {
                    public UriBuilder answer(InvocationOnMock invocation) {
                        return UriBuilder.fromUri("https://cloudtrust.io/auth");
                    }
                });

        URI baseUri = uriInfo.getBaseUriBuilder().build();
        when(uriInfo.getBaseUri()).thenReturn(baseUri);
    }

    public UriInfo getUriInfo() {
        return uriInfo;
    }

    /**
     * Initialises a keymanager with actual keys (sort of). Using a DefaultKeyManager is complicated due to the requirements on
     * the KeycloakSession (providers, factories), so a mock is used instead
     */
    private void initKeyManager() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        SecretKey secret = new SecretKeySpec("junit".getBytes(), "HmacSHA256");
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("This shouldn't happen");
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(Arrays.copyOf(sha.digest(("junit").getBytes()), 16), "AES");
        KeyManager.ActiveHmacKey activeHmacKey = new KeyManager.ActiveHmacKey(UUID.randomUUID().toString(), secret);
        KeyManager.ActiveRsaKey activeRsaKey = new KeyManager.ActiveRsaKey(UUID.randomUUID().toString(), keyPair.getPrivate(), keyPair.getPublic(), certificate);
        KeyManager.ActiveAesKey activeAesKey = new KeyManager.ActiveAesKey(UUID.randomUUID().toString(), secretKeySpec);
        when(keyManager.getActiveHmacKey(realm)).thenReturn(activeHmacKey);
        when(keyManager.getActiveRsaKey(realm)).thenReturn(activeRsaKey);
        when(keyManager.getActiveAesKey(realm)).thenReturn(activeAesKey);
    }
}
