package org.forgerock.openam.authentication.modules.oauth2;

import static org.mockito.Mockito.*;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.naming.directory.ModificationItem;
import java.security.AccessController;
import java.security.Principal;
import javax.servlet.ServletContext;

import com.sun.identity.authentication.service.AuthD;
import org.forgerock.guice.core.InjectorHolder;
import com.iplanet.dpro.session.service.SessionService;
import org.forgerock.openam.sso.providers.stateless.StatelessSessionFactory;
import org.forgerock.openam.session.SessionCache;
import com.iplanet.dpro.session.operations.ServerSessionOperationStrategy;
import org.forgerock.openam.session.SessionPollerPool;
import org.forgerock.openam.session.SessionCookies;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.authentication.service.LoginStateCallback;
import com.sun.identity.authentication.service.LoginState;
import com.sun.identity.authentication.service.AuthUtils;
import com.sun.identity.sm.SMSEntry;
import com.sun.identity.sm.SMSObject;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.sun.identity.sm.SMSDataEntry;
import com.sun.identity.sm.SMSException;
import com.iplanet.am.util.AdminUtils;
import com.sun.identity.security.SystemAppTokenProvider;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.authentication.service.SSOTokenPrincipal;
import org.forgerock.openam.xui.XUIState;
import com.sun.identity.shared.Constants;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.sm.CachedSubEntries;
import org.forgerock.openam.cts.CTSPersistentStore;
import com.iplanet.dpro.session.service.InternalSession;

import org.junit.Test;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.Assert;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.mockito.ArgumentCaptor;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;
import org.mockito.stubbing.Answer;
import org.mockito.invocation.InvocationOnMock;

@RunWith(PowerMockRunner.class)
@PrepareForTest({InjectorHolder.class,AuthD.class,AuthUtils.class,AdminUtils.class,AdminTokenAction.class,SystemProperties.class,SSOTokenManager.class,CachedSubEntries.class})
@PowerMockIgnore("javax.net.ssl.*")
public class OauthTest{

    private OAuth oauth;

    private WireMockRule mockRule;
    private String httpBase;

    @Before
    public void setup() throws Exception{
        //for AMLoginModule
        PowerMockito.mockStatic(AuthD.class);
        AuthD authD = PowerMockito.mock(AuthD.class);
        PowerMockito.whenNew(AuthD.class).withNoArguments().thenReturn(authD);
        PowerMockito.when(AuthD.getAuth()).thenReturn(authD);
        PowerMockito.mockStatic(InjectorHolder.class);
        when(InjectorHolder.getInstance(eq(SessionService.class))).thenReturn(mock(SessionService.class));
        when(InjectorHolder.getInstance(eq(StatelessSessionFactory.class))).thenReturn(mock(StatelessSessionFactory.class));
        when(InjectorHolder.getInstance(eq(SessionCache.class))).thenReturn(mock(SessionCache.class));
        when(InjectorHolder.getInstance(eq(ServerSessionOperationStrategy.class))).thenReturn(mock(ServerSessionOperationStrategy.class));
        when(InjectorHolder.getInstance(eq(SessionPollerPool.class))).thenReturn(mock(SessionPollerPool.class));
        when(InjectorHolder.getInstance(eq(SessionCookies.class))).thenReturn(mock(SessionCookies.class));
        when(InjectorHolder.getInstance(eq(CTSPersistentStore.class))).thenReturn(mock(CTSPersistentStore.class));

        //for OAuth process()
        when(InjectorHolder.getInstance(eq(XUIState.class))).thenReturn(mock(XUIState.class));

        oauth = new OAuth();


   
        //Start Wire Mocka
        mockRule = new WireMockRule(WireMockConfiguration
            .wireMockConfig()
            .dynamicPort()
            .usingFilesUnderDirectory("src/test/java/org/forgerock/openam/authentication/modules/oauth2")
            );
        mockRule.start();
        httpBase = "http://localhost:"+mockRule.port();

    }

    public LoginState processInit() throws Exception{

        //for AuthClientUtils
        System.setProperty("com.sun.identity.sm.sms_object_class_name",SMSObjectMock.class.getName());
        PowerMockito.mockStatic(AdminUtils.class);
        when(AdminUtils.getAdminPassword()).thenReturn("password".getBytes());
        when(AdminUtils.getAdminDN()).thenReturn("/");
        SSOToken ssoToken = mock(SSOToken.class);
        when(ssoToken.getPrincipal()).thenReturn(new SSOTokenPrincipal("dc=openam,dc=forgerock,dc=org"));
        when(ssoToken.getTokenID()).thenReturn(mock(SSOTokenID.class));
        AdminTokenAction adminTokenAction = mock(AdminTokenAction.class);
        when(adminTokenAction.run()).thenReturn(ssoToken);
        PowerMockito.mockStatic(AdminTokenAction.class);
        when(AdminTokenAction.getInstance()).thenReturn(adminTokenAction);
        SSOTokenManager ssoTokenManager = PowerMockito.mock(SSOTokenManager.class);
        PowerMockito.doNothing().when(ssoTokenManager).validateToken(any(SSOToken.class)); //.doNothing();
        PowerMockito.mockStatic(SSOTokenManager.class);
        PowerMockito.when(SSOTokenManager.getInstance()).thenReturn(ssoTokenManager);

        //for OAuth.process
        HashMap options = new HashMap<>();
        HashSet<String> optionsValue = new HashSet<String>();
        optionsValue.add("test=test");
        optionsValue.add("scope=uid mail");
        options.put(OAuthParam.KEY_ACCOUNT_MAPPER_CONFIG,optionsValue);
        options.put(OAuthParam.KEY_ACCOUNT_MAPPER,optionsValue);
        options.put(OAuthParam.KEY_ATTRIBUTE_MAPPER_CONFIG,optionsValue);
        options.put(OAuthParam.KEY_ATTRIBUTE_MAPPER,optionsValue);
        options.put(OAuthParam.KEY_CLIENT_ID, optionsValue);
        options.put(OAuthParam.KEY_CLIENT_SECRET, optionsValue);
        options.put(OAuthParam.KEY_AUTH_SERVICE, optionsValue);
        options.put(OAuthParam.KEY_TOKEN_SERVICE, optionsValue);
        options.put(OAuthParam.KEY_PROFILE_SERVICE, optionsValue);
        options.put(OAuthParam.KEY_MAP_TO_ANONYMOUS_USER_FLAG, optionsValue);
        final LoginState loginState = mock(LoginState.class);
        oauth.initialize(new Subject(),
            new CallbackHandler(){
                public void handle(Callback[] callbacks){
                    LoginStateCallback loginStateCallback = (LoginStateCallback)callbacks[0];
                    when(loginState.getSession()).thenReturn(mock(InternalSession.class));
                    when(loginState.getHttpServletRequest()).thenReturn(mock(HttpServletRequest.class));
                    when(loginState.getHttpServletResponse()).thenReturn(mock(HttpServletResponse.class));
                    when(loginState.getFileName(any(String.class))).thenReturn("/OAuth.xml");
                    loginStateCallback.setLoginState(loginState);
                }
            },
            new HashMap(),
            options);
        System.setProperty(Constants.SMS_ENABLE_DB_NOTIFICATION,"true");
        System.setProperty(AdminTokenAction.AMADMIN_MODE,"false");
        PowerMockito.when(SystemProperties.isServerMode()).thenReturn(true);
        PowerMockito.mockStatic(CachedSubEntries.class);
        PowerMockito.when(CachedSubEntries.getInstanceIfCached(any(SSOToken.class),any(String.class),any(boolean.class))).thenReturn(mock(CachedSubEntries.class));
        return loginState;
    }

    @Test
    public void processTest_LoginStart() throws Exception{
        processInit();
        //Test
        Assert.assertEquals(oauth.process(new Callback[0],ISAuthConstants.LOGIN_START),OAuthParam.GET_OAUTH_TOKEN_STATE); 
    }

    @Test
    public void processTest_OAuthTokenState_NO_CSRF() throws Exception{
        LoginState loginState = processInit();
        HttpServletRequest requestMock = loginState.getHttpServletRequest();
        when(requestMock.getParameter(eq("code"))).thenReturn("code");
        try{
            //Test
            Assert.assertEquals(oauth.process(new Callback[0],ISAuthConstants.LOGIN_START),0);
            Assert.fail("failure");
        }catch(AuthLoginException e){
            Assert.assertEquals(e.getMessage(),"Authorization request failed because there was no state parameter");
        }
    }

    @Test
    public void getContentStreamByGETTest_200() throws Exception{
        InputStream is = oauth.getContentStreamByGET(httpBase + "/get200Test",null,null);
        Assert.assertEquals(inputStreamRead(is),"GET Request OK");
    }
    @Test
    public void getContentStreamByGETTest_404() throws Exception{
        try{
            InputStream is2 = oauth.getContentStreamByGET("http://localhost:"+mockRule.port()+"/test2",null,null);
        }catch(AuthLoginException e){
            Assert.assertEquals(e.getMessage(),"Authentication failed because the remote server responded with an HTTP error code 404");
        }
    }

    /**
     * read input stream
     */
    private String inputStreamRead(java.io.InputStream is) throws Exception{
        StringBuffer buf = new StringBuffer();
        InputStreamReader reader= null;
        BufferedReader br = null;
        try{
            reader = new InputStreamReader(is);
            br = new BufferedReader(reader);
            String str = null;
            while( (str = br.readLine()) != null ){
                if(buf.length() != 0 ){
                    buf.append("\n");
                }
                buf.append(str);
            }
        }finally{
            if(is != null ){
                is.close();
                reader.close();
                br.close();
            }
        }
        return buf.toString();
    }

    public static class SMSObjectMock extends SMSObject{
        @Override
        public Map<String, Set<String>> read(SSOToken token, String objName) throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return new HashMap<>();
        }

        @Override
        public void create(SSOToken token, String objName, Map attributes) throws SMSException, SSOException {
            // TODO Auto-generated method stub

        }

        @Override
        public void modify(SSOToken token, String objName, ModificationItem[] mods) throws SMSException, SSOException {
            // TODO Auto-generated method stub

        }

        @Override
        public void delete(SSOToken token, String objName) throws SMSException, SSOException {
            // TODO Auto-generated method stub

        }

        @Override
        public Set<String> searchSubOrgNames(SSOToken token, String dn, String filter, int numOfEntries,
                boolean sortResults, boolean ascendingOrder, boolean recursive) throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Set<String> searchOrganizationNames(SSOToken token, String dn, int numOfEntries, boolean sortResults,
                boolean ascendingOrder, String serviceName, String attrName, Set values)
                throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Set<String> subEntries(SSOToken token, String dn, String filter, int numOfEntries, boolean sortResults,
                boolean ascendingOrder) throws SMSException, SSOException {
            // TODO Auto-generated method stub
            Set<String> ret = new HashSet<>();
            ret.add("test mock");
            return ret;
        }

        @Override
        public Set<String> schemaSubEntries(SSOToken token, String dn, String filter, String sidFilter,
                int numOfEntries, boolean sortResults, boolean ascendingOrder) throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Set<String> search(SSOToken token, String startDN, String filter, int numOfEntries, int timeLimit,
                boolean sortResults, boolean ascendingOrder) throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Iterator<SMSDataEntry> search(SSOToken token, String startDN, String filter, int numOfEntries,
                int timeLimit, boolean sortResults, boolean ascendingOrder, Set<String> excludes)
                throws SMSException, SSOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean entryExists(SSOToken token, String objName) {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public String getRootSuffix() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public String getAMSdkBaseDN() {
            // TODO Auto-generated method stub
            return null;
        }
    }
}
