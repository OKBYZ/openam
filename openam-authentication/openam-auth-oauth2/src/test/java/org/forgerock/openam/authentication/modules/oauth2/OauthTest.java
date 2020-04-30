package org.forgerock.openam.authentication.modules.oauth2;

import static org.mockito.Mockito.*;
import java.net.*;
import java.util.Vector;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import javax.naming.directory.ModificationItem;

import javax.security.auth.login.LoginException;
import com.iplanet.am.util.AdminUtils;
import com.sun.identity.authentication.service.AuthD;
import com.iplanet.services.naming.WebtopNaming;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.SMSObject;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SMSDataEntry;
import com.sun.identity.sm.SMSEntry;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOException;
import com.iplanet.services.comm.client.PLLClient;
import com.iplanet.services.comm.share.RequestSet;
import com.iplanet.services.naming.share.NamingResponse;
import com.sun.identity.authentication.share.AuthXMLTags;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.ServiceManager;
import org.forgerock.guice.core.InjectorHolder;
import com.iplanet.dpro.session.service.SessionService;
import com.iplanet.dpro.session.Session;
import com.iplanet.dpro.session.SessionID;
import javax.servlet.http.HttpSession;
import org.forgerock.openam.sso.providers.stateless.StatelessSessionFactory;
import org.forgerock.openam.session.SessionCache;
import com.iplanet.dpro.session.operations.ServerSessionOperationStrategy;
import com.iplanet.dpro.session.operations.SessionOperations;
import com.iplanet.dpro.session.share.SessionInfo;
import org.forgerock.openam.session.SessionPollerPool;
import com.iplanet.services.naming.NamingTableConfigurationFactory;
import com.iplanet.sso.providers.dpro.SSOProviderImpl;
import org.forgerock.openam.session.SessionCookies;

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
@PrepareForTest({AdminUtils.class,SystemProperties.class,ServiceManager.class,InjectorHolder.class,WebtopNaming.class,SSOProviderImpl.class,SMSEntry.class,AuthD.class})
@PowerMockIgnore("javax.net.ssl.*")
public class OauthTest{

    private WireMockRule mockRule;

    @Before
    public void setup() throws Exception{
        PowerMockito.mockStatic(AuthD.class);
        PowerMockito.whenNew(AuthD.class).withNoArguments().thenReturn(PowerMockito.mock(AuthD.class));

        SessionID sessionID = mock(SessionID.class);

        Session session = mock(Session.class);
        PowerMockito.whenNew(Session.class).withArguments(any(String.class)).thenReturn(session);
        when(session.getID()).thenReturn(sessionID);
        when(session.getProperty(eq("Principal"))).thenReturn("Principal");

        SessionService sessionService = mock(SessionService.class);
        when(sessionService.getAuthenticationSession(any(String.class),isNull(HttpSession.class))).thenReturn(session);

        SessionInfo sessionInfo = new SessionInfo();
        sessionInfo.setSessionType("application");
        sessionInfo.setState("valid");

        SessionOperations sessionOperations = mock(SessionOperations.class);
        when(sessionOperations.refresh(any(Session.class),eq(true))).thenReturn(sessionInfo);

        ServerSessionOperationStrategy sessionOperationStrategy = mock(ServerSessionOperationStrategy.class);
        when(sessionOperationStrategy.getOperation(any(Session.class))).thenReturn(sessionOperations);

        PowerMockito.mockStatic(InjectorHolder.class);
        when(InjectorHolder.getInstance(eq(SessionService.class))).thenReturn(sessionService);
        when(InjectorHolder.getInstance(eq(StatelessSessionFactory.class))).thenReturn(mock(StatelessSessionFactory.class));
        when(InjectorHolder.getInstance(eq(SessionCache.class))).thenReturn(mock(SessionCache.class));
        when(InjectorHolder.getInstance(eq(ServerSessionOperationStrategy.class))).thenReturn(sessionOperationStrategy);
        when(InjectorHolder.getInstance(eq(SessionPollerPool.class))).thenReturn(mock(SessionPollerPool.class));
        when(InjectorHolder.getInstance(eq(SessionCookies.class))).thenReturn(mock(SessionCookies.class));
    /*
        mockRule = new WireMockRule(WireMockConfiguration
            .wireMockConfig()
            .dynamicPort()
            .usingFilesUnderDirectory("src/test/java/org/forgerock/openam/authentication/modules/oauth2")
            );
        mockRule.start();

        String httpBase = "http://localhost:"+mockRule.port();
*/
/*
        PowerMockito.mockStatic(AdminUtils.class);
        when(AdminUtils.getAdminPassword()).thenReturn("p@ssw0rd".getBytes());
        when(AdminUtils.getAdminDN()).thenReturn("cn=dsameuser,ou=DSAME Users,dc=openam,dc=forgerock,dc=org");

        PowerMockito.mockStatic(SystemProperties.class);
        when(SystemProperties.isServerMode()).thenReturn(true);
        when(SystemProperties.get(eq(AdminTokenAction.AMADMIN_MODE))).thenReturn("ldap location");
        when(SystemProperties.get(Constants.SDK_GLOBAL_CACHE_PROPERTY,"true")).thenReturn("true");
        when(SystemProperties.get("com.sun.identity.sm.sms_object_class_name","com.sun.identity.sm.ldap.SMSLdapObject"))
            .thenReturn(MockSMSObject.class.getName());
        when(SystemProperties.get(eq(Constants.AM_NAMING_URL))).thenReturn("http://localhost");
//        when(SystemProperties.get(eq(SMSEntry.DB_PROXY_ENABLE))).thenReturn("true");
//        when(SystemProperties.get(SystemProperties.CONFIG_PATH)).thenReturn("./src/test/resource/");

        PowerMockito.mockStatic(ServiceManager.class);
        when(ServiceManager.getBaseDN()).thenReturn("ldap location");
        PowerMockito.when(ServiceManager.class,"getVersion",eq("iPlanetAMProviderConfigService")).thenReturn("1.1");
        PowerMockito.when(ServiceManager.class,"getVersion",nullable(String.class)).thenReturn("1.0");
        PowerMockito.when(ServiceManager.class,"getCacheIndex",any(String.class),any(String.class)).thenReturn("cache");
        PowerMockito.when(ServiceManager.class,"getServiceNameDN",any(String.class),eq("1.0")).thenReturn("ou=1.0,ou=sunidentityrepositoryservice,ou=services,dc=openam,dc=forgerock,dc=org");


        NamingTableConfigurationFactory.NamingTableConfiguration config = mock(NamingTableConfigurationFactory.NamingTableConfiguration.class);

        NamingTableConfigurationFactory namingTableConfigFactory = mock(NamingTableConfigurationFactory.class);
        PowerMockito.whenNew(NamingTableConfigurationFactory.class).withNoArguments().thenReturn(namingTableConfigFactory);
        when(namingTableConfigFactory.getConfiguration(any(Hashtable.class))).thenReturn(config);

        PowerMockito.mockStatic(WebtopNaming.class);
        PowerMockito.when(WebtopNaming.class,"getNamingTable",any(URL.class)).thenReturn(new Hashtable());

        SSOToken ssoToken = mock(SSOToken.class);

        SSOProviderImpl ssoProviderImpl = PowerMockito.mock(SSOProviderImpl.class);
        PowerMockito.whenNew(SSOProviderImpl.class).withNoArguments().thenReturn(ssoProviderImpl);
        when(ssoProviderImpl.createSSOToken(any(String.class))).thenReturn(ssoToken);
/*
        SMSEntry smsMock = mock(SMSEntry.class);
        PowerMockito.mockStatic(SMSEntry.class);
        PowerMockito.whenNew(SMSEntry.class).withArguments(any(SSOToken.class),any(String.class)).thenReturn(smsMock);
*/
    }

    @Test
    public void getContentStreamByGETTest() throws Exception{
        OAuth oauth = new OAuth();
        //oauth.getContentStreamByGET("http://localhost:"+mockRule.port()+"/test",null,null);
        HttpURLConnection con1 = (HttpURLConnection)( new URL("http://localhost:"+mockRule.port()+"/hoge.html").openConnection());
        Assert.assertEquals(con1.getResponseCode(),400);
        HttpURLConnection con2 = (HttpURLConnection)( new URL("http://localhost:"+mockRule.port()+"/hage.html").openConnection());
        Assert.assertEquals(con2.getResponseCode(),500);
        HttpURLConnection con3 = (HttpURLConnection)( new URL("http://localhost:"+mockRule.port()+"/hoge.html?test1=1&test2=2").openConnection());
        Assert.assertEquals(con3.getResponseCode(),300);
        HttpURLConnection con4 = (HttpURLConnection)( new URL("http://localhost:"+mockRule.port()+"/hoge.html?test1=a&test2=2").openConnection());
        Assert.assertEquals(con4.getResponseCode(),301);
    }

    public static class MockSMSObject extends SMSObject{

        public String getAMSdkBaseDN(){
            return null;
        }
        public String getRootSuffix(){
            return null;
        }
        public boolean entryExists(SSOToken token, String objName){
            throw new RuntimeException("Not support");
        }
        public Set<String> searchSubOrgNames(SSOToken token, String dn,
            String filter, int numOfEntries, boolean sortResults,
            boolean ascendingOrder, boolean recursive) throws SMSException,
            SSOException{
            throw new RuntimeException("Not support");
        }
        public Set<String> searchOrganizationNames(SSOToken token, String dn,
            int numOfEntries, boolean sortResults, boolean ascendingOrder,
            String serviceName, String attrName, Set values)
            throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public Set<String> subEntries(SSOToken token, String dn, String filter,
            int numOfEntries, boolean sortResults, boolean ascendingOrder)
            throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public Set<String> schemaSubEntries(SSOToken token, String dn,
            String filter, String sidFilter, int numOfEntries,
            boolean sortResults, boolean ascendingOrder) throws SMSException,
            SSOException{
            throw new RuntimeException("Not support");
        }
        public Set<String> search(SSOToken token, String startDN, String filter,
            int numOfEntries, int timeLimit, boolean sortResults,
            boolean ascendingOrder) throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public Iterator<SMSDataEntry> search(SSOToken token, String startDN,
        String filter, int numOfEntries, int timeLimit, boolean sortResults,
        boolean ascendingOrder, Set<String> excludes) throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public Map<String, Set<String>> read(SSOToken token, String objName)
            throws SMSException, SSOException{
            return new Hashtable<>();
        }
        public void create(SSOToken token, String objName, Map attributes)
            throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public void modify(SSOToken token, String objName,
            ModificationItem[] mods) throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
        public void delete(SSOToken token, String objName)
            throws SMSException, SSOException{
            throw new RuntimeException("Not support");
        }
    }
}
