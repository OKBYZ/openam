package org.forgerock.openam.authentication.modules.oauth2;

import static org.mockito.Mockito.*;
import java.net.*;

import javax.security.auth.login.LoginException;
import com.iplanet.am.util.AdminUtils;
import com.sun.identity.authentication.service.AuthD;
import com.iplanet.services.naming.WebtopNaming;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.shared.Constants;
import com.iplanet.services.comm.client.PLLClient;
import java.util.Vector;
import java.util.Hashtable;
import java.util.HashMap;
import com.iplanet.services.comm.share.RequestSet;
import com.iplanet.services.naming.share.NamingResponse;
import com.sun.identity.authentication.share.AuthXMLTags;

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
import org.mockito.AdditionalAnswers;

@RunWith(PowerMockRunner.class)
@PrepareForTest({AdminUtils.class,SystemProperties.class,PLLClient.class,WebtopNaming.class})
@PowerMockIgnore("javax.net.ssl.*")
public class OauthTest{

    private WireMockRule mockRule;

    @Before
    public void setup() throws Exception{
        mockRule = new WireMockRule(WireMockConfiguration
            .wireMockConfig()
            .dynamicPort()
            .usingFilesUnderDirectory("src/test/java/org/forgerock/openam/authentication/modules/oauth2")
            );
        mockRule.start();

        String httpBase = "http://localhost:"+mockRule.port();


        PowerMockito.mockStatic(AdminUtils.class);
        when(AdminUtils.getAdminPassword()).thenReturn(new byte[10]);

        PowerMockito.mockStatic(SystemProperties.class);
        when(SystemProperties.get(anyString(),anyString())).then(AdditionalAnswers.returnsSecondArg()); //常に台に引数を有効に
        when(SystemProperties.get(Constants.AM_NAMING_URL)).thenReturn(httpBase+"/");
        when(SystemProperties.get("com.sun.identity.agents.app.username")).thenReturn("appUser");   //APP_USERNAME
        when(SystemProperties.get("com.iplanet.am.service.secret")).thenReturn("appSecret");   //APP_SECRET
        when(SystemProperties.get("com.iplanet.am.service.password")).thenReturn("appPassword");   //APP_PASSWORD

        PowerMockito.mockStatic(WebtopNaming.class);
        PowerMockito.doReturn(new Hashtable()).when(WebtopNaming.class,"getNamingTable",any(URL.class));
        Vector authUrls = new Vector();
        URL authURL = new URL(httpBase+"/auth");
        authUrls.add(authURL);
        when(WebtopNaming.getServiceAllURLs(AuthXMLTags.AUTH_SERVICE)).thenReturn(authUrls);

        PowerMockito.mockStatic(PLLClient.class);
        when(PLLClient.send(eq(authURL),any(RequestSet.class),any(HashMap.class))).thenReturn(new Vector());

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
}
