package org.forgerock.openam.authentication.modules.oauth2;

import static org.mockito.Mockito.*;
import java.net.*;

import javax.security.auth.login.LoginException;
import com.iplanet.am.util.AdminUtils;
import com.sun.identity.authentication.service.AuthD;
import com.iplanet.services.naming.WebtopNaming;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.shared.Constants;

import org.junit.Test;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.Assert;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({AdminUtils.class,SystemProperties.class})
@PowerMockIgnore("javax.net.ssl.*")
public class OauthTest{

    private WireMockRule mockRule;

    @Before
    public void setup(){
        PowerMockito.mockStatic(AdminUtils.class);
        PowerMockito.mockStatic(SystemProperties.class);
        //AuthD mockAuth = mock(AuthD.class);
        when(AdminUtils.getAdminPassword()).thenReturn(new byte[10]);
        when(SystemProperties.get(Constants.AM_NAMING_URL)).thenReturn("/");
        WebtopNaming.initialize();
        mockRule = new WireMockRule(WireMockConfiguration
            .wireMockConfig()
            .dynamicPort()
            .usingFilesUnderDirectory("src/test/java/org/forgerock/openam/authentication/modules/oauth2")
            );
        mockRule.start();
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
