/**
 * Created by matrixdipu on 7/28/2015.
 */

import java.util.Hashtable;
import oracle.security.am.asdk.*;
public class AccessClient {
    public static final String ms_resource = "//RWG1/index.html";
    public static final String ms_protocol = "http";
    public static final String ms_method = "GET";
    public static final String ms_login = "user3";
    public static final String ms_passwd = "Welcome1";
    public static final String m_configLocation = "D:\\R2PS3\\OAMWG\\wginst\\webgate\\config";

    public static void main (String args[]){

        AccessClient testASDKClient = null;

        try {
            testASDKClient = AccessClient.createDefaultInstance(m_configLocation,ms_resource,
                    AccessClient.CompatibilityMode.OAM_11G);

            ResourceRequest resReq = new ResourceRequest(ms_protocol, ms_resource,ms_method);

            if (resReq.isProtected()){
                AuthenticationScheme authnScheme = new AuthenticationScheme(resReq);

                if (authnScheme.isForm()){
                    Hashtable userCreds = new Hashtable();
                    userCreds.put("userid",ms_login);
                    userCreds.put("password",ms_passwd);
                    UserSession userSession = new UserSession(resReq,userCreds);
                    if (userSession.getStatus() == UserSession.LOGGEDIN){
                        if (userSession.isAuthorized(resReq))
                            System.out.println("User: "+ms_login+" authorized to access: "+ms_resource);
                        else
                            System.out.println("User: "+ms_login+" not authorized to access: "+ms_resource);
                    }
                }

            }else{
                System.out.println("Resource : "+ms_resource+ " not protected");
            }

        } catch (AccessException accessException){
            System.out.println("Access Exception" + accessException.getMessage());
        }

    }

}
