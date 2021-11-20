package fr.benjaminfavre.provider;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;

import org.keycloak.models.*;

import org.keycloak.utils.StringUtil;

import javax.ws.rs.core.UriBuilder;

public class ZaloIdentityProvider  extends AbstractOAuth2IdentityProvider<ZaloIdentityProviderConfig> implements SocialIdentityProvider<ZaloIdentityProviderConfig> {

    private final String USER_INFO_URL = "https://graph.zalo.me/v2.0/me?fields=id,name,email,first_name,last_name,phoneNumber,gender,birthday";
    private final String USER_AUTHORIZATION_URL = "https://oauth.zaloapp.com/v4/permission";
    private final String USER_TOKEN_URL = "https://oauth.zaloapp.com/v4/access_token";

    public ZaloIdentityProvider(KeycloakSession session, ZaloIdentityProviderConfig config) {
        super(session, config);
        /**
         * oauth.zaloapp.com/v4/permission  là API Authorization Endpoint với các tham số
         *
         * Tham số	Kiểu dữ liệu	Tính bắt buộc 	Mô tả
         * app_id	long	yes	ID của ứng dụng.
         * redirect_uri	string	yes	Thông tin được cấu hình tại bước 1.
         * code_challenge 	string	no	code challenge được tạo từ code verifier với giải thuật SHA-256 tại bước 2.
         * state	string	yes	Dùng để chống CSRF. Được trả nguyên vẹn trong redirect_uri.
         */
        config.setAuthorizationUrl(USER_AUTHORIZATION_URL);
        /**
         * Header
         *
         * HeaderName	Kiểu dữ liệu	Tính bắt buộc	Mô tả
         * secret_key	string	yes 	Khóa bí mật của ứng dụng
         * Body x-www-form-urlencoded
         *
         * Key	Kiểu dữ liệu	Tính bắt buộc	Mô tả
         * code	string	yes	Authorization code mà bạn nhận được ở bước 3
         * app_id	long	yes	ID của ứng dụng
         * grant_type 	string	yes	Thuộc tính cho biết thông tin để tạo access token.
         * Giá trị truyền vào: authorization_code
         *
         * đại diện cho việc tạo access token từ authorization code.
         *
         * code_verifier	string	yes nếu ở bước lấy oauth code có truyền code challenge	Code verifier được dùng để tạo code challenge ở bước 2.
         */
        config.setTokenUrl(USER_TOKEN_URL);
        config.setUserInfoUrl(USER_INFO_URL);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event, (ZaloIdentityProviderConfig)this.getConfig());
    }

    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            String fetchedFields = ((ZaloIdentityProviderConfig)this.getConfig()).getFetchedFields();
            String url = StringUtil.isNotBlank(fetchedFields) ? String.join(",", USER_INFO_URL, fetchedFields) : USER_INFO_URL;
            if (accessToken != null) {
                url += "&access_token=" + accessToken;
            }
            JsonNode profile = SimpleHttp.doGet(url, this.session)
                    .header("access_token", accessToken)
                    .header("Authorization", "Bearer " + accessToken).asJson();
            return this.extractIdentityFromProfile((EventBuilder)null, profile);
        } catch (Exception var5) {
            throw new IdentityBrokerException("Could not obtain user profile from facebook.", var5);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "id,name,picture,email,first_name,last_name,phoneNumber,gender,birthday";
    }

    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        ZaloIdentityProviderConfig zaloConfig = (ZaloIdentityProviderConfig)this.getConfig();
        uriBuilder.queryParam("app_id", new Object[]{zaloConfig.getClientId()});
        //This is for testing purposes because we only can configure callback url in zalo console with https://example.com
        if (zaloConfig.getZaloRedirectUri() != null) {
            uriBuilder.replaceQueryParam("redirect_uri", new Object[]{zaloConfig.getZaloRedirectUri()});
        }
        return uriBuilder;
    }

    protected String getProfileEndpointForValidation(EventBuilder event) {
        return USER_INFO_URL;
    }

    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String id = this.getJsonProperty(profile, "id");
        BrokeredIdentityContext user = new BrokeredIdentityContext(id);
        String email = this.getJsonProperty(profile, "email");
        String phoneNumber = this.getJsonProperty(profile, "phoneNumber");

        String username = this.getJsonProperty(profile, "username");
        if (username == null) {
            if (phoneNumber != null) {
                username = phoneNumber;
            } else if (email != null) {
                username = email;
            } else {
                username = id;
            }
        }

        if ( email == null) {
            email = username + "@localhost.com";
        }
        user.setEmail(email);

        user.setUsername(username);
        String firstName = this.getJsonProperty(profile, "first_name");
        String lastName = this.getJsonProperty(profile, "last_name");
        String name = this.getJsonProperty(profile, "name");
        if (lastName == null) {
            lastName = name;
        }
        if (firstName == null) {
            firstName = name;
        }

        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setIdpConfig(this.getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, ((ZaloIdentityProviderConfig)this.getConfig()).getAlias());
        return user;
    }


    protected class OIDCEndpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        ZaloIdentityProviderConfig zaloConfig;

        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, ZaloIdentityProviderConfig zaloConfig) {
            super(callback, realm, event);
            this.zaloConfig = zaloConfig;
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            SimpleHttp simpleHttp = super.generateTokenRequest(authorizationCode);
            simpleHttp.header("secret_key", zaloConfig.getClientSecret());
            simpleHttp.param("app_id", zaloConfig.getClientId());
            return simpleHttp;
        }

    }

}
