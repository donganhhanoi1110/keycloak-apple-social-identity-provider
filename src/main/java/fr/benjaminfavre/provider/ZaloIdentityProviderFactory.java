package fr.benjaminfavre.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class ZaloIdentityProviderFactory extends AbstractIdentityProviderFactory<ZaloIdentityProvider> implements SocialIdentityProviderFactory<ZaloIdentityProvider> {
    public static final String PROVIDER_ID = "zalo";

    @Override
    public String getName() {
        return "Zalo";
    }

    @Override
    public ZaloIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new ZaloIdentityProvider(session, new ZaloIdentityProviderConfig(model));
    }

    @Override
    public ZaloIdentityProviderConfig createConfig() {
        return new ZaloIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
