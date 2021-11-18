package fr.benjaminfavre.provider;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.Optional;

class ZaloIdentityProviderConfig extends OIDCIdentityProviderConfig {
    ZaloIdentityProviderConfig() {}

    ZaloIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }


    public String getFetchedFields() {
        return (String) Optional.ofNullable(this.getConfig().get("fetchedFields")).map((fieldsConfig) -> {
            return fieldsConfig.replaceAll("\\s+", "");
        }).orElse("");
    }

    public void setFetchedFields(String fetchedFields) {
        this.getConfig().put("fetchedFields", fetchedFields);
    }

    public String getZaloRedirectUri() {
        return (String) Optional.ofNullable(this.getConfig().get("zaloRedirectUri")).map((fieldsConfig) -> {
            return fieldsConfig.replaceAll("\\s+", "");
        }).orElse("");
    }

    public void setZaloRedirectUri(String zaloRedirectUri) {
        this.getConfig().put("zaloRedirectUri", zaloRedirectUri);
    }


}
