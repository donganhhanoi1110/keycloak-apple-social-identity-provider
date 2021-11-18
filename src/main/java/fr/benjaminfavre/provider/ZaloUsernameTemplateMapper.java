package fr.benjaminfavre.provider;

import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public class ZaloUsernameTemplateMapper extends UsernameTemplateMapper {
    private static final String[] cp = new String[] { ZaloUsernameTemplateMapper.PROVIDER_ID };

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return "zalo-username-template-mapper";
    }
}
