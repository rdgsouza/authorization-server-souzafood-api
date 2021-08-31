package com.souza.souzafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClaimsTokenEnhacer implements TokenEnhancer {

//	Aula: https://app.algaworks.com/aulas/2270/adicionando-claims-customizadas-no-payload-do-jwt
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

		if (authentication.getPrincipal() instanceof AuthUser) {
			var authUser = (AuthUser) authentication.getPrincipal();

			var info = new HashMap<String, Object>();
			info.put("nome_completo", authUser.getFullName());
            info.put("usuario_id", authUser.getUserId());
			
			var oAuthAccessToken = (DefaultOAuth2AccessToken) accessToken;
			oAuthAccessToken.setAdditionalInformation(info);
		}
		
		return accessToken;
	}

}
