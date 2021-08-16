package com.souza.souzafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter	{

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
		.inMemory()
		    .withClient("souzafood-web")
		    .secret(passwordEncoder.encode("web123"))
		    .authorizedGrantTypes("password","refresh_token")
		    .scopes("write", "read")
		    .accessTokenValiditySeconds(6 * 60 * 60) // 6 horas
		    .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
		.and()
		    .withClient("faturamento")
		    .secret(passwordEncoder.encode("faturamento123"))
		    .authorizedGrantTypes("client_credentials")
		    .scopes("write", "read")
		.and()
		    .withClient("checktoken")
		    .secret(passwordEncoder.encode("check123")); //Aula: https://app.algaworks.com/aulas/2238/configurando-o-resource-server-com-a-nova-stack-do-spring-security
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()"); //Aula: https://app.algaworks.com/aulas/2237/configurando-o-endpoint-de-introspeccao-de-tokens-no-authorization-server
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

		endpoints
		     .authenticationManager(authenticationManager)
		     .userDetailsService(userDetailsService)
		     .reuseRefreshTokens(false);
	}
	
}
