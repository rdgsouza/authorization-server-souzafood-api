package com.souza.souzafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter	{

//	@Autowired
//	private PasswordEncoder passwordEncoder; Aula: https://app.algaworks.com/aulas/2238/configurando-o-resource-server-com-a-nova-stack-do-spring-security
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;    
	
	@Autowired
	private DataSource dataSource;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//    Configuracao do cliente no banco de dados usando o metodo jdbc 
		clients.jdbc(dataSource); 
	}
	
//	Configuracao do cliente em memoria
//		clients
//		.inMemory()
//		    .withClient("souzafood-web")
//		    .secret(passwordEncoder.encode("web123"))
//		    .authorizedGrantTypes("password","refresh_token")
//		    .scopes("WRITE", "READ")
//		    .accessTokenValiditySeconds(6 * 60 * 60) // 6 horas
//		    .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
//		
//		.and()
//		    .withClient("foodanalytics")
//		    .secret(passwordEncoder.encode(""))
//		    .authorizedGrantTypes("authorization_code")
////		    .autoApprove(true) // Se quiser que pule a tela do OAuth Approval adicione o .autoApprove(true) Fonte: https://app.algaworks.com/forum/topicos/80555/duvida-sobre-autorizacao
//		    .scopes("WRITE", "READ")
//		    .redirectUris("http://www.foodanalytics.local:8082")
////		    .redirectUris("https://oauth.pstmn.io/v1/callback") // https://app.algaworks.com/forum/topicos/83180/solicitacao-de-token-e-escopo
//		    
//		.and()
//		    .withClient("webadmin")
//		    .authorizedGrantTypes("implicit")
//		    .scopes("WRITE", "READ")
//		    .redirectUris("http://aplicacao-cliente")
//		    
//		.and()
//		    .withClient("faturamento")
//		    .secret(passwordEncoder.encode("faturamento123"))
//		    .authorizedGrantTypes("client_credentials")
//		    .scopes("WRITE", "READ")
//		    
//		.and()
//		    .withClient("checktoken")
//		    .secret(passwordEncoder.encode("check123")); //Aula: https://app.algaworks.com/aulas/2238/configurando-o-resource-server-com-a-nova-stack-do-spring-security
//	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()") //Aula que explica o .checkTokenAccess("permitAll()  https://app.algaworks.com/aulas/2237/configurando-o-endpoint-de-introspeccao-de-tokens-no-authorization-server
	    .tokenKeyAccess("permitAll()") //Aula que explica o .tokenKeyAccess  https://app.algaworks.com/aulas/2265/extraindo-a-chave-publica-no-formato-pem
		.allowFormAuthenticationForClients();// Aula que explica o .allowFormAuthenticationForClients():  https://app.algaworks.com/aulas/2251/testando-o-fluxo-authorization-code-com-pkce-com-o-metodo-plain
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		var enhancerChain = new TokenEnhancerChain();
	    enhancerChain.setTokenEnhancers(
	    		Arrays.asList(new JwtCustomClaimsTokenEnhacer(), jwtAccessTokenConverter()));
				
	    
		endpoints
		     .authenticationManager(authenticationManager)
		     .userDetailsService(userDetailsService)
		     .reuseRefreshTokens(false)
		     .accessTokenConverter(jwtAccessTokenConverter())
		     .tokenEnhancer(enhancerChain)
		     .approvalStore(approvalStore(endpoints.getTokenStore()))
		     .tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore approvalStore(TokenStore token) {
      
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(token);
		
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
	//	jwtAccessTokenConverter.setSigningKey("KJNFUHWKFWKF98723721NQDLQNDQDJ81UNLDNadasldnasldnladas123"); Aula: https://app.algaworks.com/aulas/2260/configurando-o-resource-server-para-jwt-assinado-com-chave-simetrica
	
		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		var keyStorePass = jwtKeyStoreProperties.getPassword();
		var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
    }
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}
