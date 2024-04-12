package com.example.demojwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//each request should be authenticated for state less sessions
public class SecurityConfguration {

	private final JwtAuthenticationFilter jwtAuthFilter;
	private final AuthenticationProvider authenticationProvider;
	
	@SuppressWarnings("removal")
	@Bean
	public SecurityFilterChain securityFilterChain (HttpSecurity http)throws Exception{
		http
		.csrf()
		.disable()
		.authorizeHttpRequests()     // White list all the request passed through requestMatchers
		.requestMatchers("/api/v1/auth/**")    //all authentication related controllers 
		.permitAll()
		.anyRequest() 				 // Then any request will be authenticated 
		.authenticated()
		.and()         				 // Stateless session management
		.sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()						 // Authentation Provider
		.authenticationProvider(authenticationProvider)
		.addFilterBefore(jwtAuthFilter,UsernamePasswordAuthenticationFilter.class) ; //do user name password authentication first
		return http.build();
		
	}
}
