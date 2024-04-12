package com.example.demojwt.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demojwt.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

//every time the user sends a request the authentication filter is activated 
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private final JwtService jwtService;
	
	private final UserDetailsService  userDetailsService;

	@Override
	protected void doFilterInternal( @NonNull HttpServletRequest request, 
			@NonNull HttpServletResponse response, 
			@NonNull FilterChain filterChain)
			throws ServletException, IOException {
		//this authentication header is part of our request header 
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		// count Bearer and a space so begin index is 7
		jwt= authHeader.substring(7);
		userEmail = jwtService.extractUsername(jwt);
		// if user is not authenticated or we don't have UserEmail
		if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails= this.userDetailsService.loadUserByUsername(userEmail);
			if (jwtService.isTokenValid(jwt,userDetails)) {
			 UsernamePasswordAuthenticationToken authToken = new  UsernamePasswordAuthenticationToken(
					 userDetails,
					 null,
					 userDetails.getAuthorities()
					 );
			 authToken.setDetails(
					 new WebAuthenticationDetailsSource().buildDetails(request)
					 );
			 SecurityContextHolder.getContext().setAuthentication(authToken);
		}
	}
		//adding these lines so that the next filters can be excuted 
           filterChain.doFilter(request, response);
}
}
