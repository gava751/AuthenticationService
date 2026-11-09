package com.innoboard.authservice.security;

import com.innoboard.authservice.domain.Credential;
import com.innoboard.authservice.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final CredentialRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Credential credentials = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid login or password"));

        return new AuthUser(credentials.getUserId(), credentials.getRole(), credentials.getUsername(),
                credentials.getPasswordHash(), credentials.isActive());
    }
}
