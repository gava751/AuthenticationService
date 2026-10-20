package com.innoboard.authservice.security;

import com.innoboard.authservice.domain.UserCredentials;
import com.innoboard.authservice.repository.UserCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final UserCredentialsRepository repository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException{
        UserCredentials credentials = repository.findByLogin(login)
                .orElseThrow(()->new UsernameNotFoundException("Invalid login or password"));

        return User.builder()
                .username(credentials.getLogin())
                .password(credentials.getPasswordHash())
                .roles(credentials.getRole().name())
                .disabled(!credentials.isActive())
                .build();
    }
}
