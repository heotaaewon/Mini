package com.example.mini.service;

import com.example.mini.entity.CustomUser;
import com.example.mini.entity.PrincipalDetails;
import com.example.mini.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService_loadUserByUsername");
        CustomUser customUser=userRepository.findByUsername(username);
        return new PrincipalDetails(customUser);
    }
}