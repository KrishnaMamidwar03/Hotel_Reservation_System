package com.book.jwt.util;


import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.book.entities.User;

public class UserPrincipal implements UserDetails {

    private User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Assuming the User entity has a Role or a list of roles
        return Collections.singleton(new SimpleGrantedAuthority(user.getRole().name()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        // Return true as per your requirement or implement based on user status
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // Return true as per your requirement or implement based on user status
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // Return true as per your requirement or implement based on user status
        return true;
    }

    @Override
    public boolean isEnabled() {
        // Return true as per your requirement or implement based on user status
        return true;
    }
}
