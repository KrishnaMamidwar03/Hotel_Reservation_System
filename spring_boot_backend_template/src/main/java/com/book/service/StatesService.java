package com.book.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.State;
import com.book.repository.StateRepository;

@Service
public class StatesService {

    @Autowired
    private StateRepository stateRepository;

    public Optional<State> findByCode(String code) {
        return stateRepository.findById(code);
    }
}
