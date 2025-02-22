package com.book.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.State;
import com.book.repository.StateRepository;

@Service
public class StateService {

    @Autowired
    private StateRepository stateRepository;

    public List<State> getAllStates() {
        return stateRepository.findAll();
    }

    public State getStateByCode(String code) {
        return stateRepository.findById(code).orElse(null);
    }

    public State createOrUpdateState(State state) {
        return stateRepository.save(state);
    }
}
