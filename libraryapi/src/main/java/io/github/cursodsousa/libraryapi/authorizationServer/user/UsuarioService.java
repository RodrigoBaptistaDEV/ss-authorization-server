package io.github.cursodsousa.libraryapi.authorizationServer.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository repository;

    public Usuario obterPorLogin(String login){
        return repository.findByLogin(login);
    }

    public Usuario obterPorEmail(String email){
        return repository.findByEmail(email);
    }
}
