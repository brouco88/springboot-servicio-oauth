package com.formacionbdi.springboot.app.oauth.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;
import com.formacionbdi.springboot.app.usuarios.commons.models.entity.Usuario;

import brave.Tracer;
import feign.FeignException;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

	private Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

	@Autowired
	private IUsuarioService usuarioService;
	@Autowired
	private Tracer tracer;
	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		UserDetails user = (UserDetails) authentication.getPrincipal();
		log.info("Succes Login: " + user.getUsername());
		
		Usuario usuario = usuarioService.findByUsername(authentication.getName());
		if (usuario.getIntentos() !=null && usuario.getIntentos()>0 ) {
			usuario.setIntentos(0);
			usuarioService.update(usuario, usuario.getId());
		}
		
		

		
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		String mensaje = "Error en el Login: " + exception.getMessage();
		log.error(mensaje);
		try {
			StringBuilder errors = new StringBuilder();
			errors.append(mensaje);
			Usuario usuario = usuarioService.findByUsername(authentication.getName());
			if (usuario.getIntentos() == null) {
				usuario.setIntentos(0);
			}
			log.info(String.format("Intectos actual el usuario %s es de %s", usuario.getUsername(),
					usuario.getIntentos()));
			usuario.setIntentos(usuario.getIntentos() + 1);
			log.info(String.format("Intectos actual el usuario %s es de %s", usuario.getUsername(),
					usuario.getIntentos()));
			errors.append(String.format("Intectos actual el usuario %s es de %s", usuario.getUsername(),
					usuario.getIntentos()));
			if (usuario.getIntentos() >= 3) {
				usuario.setEnabled(false);
				log.info(String.format("El usuario %s desabilitado por maximo de intentos", usuario.getUsername()));
				errors.append(String.format("El usuario %s desabilitado por maximo de intentos", usuario.getUsername()));
			}

			usuarioService.update(usuario, usuario.getId());
			tracer.currentSpan().tag("error.mensaje", errors.toString());
		} catch (FeignException e) {
			log.error(String.format("El usuario %s no existe en el sistema", authentication.getName()));
		}

	}

}
