import static org.junit.Assert.*;

import org.junit.Test;

import com.procergs.model.User;
import com.procergs.service.JwtSecurity;

public class JWTSignTeste {
	@Test
	public void testOK() {
		JwtSecurity jwtTeste =  new JwtSecurity();
		User user = jwtTeste.validUser("springuser", "Spring99!"); 
		String jwt =jwtTeste.generateJWT(user);
		assertNotNull(jwt);
		assertTrue(jwtTeste.validateJWT(jwt));
	}
	
	@Test
	public void testExpire() {
		JwtSecurity jwtTeste =  new JwtSecurity();
		User user = jwtTeste.validUser("springuser", "Spring99!"); 
		String jwt =jwtTeste.generateJWT(user);
		assertNotNull(jwt);
		try {
			Thread.sleep(40000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		assertTrue(jwtTeste.validateJWT(jwt));
	}
}
