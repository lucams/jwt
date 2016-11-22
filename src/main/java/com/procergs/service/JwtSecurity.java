package com.procergs.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.bson.Document;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoDatabase;
import com.procergs.model.Item;
import com.procergs.model.StatusMessage;
import com.procergs.model.User;
import com.procergs.util.MongoDBSingleton;
import com.sun.jersey.api.client.ClientResponse.Status;

@Path("/security")
public class JwtSecurity {
	static Logger logger = Logger.getLogger(JwtSecurity.class);
	static List<JsonWebKey> jwkList = null;

	static {
		logger.info("Inside static initializer...");
		jwkList = new LinkedList<>();
		// Creating three keys, will use one now, maybe rework this to be more
		// flexible -- if time permits
		for (int kid = 1; kid <= 3; kid++) {
			JsonWebKey jwk = null;
			try {
				jwk = RsaJwkGenerator.generateJwk(2048);
				logger.info("PUBLIC KEY (" + kid + "): " + jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
			} catch (JoseException e) {
				e.printStackTrace();
			}
			jwk.setKeyId(String.valueOf(kid));
			jwkList.add(jwk);
		}

	}

	@Path("/status")
	@GET
	@Produces(MediaType.TEXT_HTML)
	public String returnVersion() {
		return "JwtSecurity Status is OK...";
	}

	@Path("/authenticate")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticateCredentials(@HeaderParam("username") String username,
			@HeaderParam("password") String password)

			throws JsonGenerationException, JsonMappingException, IOException {

		logger.info("Authenticating User Credentials...");
	
		if (username == null) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.PRECONDITION_FAILED.getStatusCode());
			statusMessage.setMessage("Username não informado!");
			return Response.status(Status.PRECONDITION_FAILED.getStatusCode()).entity(statusMessage).build();
		}

		if (password == null) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.PRECONDITION_FAILED.getStatusCode());
			statusMessage.setMessage("Password não informado!");
			return Response.status(Status.PRECONDITION_FAILED.getStatusCode()).entity(statusMessage).build();
		}

		User user = validUser(username, password);
		if (user == null) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.FORBIDDEN.getStatusCode());
			statusMessage.setMessage("Acesso negado para esta funcionalidade!");
			return Response.status(Status.FORBIDDEN.getStatusCode()).entity(statusMessage).build();
		}

		String jwt = generateJWT(user);

		return Response.status(200).entity(jwt).build();
	}

	public String generateJWT(User user) {
		RsaJsonWebKey senderJwk = (RsaJsonWebKey) jwkList.get(0);

		senderJwk.setKeyId("1");
		logger.info("JWK (1) ===> " + senderJwk.toJson());

		// Create the Claims, which will be the content of the JWT
		JwtClaims claims = new JwtClaims();
		claims.setIssuer("home.net"); // who creates the token and signs it
		claims.setExpirationTimeMinutesInTheFuture(2); // token will expire (10
														// minutes from now)
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(1); // time before which the token
												// is not yet valid (2 minutes
												// ago)
		claims.setSubject(user.getUsername()); // the subject/principal is whom
												// the token is about
		claims.setStringListClaim("roles", user.getRolesList()); // multi-valued
																	// claims
																	// for roles
		JsonWebSignature jws = new JsonWebSignature();

		jws.setPayload(claims.toJson());

		jws.setKeyIdHeaderValue(senderJwk.getKeyId());
		jws.setKey(senderJwk.getPrivateKey());

		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		String jwt = null;
		try {
			jwt = jws.getCompactSerialization();
		} catch (JoseException e) {
			e.printStackTrace();
		}
		return jwt;
	}

	// --- Protected resource using service-id and api-key ---
	@Path("/finditembyid")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response findItemById(@HeaderParam("token") String token, @QueryParam("itemid") String item_id)
			throws JsonGenerationException, JsonMappingException, IOException {

		Item item = null;

		logger.info("Inside findOrderById...");

		if (token == null) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.FORBIDDEN.getStatusCode());
			statusMessage.setMessage("Token não informado. Acesso negado para esta funcionalidade!");
			return Response.status(Status.FORBIDDEN.getStatusCode()).entity(statusMessage).build();
		}

		JsonWebKeySet jwks = new JsonWebKeySet(jwkList);
		JsonWebKey jwk = jwks.findJsonWebKey("1", null, null, null);
		logger.info("JWK (1) ===> " + jwk.toJson());

		// Validate Token's authenticity and check claims
		JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime().setAllowedClockSkewInSeconds(30)
				.setRequireSubject().setExpectedIssuer("home.net").setVerificationKey(jwk.getKey()).build();

		try {
			// Validate the JWT and process it to the Claims
			JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
			logger.info("JWT validation succeeded! " + jwtClaims);
		} catch (InvalidJwtException e) {
			logger.error("JWT is Invalid: " + e);
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.FORBIDDEN.getStatusCode());
			statusMessage.setMessage("Token Inválido. Acessp negado para esta funcionalidade!");
			return Response.status(Status.FORBIDDEN.getStatusCode()).entity(statusMessage).build();
		}

		MongoDBSingleton mongoDB = MongoDBSingleton.getInstance();
		MongoDatabase db = mongoDB.getDatabase();

		BasicDBObject query = new BasicDBObject();
		query.put("_id", item_id);
		List<Document> results = db.getCollection("items").find(query).into(new ArrayList<Document>());
		int size = results.size();

		if (size == 0) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.PRECONDITION_FAILED.getStatusCode());
			statusMessage.setMessage("Item não encontrado!");
			return Response.status(Status.PRECONDITION_FAILED.getStatusCode()).entity(statusMessage).build();
		}

		for (Document current : results) {
			ObjectMapper mapper = new ObjectMapper();
			try {
				logger.info(current.toJson());
				item = mapper.readValue(current.toJson(), Item.class);
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return Response.status(200).entity(item).build();
	}

	// --- Protected resource using JWT Token ---
	@Path("/showallitems")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response showAllItems(@HeaderParam("token") String token)
			throws JsonGenerationException, JsonMappingException, IOException {

		Item item = null;

		logger.info("Inside showAllItems...");

		if (token == null) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.FORBIDDEN.getStatusCode());
			statusMessage.setMessage("Token não informado. Acesso negado para esta funcionalidade!");
			return Response.status(Status.FORBIDDEN.getStatusCode()).entity(statusMessage).build();
		}

		JsonWebKeySet jwks = new JsonWebKeySet(jwkList);
		JsonWebKey jwk = jwks.findJsonWebKey("1", null, null, null);
		logger.info("JWK (1) ===> " + jwk.toJson());

		// Validate Token's authenticity and check claims
		JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime().setAllowedClockSkewInSeconds(30) // allow
																														// for
																														// a
																														// 30
																														// second
																														// difference
																														// to
																														// account
																														// for
																														// clock
																														// skew
				.setRequireSubject().setExpectedIssuer("home.net").setVerificationKey(jwk.getKey()).build(); // create
																													// the
																													// JwtConsumer
																													// instance

		try {
			// Validate the JWT and process it to the Claims
			JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
			logger.info("JWT validation succeeded! " + jwtClaims);
		} catch (InvalidJwtException e) {
			logger.error("JWT is Invalid: " + e);
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.FORBIDDEN.getStatusCode());
			statusMessage.setMessage("Token inválido. Acesso negado para esta funcionalidade!");
			return Response.status(Status.FORBIDDEN.getStatusCode()).entity(statusMessage).build();
		}

		MongoDBSingleton mongoDB = MongoDBSingleton.getInstance();
		MongoDatabase db = mongoDB.getDatabase();

		List<Document> results = db.getCollection("items").find().into(new ArrayList<Document>());
		int size = results.size();

		if (size == 0) {
			StatusMessage statusMessage = new StatusMessage();
			statusMessage.setStatus(Status.PRECONDITION_FAILED.getStatusCode());
			statusMessage.setMessage("Não existem itens para mostrar!");
			return Response.status(Status.PRECONDITION_FAILED.getStatusCode()).entity(statusMessage).build();
		}

		List<Item> allItems = new ArrayList<Item>();
		for (Document current : results) {
			ObjectMapper mapper = new ObjectMapper();
			try {
				logger.info(current.toJson());
				item = mapper.readValue(current.toJson(), Item.class);
				allItems.add(item);
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return Response.status(200).entity(allItems).build();
	}

	public boolean validateJWT(String token) {
		JsonWebKeySet jwks = new JsonWebKeySet(jwkList);
		JsonWebKey jwk = jwks.findJsonWebKey("1", null, null, null);
		logger.info("JWK (1) ===> " + jwk.toJson());

		// Validate Token's authenticity and check claims
		JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime().setAllowedClockSkewInSeconds(10) // allow
																														// for
																														// a
																														// 30
																														// second
																														// difference
																														// to
																														// account
																														// for
																														// clock
																														// skew
				.setRequireSubject().setExpectedIssuer("home.net").setVerificationKey(jwk.getKey()).build(); // create
																													// the
																													// JwtConsumer
																													// instance

		try {
			// Validate the JWT and process it to the Claims
			JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
			return true;
		} catch (InvalidJwtException e) {
			return false;
		}
	}

	public User validUser(String username, String password) {
		MongoDBSingleton mongoDB = MongoDBSingleton.getInstance();
		MongoDatabase db = mongoDB.getDatabase();
		List<Document> results = null;

		results = db.getCollection("users").find(new Document("username", username)).limit(1)
				.into(new ArrayList<Document>());
		int size = results.size();

		if (size == 1) {
			for (Document current : results) {
				ObjectMapper mapper = new ObjectMapper();
				User user = null;
				try {
					user = mapper.readValue(current.toJson(), User.class);
				} catch (JsonParseException e) {
					e.printStackTrace();
				} catch (JsonMappingException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
				if (user != null && username.equals(user.getUsername()) && password.equals(user.getPassword())) {
					return user;
				} else {
					return null;
				}
			}
			return null;
		} else {
			return null;
		}
	}
}