package com.procergs.util;

import java.io.IOException;
import java.util.Arrays;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoDatabase;

public class MongoDBSingleton {
	static Logger logger = Logger.getLogger(MongoDBSingleton.class);
	private static final String properties_filename = "mongodb.properties";
	
	private static MongoClient mongo 						= null;
	private static MongoDatabase mongoDatabase 	= null;
	private static String hostname 							= null;
	private static int port 										= 0;
	private static String username 							= null;
	private static String password 							= null;
	private static String database 							= null;
	
	private static class Holder {
		private static final MongoDBSingleton instance = new MongoDBSingleton();
	}
	
	private MongoDBSingleton() {
		logger.info("Inside MongoDBSingleton...");
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		Properties properties = new Properties();
		try {
			logger.info("Reading mongo.properties...");
			properties.load(classLoader.getResourceAsStream(properties_filename));
			hostname = properties.getProperty("mongodb.hostname");
			logger.info("mongodb.hostname....: " + hostname);
			String portStr = properties.getProperty("mongodb.port");
			port = Integer.parseInt(portStr);
			logger.info("mongodb.port........: " + port);
			username = properties.getProperty("mongodb.username");
			logger.info("mongodb.username....: " + username);
			password = properties.getProperty("mongodb.password");
			//logger.info("mongodb.password....: " + password);
			database = properties.getProperty("mongodb.database");
			logger.info("mongodb.database....: " + database);	
		} catch (IOException e) {
			e.printStackTrace();
		}
	};
	
	public static MongoDBSingleton getInstance() {
		return Holder.instance;
	}
	
	public MongoClient getMongoClient() {
		//String URI = String.format("mongodb://%s:%s@%s:%d/?authSource=%s", username, password, hostname, port, database); 
		//MongoClientURI mongoClientURI = new MongoClientURI(URI);
		MongoCredential mongoCredential = MongoCredential
				.createMongoCRCredential(username, database,
						password.toCharArray());
		
		mongo =new MongoClient(new ServerAddress(
				hostname, port),
				Arrays.asList(mongoCredential));
		
		//mongo = new MongoClient(mongoClientURI);
		return mongo;
	}
	
	public MongoDatabase getDatabase() {
		if (mongoDatabase == null) {
			mongo = getMongoClient();
		}
		return mongo.getDatabase(database);
	}
}
