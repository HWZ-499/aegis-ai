package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

class AppConfig {
    public String getParameter(String name) {
        return "admin";
    }
}

public class NoSqlJavaBusinessGetParameterFp {
    public void safe(MongoCollection<Document> coll, AppConfig config) {
        coll.find(new Document("user", config.getParameter("defaultUser")));
    }
}
