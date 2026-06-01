package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

import javax.servlet.http.HttpServletRequest;

public class NoSqlJavaUnrelatedRequestFp {
    public String safe(MongoCollection<Document> coll, HttpServletRequest httpRequest) {
        coll.find(new Document("user", "admin"));
        return httpRequest.getParameter("debug");
    }
}
