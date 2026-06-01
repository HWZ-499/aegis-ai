package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

import javax.servlet.http.HttpServletRequest;

public class NoSqlJavaRequestAliasTp {
    public void vulnerable(MongoCollection<Document> coll, HttpServletRequest httpRequest) {
        coll.find(new Document("user", httpRequest.getParameter("user")));
    }
}
