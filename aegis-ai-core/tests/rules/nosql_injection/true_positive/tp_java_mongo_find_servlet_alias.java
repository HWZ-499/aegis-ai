package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

import javax.servlet.http.HttpServletRequest;

public class NoSqlJavaServletAliasTp {
    public void vulnerable(MongoCollection<Document> coll, HttpServletRequest servlet) {
        coll.find(new Document("user", servlet.getParameter("user")));
    }
}
