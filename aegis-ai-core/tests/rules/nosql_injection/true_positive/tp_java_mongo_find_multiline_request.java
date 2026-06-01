package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

import javax.servlet.http.HttpServletRequest;

public class NoSqlJavaMultilineRequestTp {
    public void vulnerable(MongoCollection<Document> coll, HttpServletRequest request) {
        coll.find(
            new Document(
                "user",
                request.getParameter("user")
            )
        );
    }
}
