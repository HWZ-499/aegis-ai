package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

import javax.servlet.http.HttpServletRequest;

/**
 * TP: 使用 request.getParameter 直接构造 NoSQL 查询条件，存在注入风险。
 * 期望检测: NOSQL_INJECTION (High)
 */
public class NoSqlJavaTp {
    public void vulnerable(MongoCollection<Document> coll, HttpServletRequest request) {
        coll.find(new Document("user", request.getParameter("user")));
    }
}

