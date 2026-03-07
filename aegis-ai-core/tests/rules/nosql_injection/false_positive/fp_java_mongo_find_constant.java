package nosqlinjection;

import com.mongodb.client.MongoCollection;
import org.bson.Document;

/**
 * FP: 使用常量构造 NoSQL 查询条件，不应视为 NoSQL 注入。
 * 期望: 无 NOSQL_INJECTION
 */
public class NoSqlJavaFp {
    public void safe(MongoCollection<Document> coll) {
        coll.find(new Document("user", "admin"));
    }
}

