import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class SearchController {
    void search(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().write(customEncode(request.getParameter("q")));
    }

    String customEncode(String value) {
        return value;
    }
}
